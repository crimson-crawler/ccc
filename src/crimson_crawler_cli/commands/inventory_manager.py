"""``ccc inventory-manager`` — your Inventory Manager inventories over the key-authed Inventory Manager API.

Each subcommand routes through the SDK's hand-written ``client.inventory_manager`` namespace
(:class:`crimson_crawler_client.InventoryManagerAPI`) — never the raw escape hatch — satisfying the
convenience-surface invariant. A **inventory** is a continuously-monitored context window (asset inventory + attached
artifacts + saved enrichment history). Inventory CRUD is **usage-exempt**; only ``enrichment`` (submit) counts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import auth, output, paths
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from ._formatters import with_live_progress, with_status

# Asset import/export formats — the user PICKS one (no auto-detect), mirroring the portal editor.
_IMPORT_FORMATS = ("json", "sbom", "csv", "nmap", "list", "grype", "trivy", "depcheck", "nessus", "gvm", "xlsx")
_EXPORT_FORMATS = ("json", "csv", "list", "cyclonedx", "spdx", "spdx2", "workbook")

app = typer.Typer(
    name="inventory-manager",
    help="Your Inventory Manager — list/create/edit inventories, attach/detach artifacts, toggle "
    "monitoring, and enrich an inventory (usage-exempt except the enrichment submit).",
    no_args_is_help=True,
)


# -- list / show ------------------------------------------------------------ #


def _render_inventories(console: Console, payload: dict[str, Any]) -> None:
    inventories = payload.get("inventories", [])
    if not inventories:
        console.print("[dim]No inventories.[/dim]")
        return
    table = Table(title=f"Inventories ({len(inventories)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Assets", justify="right")
    table.add_column("Attached", justify="right")
    table.add_column("Monitor", justify="center")
    for p in inventories:
        table.add_row(
            escape(str(p.get("id", ""))),
            escape(str(p.get("name", ""))),
            escape(str(p.get("item_count", 0))),
            escape(str(p.get("linked_count", 0))),
            "●" if p.get("monitoring") else "",
        )
    console.print(table)


@app.command("list", help="List your Inventory Manager inventories (continuously-monitored context windows).")
@handle_errors
def list_command() -> None:
    """List inventories via ``client.inventory_manager.list_inventories``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"inventories": await client.inventory_manager.list_inventories()}

    payload = with_status("Listing inventories…", _call())
    output.render(payload, _render_inventories)


def _render_inventory(console: Console, payload: dict[str, Any]) -> None:
    console.print(f"[bold]{escape(str(payload.get('inventory_name') or payload.get('name', '')))}[/bold]")
    if payload.get("description"):
        console.print(escape(str(payload["description"])))
    console.print(
        f"[dim]Monitoring {'on' if payload.get('monitoring') else 'off'} · "
        f"{len(payload.get('inventory', []))} assets · "
        f"{len(payload.get('attached', []))} attached · "
        f"{len(payload.get('enrichments', []))} saved enrichments[/dim]"
    )


@app.command(
    "show",
    help="Show one inventory — manifest (default) or the untrusted-data context bundle (--context).",
)
@handle_errors
def show_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    context: Annotated[
        bool,
        typer.Option(
            "--context",
            help="Emit the bounded, provenance-labeled context bundle instead of the manifest.",
        ),
    ] = False,
) -> None:
    """Fetch an inventory via ``client.inventory_manager.get_inventory`` (manifest) or
    ``get_inventory_context`` (the bounded context window)."""
    resolved = auth.resolve_auth()

    if context:

        async def _call() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.inventory_manager.get_inventory_context(inventory_id)

        payload = with_status("Building inventory context…", _call())
        if output.is_json_mode():
            output.render(payload, lambda c, p: None)
        else:
            # Pipe-friendly: the context includes its untrusted-data preamble.
            # Emit it unchanged with no Rich markup.
            typer.echo(str(payload.get("context", "")))
        return

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.get_inventory(inventory_id)

    payload = with_status("Fetching inventory…", _call())
    output.render(payload, _render_inventory)


def _render_enrichments(console: Console, payload: dict[str, Any]) -> None:
    enrichments = payload.get("enrichments", [])
    if not enrichments:
        console.print("[dim]No saved enrichments.[/dim]")
        return
    table = Table(title=f"Previous enrichments ({len(enrichments)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Created", overflow="fold")
    table.add_column("CVEs", justify="right")
    table.add_column("KEV", justify="right")
    for e in enrichments:
        meta = e.get("meta") if isinstance(e.get("meta"), dict) else {}
        table.add_row(
            escape(str(e.get("id", ""))),
            escape(str(e.get("name", ""))),
            escape(str(e.get("created_at", ""))),
            escape(str(meta.get("total_cves", ""))),
            escape(str(meta.get("total_kev", ""))),
        )
    console.print(table)


@app.command("enrichments", help="List an inventory's saved enrichment history (the 'Previous enrichments' strip).")
@handle_errors
def enrichments_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
) -> None:
    """List an inventory's saved enrichments via ``client.inventory_manager.list_enrichments`` (newest first,
    no content — each row's ``meta`` carries the asset/CVE/KEV card stats)."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"enrichments": await client.inventory_manager.list_enrichments(inventory_id)}

    payload = with_status("Listing enrichments…", _call())
    output.render(payload, _render_enrichments)


# -- compare ---------------------------------------------------------------- #


def _render_inventory_matrix(console: Console, payload: dict[str, Any]) -> None:
    matrix = payload.get("matrix", {})
    counts = matrix.get("counts", {})
    console.print(
        f"[bold]Change:[/bold] "
        f"[green]{counts.get('new', 0)} new[/green] · "
        f"[cyan]{counts.get('resolved', 0)} resolved[/cyan] · "
        f"[yellow]{counts.get('changed', 0)} changed[/yellow] · "
        f"[dim]{counts.get('persistent', 0)} persistent[/dim]"
    )
    rows = matrix.get("rows", [])[:20]
    if not rows:
        return
    columns = matrix.get("columns", [])
    table = Table(title=f"CVEs ({len(matrix.get('rows', []))} total, showing {len(rows)})")
    table.add_column("CVE", overflow="fold")
    table.add_column("Status")
    for col in columns:
        table.add_column(escape(str(col.get("name", ""))[:24]), justify="right")
    for row in rows:
        cells = []
        for c in row.get("cells", []):
            if c is None:
                cells.append("—")
            else:
                weap = c.get("weaponization", "·")
                cells.append(f"{weap}{' KEV' if c.get('kev') else ''}")
        table.add_row(escape(str(row.get("cve_id", ""))), escape(str(row.get("status", ""))), *map(escape, cells))
    console.print(table)


@app.command("compare", help="CVE difference matrix across 2-12 of an inventory's saved enrichments.")
@handle_errors
def compare_command(
    enrichment_ids: Annotated[
        list[str],
        typer.Argument(help="Two to twelve inventory-enrichment ids.", show_default=False),
    ],
) -> None:
    """Build the inventory-enrichment difference matrix via ``client.inventory_manager.compare_enrichments``."""
    if not 2 <= len(enrichment_ids) <= 12:
        raise BadInputError("Pass between 2 and 12 inventory-enrichment ids.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"matrix": await client.inventory_manager.compare_enrichments(enrichment_ids)}

    payload = with_status("Comparing inventory enrichments…", _call())
    output.render(payload, _render_inventory_matrix)


# -- write (create / delete / attach / detach / monitor / enrichment) ---- #


@app.command("create", help="Create an empty Inventory Manager inventory (add assets later via attach).")
@handle_errors
def create_command(
    name: Annotated[
        str,
        typer.Option("--name", help="Inventory scope name.", show_default=False),
    ],
    description: Annotated[str | None, typer.Option("--description", help="Optional inventory description.")] = None,
    monitoring: Annotated[
        bool,
        typer.Option("--monitoring/--no-monitoring", help="Enable continuous re-enrichment monitoring."),
    ] = False,
    linked_artifact_ids: Annotated[
        list[str] | None,
        typer.Option("--linked-artifact-id", help="Attach a saved artifact id (repeatable)."),
    ] = None,
) -> None:
    """Create an inventory via ``client.inventory_manager.create_inventory`` (empty inventory)."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.create_inventory(
                name,
                description=description,
                monitoring=monitoring,
                linked_artifact_ids=linked_artifact_ids or None,
            )

    payload = with_status("Creating inventory…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Created[/green] inventory {p.get('id', '')} ([dim]{p.get('item_count', 0)} assets[/dim])"
        ),
    )


@app.command("delete", help="Delete one of your Inventory Manager inventories.")
@handle_errors
def delete_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
) -> None:
    """Delete an inventory via ``client.inventory_manager.delete_inventory``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"deleted": await client.inventory_manager.delete_inventory(inventory_id), "id": inventory_id}

    payload = with_status("Deleting inventory…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Deleted[/green] inventory {p['id']}"))


def _render_attach(console: Console, payload: dict[str, Any]) -> None:
    # Bulk shape: {id, linked_count, attached, skipped, mode}.
    if "attached" in payload:
        skipped = payload.get("skipped", 0)
        console.print(
            f"[green]{'Set' if payload.get('mode') == 'replace' else 'Added'}[/green] "
            f"{payload.get('attached', 0)} attachment(s) — inventory now has "
            f"{payload.get('linked_count', 0)} attached"
            + (f" [yellow]({skipped} skipped — not attachable)[/yellow]" if skipped else "")
        )
        return
    # Single shape: {ok, linked, already}.
    if not payload.get("ok"):
        console.print("[yellow]Not linked.[/yellow]")
    elif payload.get("already"):
        console.print("[dim]Already linked — no change.[/dim]")
    else:
        console.print("[green]Linked[/green] artifact to inventory.")


@app.command("attach", help="Attach saved artifact(s) to an inventory (one or many; idempotent).")
@handle_errors
def attach_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    artifact_ids: Annotated[list[str], typer.Argument(help="Saved artifact id(s) to attach.", show_default=False)],
    replace: Annotated[
        bool,
        typer.Option(
            "--replace",
            help="Set the inventory's attachments to EXACTLY these (default appends).",
        ),
    ] = False,
) -> None:
    """Link artifact(s) to an inventory. One id (append) goes through ``attach_to_inventory``; multiple ids
    or ``--replace`` use the bulk ``add_attachments`` / ``set_attachments``. Only input/enrichment/report
    artifacts are attachable — inventories and inventory enrichments are skipped."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            pm = client.inventory_manager
            if replace:
                return await pm.set_attachments(inventory_id, artifact_ids)
            if len(artifact_ids) == 1:
                return await pm.attach_to_inventory(inventory_id, artifact_ids[0])
            return await pm.add_attachments(inventory_id, artifact_ids)

    payload = with_status("Attaching artifact(s)…", _call())
    output.render(payload, _render_attach)


@app.command("detach", help="Detach a saved artifact from an inventory (atomic, idempotent).")
@handle_errors
def detach_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    artifact_id: Annotated[str, typer.Argument(help="Saved artifact id to detach.", show_default=False)],
) -> None:
    """Unlink an artifact from an inventory via ``client.inventory_manager.detach_from_inventory``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.detach_from_inventory(inventory_id, artifact_id)

    payload = with_status("Detaching artifact…", _call())
    output.render(
        payload,
        lambda c, p: c.print("[green]Detached.[/green]" if p.get("removed") else "[dim]Not linked — no change.[/dim]"),
    )


@app.command("apply-fix", help="Apply a recommended upgrade to one asset (sets its version; preserves the rest).")
@handle_errors
def apply_fix_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    product: Annotated[str, typer.Argument(help="Asset product to upgrade (case-insensitive).", show_default=False)],
    version: Annotated[
        str, typer.Argument(help="Fixed version to set (the recommended upgrade target).", show_default=False)
    ],
    vendor: Annotated[
        str | None, typer.Option("--vendor", help="Disambiguate duplicate product names.", show_default=False)
    ] = None,
) -> None:
    """Apply a recommended upgrade via ``client.inventory_manager.apply_asset_fix`` — sets the matched
    asset's version to the published fix the Inventory Enricher surfaced, preserving everything else. Writes
    the inventory only (no re-enrich; the next enrichment / daily monitor confirms the CVEs cleared)."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.apply_asset_fix(inventory_id, product, version, vendor)

    payload = with_status("Applying upgrade…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Applied[/green] {p.get('product', product)} → {p.get('version', version)} "
            f"(inventory now has {p.get('item_count', '?')} assets)."
        ),
    )


@app.command("monitor", help="Enable/disable an inventory's continuous monitoring (preserves assets).")
@handle_errors
def monitor_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    monitoring: Annotated[
        bool,
        typer.Option("--monitoring/--no-monitoring", help="Enable or disable continuous re-enrichment monitoring."),
    ],
) -> None:
    """Toggle monitoring via ``client.inventory_manager.set_monitoring`` (read-modify-write — assets, attachments,
    prefs, and attachments are preserved). Monitoring enrichments always run at full depth."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.set_monitoring(inventory_id, monitoring=monitoring)

    payload = with_status("Updating monitoring…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Monitoring {'enabled' if monitoring else 'disabled'}[/green] for {p.get('id', inventory_id)}."
        ),
    )


@app.command("favorite", help="Star or unstar an inventory (the ★ on inventory cards).")
@handle_errors
def favorite_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    on: Annotated[bool, typer.Option("--on/--off", help="Star (--on) or unstar (--off).")] = True,
) -> None:
    """Star/unstar via ``client.inventory_manager.set_favorite`` — a favorite-only update that leaves the
    asset inventory, attachments, monitoring, and automation untouched."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.set_favorite(inventory_id, on)

    payload = with_status("Updating favorite…", _call())
    output.render(
        payload, lambda c, p: c.print(f"[green]{'Starred' if on else 'Unstarred'}[/green] {p.get('id', inventory_id)}.")
    )


def _render_automation(console: Console, payload: dict[str, Any]) -> None:
    a = payload.get("automation") or {}
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="cyan")
    t.add_column()
    t.add_row("Daily enrichment", "[green]on[/green]" if a.get("monitoring") else "off")
    t.add_row("  · alert email", "on" if a.get("daily_enrichment_email") else "off")
    t.add_row("Daily report", "[green]on[/green]" if a.get("daily_report") else "off")
    t.add_row("  · report email", "on" if a.get("daily_report_email") else "off")
    tmpl = str(a.get("daily_report_template") or "—")
    if a.get("custom_template_pinned"):
        tmpl += "  [dim](custom pinned)[/dim]"
    t.add_row("  · template", tmpl)
    console.print(t)


@app.command("automation", help="Show or set an inventory's daily automation (enrichment + report).")
@handle_errors
def automation_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    daily_enrichment: Annotated[
        bool | None,
        typer.Option("--daily-enrichment/--no-daily-enrichment", help="Daily re-enrichment job."),
    ] = None,
    enrichment_email: Annotated[
        bool | None,
        typer.Option("--enrichment-email/--no-enrichment-email", help="Email an alert on new findings."),
    ] = None,
    daily_report: Annotated[
        bool | None,
        typer.Option(
            "--daily-report/--no-daily-report",
            help="Daily report (runs after the daily enrichment; requires --daily-enrichment).",
        ),
    ] = None,
    report_email: Annotated[
        bool | None,
        typer.Option("--report-email/--no-report-email", help="Email the daily report when ready."),
    ] = None,
    report_template: Annotated[
        str | None,
        typer.Option("--report-template", help="Built-in report template id (e.g. project_brief).", show_default=False),
    ] = None,
) -> None:
    """Manage an inventory's daily automation via ``client.inventory_manager.get_automation`` /
    ``set_automation``. With NO flags it SHOWS the current config; any flag SETS only that field
    (the rest preserved). ONE pipeline: the daily report rides the daily enrichment, so ``--daily-report``
    REQUIRES ``--daily-enrichment`` (enabling it alone errors; turning enrichment off turns the report off).
    The daily cron runs the pipeline on your key (enrichment counts then)."""
    resolved = auth.resolve_auth()
    patch: dict[str, Any] = {}
    if daily_enrichment is not None:
        patch["monitoring"] = daily_enrichment
    if enrichment_email is not None:
        patch["daily_enrichment_email"] = enrichment_email
    if daily_report is not None:
        patch["daily_report"] = daily_report
    if report_email is not None:
        patch["daily_report_email"] = report_email
    if report_template is not None:
        patch["daily_report_template"] = report_template

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            if not patch:
                return await client.inventory_manager.get_automation(inventory_id)
            return await client.inventory_manager.set_automation(inventory_id, **patch)

    payload = with_status("Reading automation…" if not patch else "Updating automation…", _call())
    output.render(payload, _render_automation)


def _render_inventory_scan(console: Console, payload: dict[str, Any]) -> None:
    if payload.get("empty"):
        console.print("[yellow]Inventory inventory is empty — nothing to enrich.[/yellow]")
        return
    # The /v1 engine returns {enrichment_id, report}; the rollup lives under report.summary.
    report = payload.get("report") if isinstance(payload.get("report"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    assets = summary.get("asset_count")
    cves = summary.get("total_cves")
    kev = summary.get("total_kev")
    if assets is not None or cves is not None or kev is not None:
        console.print(
            f"[green]Enrichment complete.[/green] "
            f"{_maybe_count(assets)} assets · {_maybe_count(cves)} CVEs · {_maybe_count(kev)} KEV"
        )
    else:
        console.print("[green]Enrichment complete.[/green]")
    if payload.get("enrichment_id"):
        console.print(f"[dim]Enrichment {payload['enrichment_id']}[/dim]")
    saved = payload.get("saved") if isinstance(payload.get("saved"), dict) else None
    if saved and saved.get("artifact_id"):
        console.print(f"[green]Saved to inventory history:[/green] {saved['artifact_id']}")


def _maybe_count(value: object) -> str:
    return str(value) if isinstance(value, (int, float)) else "?"


@app.command("enrich", help="Enrich an inventory's asset inventory (submit → poll → report).")
@handle_errors
def scan_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    save: Annotated[
        bool,
        typer.Option("--save", help="Save the finished enrichment into this inventory's history (usage-exempt)."),
    ] = False,
    enrich_attachments: Annotated[
        bool | None,
        typer.Option(
            "--enrich-attachments/--no-enrich-attachments",
            help="Also enrich the inventory's ATTACHED artifacts (the 'artifact scans' toggle). "
            "Default: honor the inventory's saved toggle.",
        ),
    ] = None,
) -> None:
    """Run an inventory enrichment via ``client.inventory_manager.enrich_inventory`` (submit → poll → report,
    full depth, against the /v1 engine). ``--save`` files the result into the inventory's saved history;
    ``--enrich-attachments`` also runs a mini Artifact Enrichment over the inventory's attached artifacts."""
    resolved = auth.resolve_auth()

    def _call(on_progress: Any) -> Any:
        async def _inner() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.inventory_manager.enrich_inventory(
                    inventory_id, on_progress=on_progress, save=save, enrich_attachments=enrich_attachments
                )

        return _inner()

    payload = with_live_progress("Enriching inventory", _call)
    output.render(payload, _render_inventory_scan)


@app.command("import", help="Import an asset-inventory file — create an inventory, or edit an existing one's assets.")
@handle_errors
def import_command(
    file: Annotated[
        Path,
        typer.Argument(
            exists=True, dir_okay=False, readable=True, show_default=False, help="Inventory file to import."
        ),
    ],
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            show_default=False,
            help="File format (you pick it — no auto-detect): "
            "json | sbom | csv | nmap | list | grype | trivy | depcheck | nessus | gvm | xlsx.",
        ),
    ],
    name: Annotated[str | None, typer.Option("--name", help="Inventory name (overrides the file's).")] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional inventory description.")] = None,
    into: Annotated[
        str | None,
        typer.Option(
            "--into",
            help="Import INTO an existing inventory id (edits its assets) instead of creating a new one.",
        ),
    ] = None,
    append: Annotated[
        bool,
        typer.Option(
            "--append",
            help="With --into: ADD the file's assets to the existing ones (default replaces).",
        ),
    ] = False,
) -> None:
    """Import via ``client.inventory_manager.import_inventory`` (the chosen per-format parser runs). With
    ``--into`` the file's assets replace (or, with ``--append``, add to) an existing inventory's inventory,
    preserving its attachments / monitoring."""
    fmt = fmt.lower()
    if fmt not in _IMPORT_FORMATS:
        raise BadInputError(f"Unknown --format '{fmt}'. One of: {', '.join(_IMPORT_FORMATS)}.")
    resolved = auth.resolve_auth()
    # xlsx is binary — read bytes (the SDK base64-encodes them); the other 10 formats are text.
    content: str | bytes = file.read_bytes() if fmt == "xlsx" else file.read_text(encoding="utf-8", errors="replace")
    mode = "append" if append else "replace"

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.import_inventory(
                fmt=fmt,
                content=content,
                inventory_name=name,
                description=description,
                inventory_id=into,
                mode=mode,
            )

    verb = "Updating" if into else "Importing"
    payload = with_status(f"{verb} inventory…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]{'Updated' if p.get('replaced') else 'Imported'}[/green] "
            f"{p.get('imported', p.get('item_count', 0))} assets "
            f"{'in' if p.get('replaced') else '→'} inventory {p.get('id', '')}"
            + (f" [dim](mode: {p['mode']})[/dim]" if p.get("mode") else "")
            + (f" [yellow](+{p['truncated']} dropped — 200 cap)[/yellow]" if p.get("truncated") else "")
        ),
    )


@app.command("import-multi", help="Combine SEVERAL files (different formats) into ONE inventory.")
@handle_errors
def import_multi_command(
    sources: Annotated[
        list[str],
        typer.Option(
            "--source",
            "-s",
            show_default=False,
            help="PATH or FORMAT=PATH — repeatable. The FORMAT is OPTIONAL: omit it and the file's "
            "format is auto-detected (e.g. -s scan.xml -s laptops.csv -s bom.json). Pin a FORMAT only "
            "to override detection (one of: " + " | ".join(_IMPORT_FORMATS) + ").",
        ),
    ],
    name: Annotated[str | None, typer.Option("--name", help="Inventory name for the new inventory.")] = None,
    description: Annotated[str | None, typer.Option("--description", help="Optional inventory description.")] = None,
    into: Annotated[
        str | None,
        typer.Option(
            "--into",
            help="Import the COMBINED set INTO an existing inventory id instead of creating a new one.",
        ),
    ] = None,
    append: Annotated[
        bool,
        typer.Option(
            "--append",
            help="With --into: ADD the combined assets to the existing ones (default replaces).",
        ),
    ] = False,
) -> None:
    """Parse + COMBINE several files into one inventory (the multi-source twin of ``import``), deduping assets
    across sources. Each ``--source [FORMAT=]PATH`` is parsed in isolation server-side then merged; the format
    is auto-detected unless you pin it. A source that fails to parse is reported in ``per_source`` and skipped,
    never failing the whole import."""
    if not sources:
        raise BadInputError("Pass at least one --source PATH (or FORMAT=PATH).")
    payload_sources: list[dict[str, Any]] = []
    for spec in sources:
        # `FORMAT=PATH` pins the format ONLY when the head before `=` is a known format token; anything else
        # (a bare PATH, or a path that happens to contain `=`) auto-detects — so `-s scan.xml` just works.
        head = spec.split("=", 1)[0].strip().lower() if "=" in spec else ""
        if head in _IMPORT_FORMATS:
            fmt = head
            path = Path(spec.split("=", 1)[1].strip())
        else:
            fmt = ""  # auto-detect
            path = Path(spec.strip())
        if not path.is_file():
            raise BadInputError(f"No such file: {path}")
        # xlsx is binary (can't be auto-detected from base64) — read bytes + pin format=xlsx; everything else is
        # text, and an un-pinned format omits the `format` key so the server auto-detects it.
        is_xlsx = fmt == "xlsx" or (not fmt and path.suffix.lower() in (".xlsx", ".xlsm"))
        content: str | bytes = path.read_bytes() if is_xlsx else path.read_text(encoding="utf-8", errors="replace")
        src: dict[str, Any] = {"content": content, "label": path.name}
        if is_xlsx:
            src["format"] = "xlsx"
        elif fmt:
            src["format"] = fmt
        payload_sources.append(src)
    resolved = auth.resolve_auth()
    mode = "append" if append else "replace"

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.inventory_manager.import_multi(
                payload_sources,
                inventory_name=name,
                description=description,
                inventory_id=into,
                mode=mode,
            )

    payload = with_status(f"Combining {len(payload_sources)} sources…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]{'Updated' if p.get('replaced') else 'Imported'}[/green] "
            f"{p.get('item_count', 0)} combined assets "
            f"{'in' if p.get('replaced') else '→'} inventory {p.get('id', '')}"
            + (f" [dim](mode: {p['mode']})[/dim]" if p.get("mode") else "")
            + (f" [yellow](+{p['truncated']} dropped — 200 cap)[/yellow]" if p.get("truncated") else "")
            + "".join(
                f"\n  [dim]· {s.get('label', '?')}: +{s.get('contributed', 0)} new"
                + (f" — {s['error']}" if s.get("error") else "")
                + "[/dim]"
                for s in (p.get("per_source") or [])
            )
        ),
    )


@app.command("export", help="Export an inventory's asset inventory to a file or stdout.")
@handle_errors
def export_command(
    inventory_id: Annotated[str, typer.Argument(help="Inventory (asset) id.", show_default=False)],
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="json | csv | list | cyclonedx | spdx | spdx2 | workbook "
            "(json/csv/list round-trip via import; workbook is a binary .xlsx — needs --output).",
        ),
    ] = "json",
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write to this file instead of stdout."),
    ] = None,
) -> None:
    """Export an inventory via ``client.inventory_manager.export_inventory`` (the text/bytes IS the file)."""
    fmt = fmt.lower()
    if fmt not in _EXPORT_FORMATS:
        raise BadInputError(f"Unknown --format '{fmt}'. One of: {', '.join(_EXPORT_FORMATS)}.")
    # workbook is a binary .xlsx — it can't go to stdout intact, so require an output file.
    if fmt == "workbook" and out is None:
        raise BadInputError("The 'workbook' export is a binary .xlsx — pass --output FILE to write it.")
    if out is not None:
        paths.ensure_writable_output(out)
        if out.exists():
            raise BadInputError(f"Output file already exists: {out}")
    resolved = auth.resolve_auth()

    async def _call() -> str | bytes:
        async with build_client(resolved) as client:
            return await client.inventory_manager.export_inventory(inventory_id, fmt=fmt)

    data = with_status("Exporting inventory…", _call())
    if isinstance(data, (bytes, bytearray)):
        assert out is not None  # workbook is rejected above unless --output is present
        paths.write_atomic(out, data, overwrite=False)  # out is non-None (guarded above)
        Console().print(f"[green]Wrote[/green] {len(data)} bytes to [bold]{escape(str(out))}[/bold]")
    elif out is not None:
        paths.write_atomic(out, data, overwrite=False)
        Console().print(f"[green]Wrote[/green] {len(data)} chars to [bold]{escape(str(out))}[/bold]")
    else:
        typer.echo(data)  # raw to stdout so it can be piped / redirected


__all__ = ["app"]
