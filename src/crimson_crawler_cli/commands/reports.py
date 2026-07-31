"""``ccc reports`` — generate + manage reports over the key-authed Report Generator API.

Each subcommand routes through the SDK's hand-written ``client.ai_reports`` namespace
(:class:`crimson_crawler_client.AiReportsAPI`) — never the raw escape hatch — satisfying the
convenience-surface invariant. A **report** is a grounded, cite-or-refuse intelligence document built from a template +
saved source artifacts. The whole Report Generator surface is **usage-exempt** (including the LLM
generation). The headline command is ``generate``: create a draft, fill every AI section, fetch the
finished report — in one call.

Browser-only (not exposed here, by design): PDF/DOCX export, the TipTap rich-text editor, the
custom-template builder. The API/CLI export ``html`` / ``md`` of AI-generated reports.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from .. import auth, output
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from ._formatters import with_status

app = typer.Typer(
    name="reports",
    help="Your Report Generator — list templates, create/generate grounded reports from saved "
    "artifacts, export html/md, rename, delete (all usage-exempt).",
    no_args_is_help=True,
)


class ExportFormat(str, Enum):
    """Export format for ``export`` — html or markdown."""

    html = "html"
    md = "md"


class Verbosity(str, Enum):
    """Verbosity for an ad-hoc ``section`` — concise / standard / detailed."""

    concise = "concise"
    standard = "standard"
    detailed = "detailed"


# -- templates / list / show ------------------------------------------------ #


def _render_templates(console: Console, payload: dict[str, Any]) -> None:
    templates = payload.get("templates", [])
    if not templates:
        console.print("[dim]No templates.[/dim]")
        return
    table = Table(title=f"Report templates ({len(templates)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("AI sections", justify="right")
    table.add_column("Description", overflow="fold")
    for t in templates:
        sections = t.get("ai_sections") or []
        table.add_row(
            str(t.get("id", "")), str(t.get("name", "")), str(len(sections)),
            str(t.get("description", "")),
        )
    console.print(table)


@app.command("templates", help="List the built-in report templates.")
@handle_errors
def templates_command(_json: output.JsonFlag = False, _expand: output.ExpandFlag = False) -> None:
    """List templates via ``client.ai_reports.list_templates``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"templates": await client.ai_reports.list_templates()}

    payload = with_status("Listing templates…", _call())
    output.render(payload, _render_templates)


def _render_discovery(console: Console, payload: dict[str, Any]) -> None:
    for k, v in payload.items():
        console.print(f"[bold]{k}:[/bold] {v}")


@app.command("discovery", help="Show the Report Generator API discovery document + your account context.")
@handle_errors
def discovery_command(_json: output.JsonFlag = False, _expand: output.ExpandFlag = False) -> None:
    """Fetch the section's endpoint map + caller context via ``client.ai_reports.discovery``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.discovery()

    payload = with_status("Fetching discovery…", _call())
    output.render(payload, _render_discovery)


def _render_reports(console: Console, payload: dict[str, Any]) -> None:
    reports = payload.get("reports", [])
    if not reports:
        console.print("[dim]No reports.[/dim]")
        return
    table = Table(title=f"Reports ({len(reports)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Created", overflow="fold")
    for r in reports:
        table.add_row(
            str(r.get("id", "")), str(r.get("name", "")),
            str(r.get("created_at", r.get("createdAt", ""))),
        )
    console.print(table)


@app.command("list", help="List your saved reports.")
@handle_errors
def list_command(_json: output.JsonFlag = False, _expand: output.ExpandFlag = False) -> None:
    """List reports via ``client.ai_reports.list_reports``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"reports": await client.ai_reports.list_reports()}

    payload = with_status("Listing reports…", _call())
    output.render(payload, _render_reports)


@app.command("show", help="Show one report's body (HTML).")
@handle_errors
def show_command(
    report_id: Annotated[str, typer.Argument(help="Report id.", show_default=False)],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Fetch a report via ``client.ai_reports.get_report``. In JSON mode emits the full report; in
    human mode prints the report HTML to stdout (pipe-friendly)."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.get_report(report_id)

    payload = with_status("Fetching report…", _call())
    if output.is_json_mode():
        output.render(payload, lambda c, p: None)
    else:
        typer.echo(str(payload.get("content", "")))


# -- create / generate ------------------------------------------------------ #


@app.command("create", help="Create a DRAFT report (scaffold only — fill sections separately).")
@handle_errors
def create_command(
    template: Annotated[str, typer.Argument(help="Template id (see `ccc reports templates`).", show_default=False)],
    source: Annotated[
        list[str] | None,
        typer.Option("--source", "-s", help="Saved artifact id to ground on (repeatable)."),
    ] = None,
    name: Annotated[str | None, typer.Option("--name", help="Optional report name.")] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Create a draft via ``client.ai_reports.create_draft`` (returns id + the AI sections to fill)."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.create_draft(template, source_ids=source or None, name=name)

    payload = with_status("Creating draft…", _call())
    output.render(payload, lambda c, p: c.print(
        f"[green]Draft created[/green] {p.get('id', '')} — "
        f"[dim]{len(p.get('ai_sections') or [])} AI section(s) to fill "
        f"(use `ccc reports generate` to do it in one shot)[/dim]"
    ))


@app.command("generate", help="Generate a report end-to-end (create draft → fill all sections → fetch).")
@handle_errors
def generate_command(
    template: Annotated[str, typer.Argument(help="Template id (see `ccc reports templates`).", show_default=False)],
    source: Annotated[
        list[str] | None,
        typer.Option("--source", "-s", help="Saved artifact id to ground on (repeatable)."),
    ] = None,
    name: Annotated[str | None, typer.Option("--name", help="Optional report name.")] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Generate a full report via ``client.ai_reports.generate_report`` — the headline command. In JSON
    mode emits {report, sections, skipped}; in human mode prints a summary + the report id."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.generate_report(template, source_ids=source or None, name=name)

    payload = with_status("Generating report…", _call())

    def _render(console: Console, p: dict[str, Any]) -> None:
        report = p.get("report") or {}
        sections = p.get("sections") or []
        skipped = p.get("skipped") or []
        console.print(
            f"[green]Report generated[/green] {report.get('id', '')} "
            f"([dim]{report.get('name', '')}[/dim])"
        )
        console.print(f"[dim]{len(sections)} AI section(s) filled[/dim]")
        if skipped:
            joined = ", ".join(map(str, skipped))
            console.print(f"[yellow]{len(skipped)} source id(s) skipped (unresolved): {joined}[/yellow]")

    output.render(payload, _render)


# -- fill / section --------------------------------------------------------- #


@app.command("fill", help="Fill ONE grounded AI section of a draft (the next pending one by default).")
@handle_errors
def fill_command(
    report_id: Annotated[str, typer.Argument(help="Draft report id.", show_default=False)],
    section: Annotated[
        str | None,
        typer.Option("--section", help="Section type to fill (default: the next pending one)."),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Fill one AI section via ``client.ai_reports.fill_section``. In JSON mode emits the full payload
    ({section_type, filled, truncated, remaining, complete}); in human mode prints a one-line status."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.fill_section(report_id, section_type=section)

    payload = with_status("Filling section…", _call())

    def _render(console: Console, p: dict[str, Any]) -> None:
        section_type = p.get("section_type", "")
        if p.get("complete"):
            console.print(f"[green]Filled section[/green] {section_type} — [dim]report complete[/dim]")
        else:
            remaining = len(p.get("remaining") or [])
            console.print(f"[green]Filled section[/green] {section_type} — [dim]{remaining} remaining[/dim]")

    output.render(payload, _render)


@app.command("section", help="Generate one ad-hoc grounded section from sources (NOT tied to a report).")
@handle_errors
def section_command(
    source: Annotated[
        list[str] | None,
        typer.Option("--source", "-s", help="Saved artifact id to ground on (repeatable, required)."),
    ] = None,
    section_type: Annotated[
        str | None,
        typer.Option("--type", help="Template section type to generate."),
    ] = None,
    instruction: Annotated[
        str | None,
        typer.Option("--instruction", help="Free-text instruction for the section."),
    ] = None,
    verbosity: Annotated[
        Verbosity | None,
        typer.Option("--verbosity", help="Section verbosity.", case_sensitive=False),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Generate an ad-hoc grounded section via ``client.ai_reports.section``. Requires at least one
    ``--source``. In JSON mode emits the full payload ({text, truncated, grounded, unsupported_ids});
    in human mode prints the generated text plus any truncated/grounded/unsupported notes."""
    if not source:
        raise BadInputError("At least one --source/-s is required for `ccc reports section`.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.section(
                source,
                section_type=section_type,
                instruction=instruction,
                verbosity=verbosity.value if verbosity is not None else None,
            )

    payload = with_status("Generating section…", _call())

    def _render(console: Console, p: dict[str, Any]) -> None:
        typer.echo(str(p.get("text", "")))
        if p.get("truncated"):
            console.print("[yellow]Section was truncated.[/yellow]")
        if p.get("grounded") is False:
            console.print("[yellow]Section is not fully grounded in the provided sources.[/yellow]")
        unsupported = p.get("unsupported_ids") or []
        if unsupported:
            joined = ", ".join(map(str, unsupported))
            console.print(f"[yellow]Unsupported source id(s): {joined}[/yellow]")

    output.render(payload, _render)


# -- export / rename / delete ----------------------------------------------- #


@app.command("export", help="Export a report as html or md (to stdout or a file).")
@handle_errors
def export_command(
    report_id: Annotated[str, typer.Argument(help="Report id.", show_default=False)],
    fmt: Annotated[
        ExportFormat,
        typer.Option("--format", "-f", help="Export format.", case_sensitive=False),
    ] = ExportFormat.html,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the export to a file instead of stdout."),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Export a report via ``client.ai_reports.export_report``. Writes the file when ``--output`` is
    given, else prints the content to stdout. (PDF/DOCX are browser-editor-only.)"""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.export_report(report_id, fmt.value)

    payload = with_status("Exporting report…", _call())
    content = str(payload.get("content", ""))
    if output_path is not None:
        output_path.write_text(content, encoding="utf-8")
        if output.is_json_mode():
            output.render({"filename": payload.get("filename"), "written": str(output_path)}, lambda c, p: None)
        else:
            output.get_error_console().print(f"Report written to {output_path}")
        return
    if output.is_json_mode():
        output.render(payload, lambda c, p: None)
    else:
        typer.echo(content)


@app.command("rename", help="Rename one of your reports.")
@handle_errors
def rename_command(
    report_id: Annotated[str, typer.Argument(help="Report id.", show_default=False)],
    name: Annotated[str, typer.Argument(help="New report name.", show_default=False)],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Rename a report via ``client.ai_reports.rename_report``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.ai_reports.rename_report(report_id, name)

    payload = with_status("Renaming report…", _call())
    output.render(payload, lambda c, p: c.print(
        f"[green]Renamed[/green] report {p.get('id', report_id)} → {p.get('name', name)}"
    ))


@app.command("delete", help="Delete one of your reports.")
@handle_errors
def delete_command(
    report_id: Annotated[str, typer.Argument(help="Report id.", show_default=False)],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Delete a report via ``client.ai_reports.delete_report``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"deleted": await client.ai_reports.delete_report(report_id), "id": report_id}

    payload = with_status("Deleting report…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Deleted[/green] report {p['id']}"))


__all__ = ["app"]
