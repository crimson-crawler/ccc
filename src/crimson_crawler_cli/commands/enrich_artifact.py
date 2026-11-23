"""``ccc artifact-enrich`` — run the async Artifact Enricher engine end-to-end.

Stages pasted ``--text`` and/or ``--file`` artifacts, submits them to the
``/v1/artifact-enrich`` engine via the SDK's ``client.enricher.enrich`` (submit →
poll → graded report), and renders a concise Rich summary (or the full
``{enrichment_id, report}`` payload under ``--json`` / ``--output``).

Like the SDK method, the submit **counts toward your API usage** (it's a
``/v1/artifact-enrich`` compute request); polling is the engine's own status read.
This mirrors ``ingest``'s option style — :data:`output.JsonFlag` /
:data:`output.ExpandFlag` trailing twins, ``--output FILE``, ``--depth
{fast,full}`` — but runs a single async enrichment rather than a per-product
fan-out. MCP exposes the same engine as the ``artifact_enrich`` and
``artifact_enrich_status`` tool pair.
"""

from __future__ import annotations

import base64
import json
from enum import Enum
from pathlib import Path
from typing import Any

from crimson_crawler_client import Tlp

from .. import auth, output, paths
from ..client_factory import build_client
from ..exceptions import BadInputError
from . import _formatters


class Depth(str, Enum):
    """Enrichment depth for the artifact enrichment."""

    fast = "fast"
    full = "full"


# full: the engine default (include=None) — the complete graded enrichment.
# fast: a minimal include set so the engine skips the heavier optional passes.
_FAST_INCLUDE = ["enrichment"]


def _render_artifact_enrich(console: Any, payload: dict[str, Any]) -> None:
    """Render a concise summary of the enrichment report.

    Defensive throughout — the engine's report shape is rich and every field
    here is optional, so each lookup uses ``.get`` and degrades to "—" / a
    skipped row rather than raising.
    """
    from rich.table import Table

    enrichment_id = payload.get("enrichment_id")
    report = payload.get("report") if isinstance(payload.get("report"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    references = report.get("references") if isinstance(report.get("references"), list) else []

    table = Table(title="Crimson Crawler — artifact enrichment", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Enrichment", _formatters._maybe(enrichment_id))

    saved = payload.get("saved") if isinstance(payload.get("saved"), dict) else None
    if saved:
        sid = saved.get("enrichment_artifact_id") or ("already saved" if saved.get("already_persisted") else None)
        if sid:
            table.add_row("Saved to library", _formatters._maybe(sid))

    grade = summary.get("grade") or report.get("grade")
    if grade is not None:
        table.add_row("Grade", _formatters._maybe(grade))
    confidence = summary.get("confidence")
    if confidence is None:
        confidence = report.get("confidence")
    if confidence is not None:
        table.add_row("Confidence", _formatters._maybe(confidence))

    table.add_row("References", str(len(references)))

    # Action breakdown — the engine tags each reference with a recommended action.
    actions = _count_actions(references)
    if actions:
        # No escaping: _count_actions keys are always one of its four literals.
        breakdown = " · ".join(f"{label} {count}" for label, count in actions.items())
        table.add_row("Actions", breakdown)

    errors = report.get("errors") if isinstance(report.get("errors"), list) else []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    bluf = summary.get("bluf") or report.get("bluf")
    if bluf:
        console.print(f"[bold]BLUF:[/bold] {_formatters._trim(bluf, 400)}")

    prioritized = report.get("prioritized_actions")
    if not isinstance(prioritized, list):
        prioritized = summary.get("prioritized_actions") if isinstance(summary.get("prioritized_actions"), list) else []
    if prioritized:
        action_table = Table(title="Top prioritized actions", show_lines=False)
        action_table.add_column("Action", style="cyan")
        action_table.add_column("Detail", overflow="fold")
        for item in _formatters._cap(prioritized, 5):
            if isinstance(item, dict):
                action = item.get("action") or item.get("title") or ""
                detail = item.get("detail") or item.get("description") or item.get("summary") or ""
            else:
                action, detail = str(item), ""
            action_table.add_row(_formatters._maybe(action), _formatters._trim(detail, 100))
        console.print(action_table)

    # Report schema 2.2 — per-CVE exploit evidence, then the threat context the engine resolved.
    cves = [r for r in references if isinstance(r, dict) and r.get("type") == "cve"]
    cves.sort(key=lambda r: (not (r.get("kev") or r.get("kev_due_date")), -(r.get("score") or 0)))
    if cves:
        _formatters.render_vulnerability_detail(console, cves, title="Vulnerabilities", id_key="value")
    _render_threat_context(console, references, report.get("rollups"))


def _render_threat_context(console: Any, references: list[Any], rollups: Any) -> None:
    """Targets (with the actors known to target them), named groups' reach, and likely next techniques."""
    from rich.markup import escape

    lines: list[str] = []
    for ref in references:
        if not isinstance(ref, dict) or ref.get("type") not in ("location", "sector"):
            continue
        profile = ref.get(ref["type"]) if isinstance(ref.get(ref["type"]), dict) else {}
        name = profile.get("name") or ref.get("value")
        targeting = ref.get("threat_actors_targeting") or []
        who = f"targeted by {len(targeting)} known actors" if targeting else "no known targeting actors"
        lines.append(f"{escape(str(name))} ({ref['type']}): {who}")
    for ref in references:
        if not isinstance(ref, dict) or ref.get("type") != "group":
            continue
        grp = ref.get("group") if isinstance(ref.get("group"), dict) else {}
        risk = ref.get("group_risk") if isinstance(ref.get("group_risk"), dict) else {}
        if not (grp or risk):
            continue
        worst = risk.get("max_weaponization")
        lines.append(
            f"{escape(str(grp.get('name') or ref.get('value')))} (threat group): worst CVE in reach "
            f"{round(worst) if isinstance(worst, (int, float)) else '—'}, "
            f"{risk.get('exploitable_cve_count', 0)} CVEs in reach, {risk.get('kev_cve_count', 0)} on KEV"
        )
    preds: dict[str, float] = {}
    for key in ("technique_coverage", "group_exposure"):
        block = rollups.get(key) if isinstance(rollups, dict) and isinstance(rollups.get(key), dict) else {}
        for p in block.get("predictions") or []:
            if isinstance(p, dict) and p.get("technique_id") and isinstance(p.get("probability"), (int, float)):
                preds[p["technique_id"]] = max(preds.get(p["technique_id"], 0.0), float(p["probability"]))
    if preds:
        top = sorted(preds.items(), key=lambda kv: -kv[1])[:5]
        lines.append("Likely next: " + ", ".join(f"{escape(t)} {p * 100:.0f}%" for t, p in top))
    if lines:
        console.print("[bold]Threat context[/bold]")
        for line in lines:
            console.print(f"  {line}")


def _count_actions(references: list[Any]) -> dict[str, int]:
    """Tally PATCH / BLOCK / WATCH / INFO recommended actions across references.

    Returns an ordered dict (canonical action order) of only the non-zero
    buckets, so a report that never produced an action renders no row at all.
    """
    order = ["PATCH", "BLOCK", "WATCH", "INFO"]
    counts = {label: 0 for label in order}
    for ref in references:
        if not isinstance(ref, dict):
            continue
        action = ref.get("recommended_action") or ref.get("action")
        if isinstance(action, str):
            key = action.strip().upper()
            if key in counts:
                counts[key] += 1
    return {label: n for label, n in counts.items() if n}


def _stage_files(files: list[Path]) -> list[dict[str, str]]:
    """Read each file's bytes and base64-encode into the engine's ``files`` shape."""
    staged: list[dict[str, str]] = []
    for path in files:
        content_b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        staged.append({"filename": path.name, "content_b64": content_b64})
    return staged


def artifact_enrich_command(
    *,
    text: str | None = None,
    files: list[Path] | None = None,
    attached_artifact_ids: list[str] | None = None,
    depth: Depth = Depth.full,
    output_path: Path | None = None,
    save: bool = False,
    tlp: Tlp | None = None,
) -> None:
    """Submit text + files to the Artifact Enricher engine, poll, and summarize the report.

    ``save=True`` files the finished report into your Artifact Manager library once it completes (the
    ``/v1`` engine returns the report but never persists it) — usage-exempt.

    ``attached_artifact_ids`` names the stored artifacts the ``--text`` content came from, so the
    report's ``attachment_sources`` says where its references came from instead of leaving them
    unattributed.

    ``tlp`` is the optional TLP 2.0 marking written into the exported formats that carry one (default
    ``AMBER``; ``openvex``/``csv``/``emass`` have no marking slot).
    """
    file_list = list(files or [])
    if not text and not file_list:
        raise BadInputError("Provide --text and/or at least one --file to enrich.")
    if output_path is not None:
        paths.ensure_writable_output(output_path)  # fail before any billable API work

    resolved = auth.resolve_auth()
    staged = _stage_files(file_list) if file_list else None
    include = None if depth is Depth.full else _FAST_INCLUDE

    def _call(on_progress: Any) -> Any:
        async def _inner() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.enricher.enrich(
                    text=text,
                    files=staged,
                    attached_artifact_ids=list(attached_artifact_ids) if attached_artifact_ids else None,
                    include=include,
                    on_progress=on_progress,
                    save=save,
                    tlp=tlp,
                )

        return _inner()

    payload = _formatters.with_live_progress("Enriching", _call)

    if output_path is not None:
        paths.write_atomic(output_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        if not output.is_json_mode():
            output.get_error_console().print(f"Report written to {output_path}")
        return

    output.render(payload, _render_artifact_enrich)


def artifact_enrich_status_command(enrichment_id: str) -> None:
    """Read one artifact-enrichment job's status, stages, and result readiness.

    The status half of the ``/v1/artifact-enrich`` pair. ``ccc artifact-enrich``
    already submits *and* polls to completion, so this is for the other cases:
    checking a run you walked away from, or reading a job another surface (MCP,
    an SDK script, the portal) submitted on the same key. Unlike the submit, the
    status read does not count toward usage.
    """
    if not enrichment_id.strip():
        raise BadInputError("Pass the enrichment id returned by the submit.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.artifact_enrich_status(enrichment_id)
            return response.to_dict()

    payload = _formatters.with_status(f"Reading {enrichment_id}…", _call())
    output.render(payload, _formatters.render_job)


__all__ = ["Depth", "artifact_enrich_command", "artifact_enrich_status_command"]
