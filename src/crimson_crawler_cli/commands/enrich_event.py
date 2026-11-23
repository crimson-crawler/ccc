"""``ccc event-enrich`` — run the async Event Enricher engine end-to-end.

Submits a raw security event (``--event`` / ``--event-file``, a Defender XDR /
Sentinel alert, a SIEM/EDR log line, any JSON or text) to the ``/v1/event-enrich``
engine via the SDK's ``client.enricher.enrich_event`` (submit → poll → per-indicator
result + aggregate verdict), and renders a concise Rich summary (or the full
``{enrichment_id, result}`` payload under ``--json`` / ``--output``).

Like the SDK method, the submit **counts toward your API usage** (it's a
``/v1/event-enrich`` compute request); polling is the engine's own status read.
MCP exposes the same engine as the ``event_enrich`` / ``event_enrich_status`` tool pair.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import auth, output, paths
from ..client_factory import build_client
from ..exceptions import BadInputError
from . import _formatters

_MAX_EVENT_CHARS = 200_000  # mirrors the engine's EventEnrichmentRequest.event cap

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _read_event(event: str | None, event_file: Path | None) -> str:
    """Resolve the raw event from --event and/or --event-file (file wins when both).

    An event over the engine's 200k-char cap is refused here (exit 64) rather than silently
    truncated — the engine would 422 it anyway, and a truncated event would bill for enriching
    something the caller never sent.
    """
    if event_file is not None:
        try:
            raw = event_file.read_text(encoding="utf-8")
        except OSError as exc:  # noqa: BLE001 — surface the underlying read error
            raise BadInputError(f"Could not read event file {event_file}: {exc}") from exc
    elif event is None or not event.strip():
        raise BadInputError("Provide --event and/or --event-file with the raw security event to enrich.")
    else:
        raw = event
    if len(raw) > _MAX_EVENT_CHARS:
        raise BadInputError(f"Event is {len(raw):,} chars; the engine accepts at most {_MAX_EVENT_CHARS:,}.")
    return raw


def _render_event_enrich(console: Any, payload: dict[str, Any]) -> None:
    """Render a concise summary of the event enrichment result.

    Defensive throughout — the engine's result shape is rich and every field here is optional, so
    each lookup uses ``.get`` and degrades to a skipped row rather than raising.
    """
    from rich.table import Table

    enrichment_id = payload.get("enrichment_id")
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    ta = result.get("threat_assessment") if isinstance(result.get("threat_assessment"), dict) else {}
    indicators = result.get("indicators") if isinstance(result.get("indicators"), list) else []
    techniques = result.get("techniques") if isinstance(result.get("techniques"), list) else []
    event_id = result.get("event_id")

    table = Table(title="Crimson Crawler — event enrichment", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Enrichment", _formatters._maybe(enrichment_id))
    if event_id:
        table.add_row("Event ID", _formatters._maybe(event_id))

    verdict = ta.get("verdict")
    if verdict is not None:
        style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "white",
        }.get(str(verdict).lower(), "white")
        table.add_row("Verdict", f"[{style}]{_formatters._maybe(verdict).upper()}[/{style}]")
    table.add_row("Indicators", str(ta.get("indicator_count", len(indicators))))
    extracted = result.get("extracted_count")
    if isinstance(extracted, int):
        table.add_row("Extracted", str(extracted))
    kev_count = ta.get("kev_count")
    if kev_count:
        table.add_row("KEV", str(kev_count))
    weaponized_count = ta.get("weaponized_count")
    if weaponized_count:
        table.add_row("Metasploit module", str(weaponized_count))
    max_w = ta.get("max_weaponization")
    if max_w is not None:
        table.add_row("Max weaponization", f"{max_w:.1f}")
    score = ta.get("score")
    if score is not None:
        table.add_row("Top IOC score", f"{score:.2f}")
    counts = ta.get("counts_by_type")
    if isinstance(counts, dict) and counts:
        breakdown = " · ".join(f"{k} {v}" for k, v in counts.items())
        table.add_row("By type", breakdown)
    if techniques:
        table.add_row("Techniques", str(len(techniques)))
    console.print(table)

    # Top indicators — worst-severity / KEV first (the engine's own sort order).
    if indicators:
        ind_table = Table(title="Indicators", show_lines=False)
        ind_table.add_column("Type", style="cyan")
        ind_table.add_column("Value", overflow="fold")
        ind_table.add_column("Verdict")
        ind_table.add_column("Score")
        ind_table.add_column("Exploit evidence")
        for item in _formatters._cap(indicators, 10):
            if not isinstance(item, dict):
                continue
            ind_table.add_row(
                _formatters._maybe(item.get("type")),
                _formatters._trim(str(item.get("value") or ""), 60),
                _formatters._maybe(item.get("verdict")),
                _formatters._maybe(
                    f"{item['score']:.2f}"
                    if isinstance(item.get("score"), (int, float)) and item["type"] == "ioc"
                    else f"{item['score']:.0f}"
                    if isinstance(item.get("score"), (int, float))
                    else None
                ),
                " · ".join(
                    label for flag, label in ((item.get("kev"), "KEV"), (item.get("weaponized"), "Metasploit")) if flag
                )
                or "-",
            )
        console.print(ind_table)

    errors = result.get("errors") if isinstance(result.get("errors"), list) else []
    if errors:
        table_err = Table(title="Event-level errors", show_lines=False)
        table_err.add_column("Detail", overflow="fold")
        for err in _formatters._cap(errors, 5):
            if isinstance(err, dict):
                table_err.add_row(_formatters._maybe(err.get("detail") or err.get("error")))
        console.print(table_err)


def event_enrich_command(
    *,
    event: str | None = None,
    event_file: Path | None = None,
    event_id: str | None = None,
    output_path: Path | None = None,
) -> None:
    """Submit a raw security event to the Event Enricher engine, poll, and summarize the result."""
    raw_event = _read_event(event, event_file)
    if output_path is not None:
        paths.ensure_writable_output(output_path)  # fail before any billable API work

    resolved = auth.resolve_auth()

    def _call(on_progress: Any) -> Any:
        async def _inner() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.enricher.enrich_event(event=raw_event, event_id=event_id, on_progress=on_progress)

        return _inner()

    payload = _formatters.with_live_progress("Enriching event", _call)

    if output_path is not None:
        paths.write_atomic(output_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        if not output.is_json_mode():
            output.get_error_console().print(f"Report written to {output_path}")
        return

    output.render(payload, _render_event_enrich)


def event_enrich_status_command(enrichment_id: str) -> None:
    """Read one event-enrichment job's status, stages, and result readiness.

    The status half of the ``/v1/event-enrich`` pair. ``ccc event-enrich``
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
            response = await client.event_enrich_status(enrichment_id)
            return response.to_dict()

    payload = _formatters.with_status(f"Reading {enrichment_id}…", _call())
    output.render(payload, _formatters.render_job)


__all__ = ["event_enrich_command", "event_enrich_status_command"]
