"""Scan → briefing ingest — the CLI's own copy of the ingest component.

One ingest file per client, kept logically IDENTICAL across them (Python SDK, this CLI, MCP) so the
scan→briefing workflow reads the same everywhere. This copy uses the SDK's public ``inventory_manager``
methods (``parse_scan`` + ``enrich_items``) for I/O, so the HTTP/key/retry transport stays in the SDK client.

  • :func:`assemble_briefing` — PURE (no I/O): turns a ``/v1/inventory-enrich`` result into a briefing by
    attaching a top-N KEV-first ``recommended_actions`` list (the engine already ranks per-asset findings).
  • :func:`ingest_scan` — parse the scan (usage-exempt) → enrich the assets (one billable
    ``/v1/inventory-enrich`` submit) → assemble.
"""

from __future__ import annotations

from typing import Any


def assemble_briefing(
    report: dict[str, Any],
    *,
    fmt: str,
    parsed_count: int,
    truncated: Any,
    enrichment_id: Any,
) -> dict[str, Any]:
    """Turn a ``/v1/inventory-enrich`` result into a scan **briefing** — the engine already ranks per-asset
    findings KEV-first, so this just attaches a top-N ``recommended_actions`` list (highest-priority CVEs
    across all assets, KEV first then weaponization, deduped) over the report. Pure (no I/O)."""
    seen: dict[str, dict[str, Any]] = {}
    for asset in report.get("assets") or []:
        product = asset.get("product") or asset.get("name") or "—"
        for cve in asset.get("top_cves") or []:
            cid = cve.get("cve_id")
            if not cid:
                continue
            weap = cve.get("weaponization_score") or 0
            prev = seen.get(cid)
            if prev is None or weap > (prev.get("weaponization_score") or 0):
                seen[cid] = {
                    "cve_id": cid,
                    "product": product,
                    "weaponization_score": weap,
                    "kev": bool(cve.get("kev")),
                    "reason": "KEV-listed — patch now" if cve.get("kev") else "High weaponization",
                }
    actions = sorted(seen.values(), key=lambda a: (0 if a["kev"] else 1, -(a["weaponization_score"] or 0)))[:10]
    out: dict[str, Any] = {
        "format": fmt,
        "parsed_count": parsed_count,
        "enrichment_id": enrichment_id,
        "report": report,
        "recommended_actions": actions,
    }
    if truncated:
        out["truncated"] = truncated
    return out


async def ingest_scan(
    inv_api: Any,
    content: str | bytes,
    scan_format: str,
    *,
    include: list[str] | None = None,
    poll_interval: float = 3.0,
    timeout: float = 300.0,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Parse a scan FILE (server-side, all 11 formats) → enrich the discovered assets against the
    ``/v1/inventory-enrich`` ranking engine → assemble a structured briefing. The parse is usage-exempt;
    the enrichment submit counts toward usage (one request). ``on_progress`` streams the live enrichment
    job each poll (for a live CLI bar / feed). Returns
    ``{format, parsed_count, truncated?, enrichment_id, report, recommended_actions}``; an empty parse
    short-circuits to ``{format, parsed_count: 0, enrichment_id: None, empty: True}``."""
    parsed = await inv_api.parse_scan(content, scan_format)
    items = parsed.get("items") or []
    fmt = parsed.get("format", scan_format)
    truncated = parsed.get("truncated")
    if not items:
        return {"format": fmt, "parsed_count": 0, "enrichment_id": None, "empty": True}
    result = await inv_api.enrich_items(
        items, include=include, poll_interval=poll_interval, timeout=timeout, on_progress=on_progress
    )
    return assemble_briefing(
        result.get("report") or {},
        fmt=fmt,
        parsed_count=len(items),
        truncated=truncated,
        enrichment_id=result.get("enrichment_id"),
    )
