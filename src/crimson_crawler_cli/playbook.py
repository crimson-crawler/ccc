"""Render a scan **briefing** (from the SDK's ``ingest_scan``) into a Markdown playbook.

The parse + per-asset enrichment + KEV-first ranking all happen server-side / in the
SDK now (``client.inventory_manager.ingest_scan`` → parse → ``/v1/inventory-enrich``
→ structured briefing). This module owns ONLY the human-readable Markdown rendering of
that briefing — the CLI's one application-layer job. The raw structured briefing is what
``--json`` emits, so this is never on the JSON path.

Briefing shape (from ``ingest_scan``)::

    { "format", "parsed_count", "enrichment_id", "truncated"?,
      "recommended_actions": [{"cve_id","product","weaponization_score","kev","reason"}],
      "report": {  # the /v1/inventory-enrich result, already KEV-first ranked
        "summary": {"asset_count","total_cves","total_kev","max_weaponization", ...},
        "assets":  [{"product","vendor","status","cve_count","kev_count","max_weaponization",
                     "top_cves": [{"cve_id","cvss_score","epss","kev","weaponization_score","description"?}],
                     "errors": [...]}],
      } }
"""

from __future__ import annotations

from typing import Any

# Per-finding CVE-description cap in the Markdown playbook; lifted entirely under --expand.
_DESC_CAP = 500
# How many Recommended Actions to surface (stays curated even under --expand).
_TOP_ACTIONS = 10


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _kev_badge(cve: dict[str, Any]) -> str:
    return " **[KEV]**" if cve.get("kev") else ""


def render_briefing(briefing: dict[str, Any], *, scan_file: str, expand: bool = False) -> str:
    """Render the structured briefing into a Markdown playbook string."""
    fmt = briefing.get("format", "scan")
    if briefing.get("empty") or briefing.get("parsed_count", 0) == 0:
        return f"# Scan briefing — {scan_file}\n\nNo enrichable assets were found in this `{fmt}` file.\n"

    report = briefing.get("report") or {}
    summary = report.get("summary") or {}
    assets = report.get("assets") or []
    actions = briefing.get("recommended_actions") or []

    lines: list[str] = [f"# Scan briefing — {scan_file}", ""]
    lines.append(
        f"_{fmt} · {briefing.get('parsed_count', 0)} assets · "
        f"{summary.get('total_cves', 0)} CVEs · {summary.get('total_kev', 0)} KEV · "
        f"peak weaponization {summary.get('max_weaponization', 0)}_"
    )
    if briefing.get("truncated"):
        lines.append(f"\n> ⚠️ {briefing['truncated']} assets over the 200-asset cap were dropped.")
    lines.append("")

    # ── Recommended Actions (curated top-N, KEV-first) ──
    lines.append("## Recommended actions")
    if actions:
        for i, a in enumerate(actions[:_TOP_ACTIONS], 1):
            badge = " **[KEV]**" if a.get("kev") else ""
            lines.append(
                f"{i}. `{a.get('cve_id', '—')}`{badge} — {a.get('product', '—')} "
                f"(weaponization {a.get('weaponization_score', 0)}) — {a.get('reason', '')}"
            )
    else:
        lines.append("_No prioritized CVEs surfaced._")
    lines.append("")

    # ── Per-asset findings ──
    lines.append("## Findings by asset")
    ok_assets = [a for a in assets if a.get("status") != "error"]
    if not ok_assets:
        lines.append("_No assets enriched successfully._")
    for asset in ok_assets:
        name = asset.get("product") or asset.get("name") or "—"
        vendor = asset.get("vendor")
        head = f"### {name}" + (f" ({vendor})" if vendor else "")
        lines.append(head)
        lines.append(
            f"_{asset.get('cve_count', 0)} CVEs · {asset.get('kev_count', 0)} KEV · "
            f"max weaponization {asset.get('max_weaponization', 0)}_"
        )
        cves = sorted(
            asset.get("top_cves") or [],
            key=lambda c: (0 if c.get("kev") else 1, -_num(c.get("weaponization_score"))),
        )
        for cve in cves:
            cid = cve.get("cve_id", "—")
            cvss = cve.get("cvss_score")
            epss = cve.get("epss")
            meta = []
            if cvss is not None:
                meta.append(f"CVSS {cvss}")
            if epss is not None:
                meta.append(f"EPSS {epss}")
            meta_str = f" ({', '.join(meta)})" if meta else ""
            lines.append(f"- `{cid}`{_kev_badge(cve)}{meta_str}")
            desc = (cve.get("description") or "").strip()
            if desc:
                if not expand and len(desc) > _DESC_CAP:
                    desc = desc[:_DESC_CAP].rstrip() + "…"
                lines.append(f"  - {desc}")
        lines.append("")

    # ── Errors ──
    errored = [a for a in assets if a.get("status") == "error"]
    if errored:
        lines.append("## Errors")
        for a in errored:
            name = a.get("product") or a.get("name") or "—"
            errs = a.get("errors") or []
            detail = "; ".join(str(e) for e in errs) if errs else "enrichment failed"
            lines.append(f"- {name}: {detail}")
        lines.append("")

    return "\n".join(lines)


__all__ = ["render_briefing"]
