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

import html
import unicodedata
from typing import Any

# Per-finding CVE-description cap in the Markdown playbook; lifted entirely under --expand.
_DESC_CAP = 500
# How many Recommended Actions to surface (stays curated even under --expand).
_TOP_ACTIONS = 10

# Inline Markdown/HTML structure an untrusted scalar could otherwise inject. `.` is
# deliberately absent: it is only structural as `N.` at the start of a line, and every
# scalar here is interpolated mid-line after a prefix. Escaping it corrupted ordinary
# content (`scan.xml` -> `scan\.xml`) and the truncation marker below.
_MARKDOWN_STRUCTURAL = "\\`*_{}[]()#+-!|>"


def escape_markdown_scalar(value: object) -> str:
    """Render an untrusted scalar as single-line Markdown text."""
    # NFC, not NFKC: compatibility decomposition rewrites the CLI's own truncation
    # marker `…` into `...` (and ligatures/fullwidth forms into ASCII). Injection is
    # handled by escaping below, so normalization only needs to be canonical.
    normalized = unicodedata.normalize("NFC", str(value))
    characters: list[str] = []
    for character in normalized:
        category = unicodedata.category(character)
        if category == "Cc":
            characters.append(" ")
        elif not category.startswith("C"):
            characters.append(character)
    normalized = "".join(characters)
    normalized = " ".join(normalized.split())
    escaped = html.escape(normalized, quote=False)
    return escaped.translate({ord(character): f"\\{character}" for character in _MARKDOWN_STRUCTURAL})


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _kev_badge(cve: dict[str, Any]) -> str:
    return " **[KEV]**" if cve.get("kev") else ""


def render_briefing(briefing: dict[str, Any], *, scan_file: str, expand: bool = False) -> str:
    """Render the structured briefing into a Markdown playbook string."""
    fmt = escape_markdown_scalar(briefing.get("format", "scan"))
    safe_scan_file = escape_markdown_scalar(scan_file)
    if briefing.get("empty") or briefing.get("parsed_count", 0) == 0:
        return f"# Scan briefing — {safe_scan_file}\n\nNo enrichable assets were found in this {fmt} file.\n"

    report = briefing.get("report") or {}
    summary = report.get("summary") or {}
    assets = report.get("assets") or []
    actions = briefing.get("recommended_actions") or []

    lines: list[str] = [f"# Scan briefing — {safe_scan_file}", ""]
    lines.append(
        f"_{fmt} · {escape_markdown_scalar(briefing.get('parsed_count', 0))} assets · "
        f"{escape_markdown_scalar(summary.get('total_cves', 0))} CVEs · "
        f"{escape_markdown_scalar(summary.get('total_kev', 0))} KEV · "
        f"peak weaponization {escape_markdown_scalar(summary.get('max_weaponization', 0))}_"
    )
    if briefing.get("truncated"):
        lines.append(
            f"\n> ⚠️ {escape_markdown_scalar(briefing['truncated'])} assets over the 200-asset cap were dropped."
        )
    lines.append("")

    # ── Recommended Actions (curated top-N, KEV-first) ──
    lines.append("## Recommended actions")
    if actions:
        for i, a in enumerate(actions[:_TOP_ACTIONS], 1):
            badge = " **[KEV]**" if a.get("kev") else ""
            lines.append(
                f"{i}. {escape_markdown_scalar(a.get('cve_id', '—'))}{badge} — "
                f"{escape_markdown_scalar(a.get('product', '—'))} "
                f"(weaponization {escape_markdown_scalar(a.get('weaponization_score', 0))}) — "
                f"{escape_markdown_scalar(a.get('reason', ''))}"
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
        head = f"### {escape_markdown_scalar(name)}" + (f" ({escape_markdown_scalar(vendor)})" if vendor else "")
        lines.append(head)
        lines.append(
            f"_{escape_markdown_scalar(asset.get('cve_count', 0))} CVEs · "
            f"{escape_markdown_scalar(asset.get('kev_count', 0))} KEV · "
            f"max weaponization {escape_markdown_scalar(asset.get('max_weaponization', 0))}_"
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
                meta.append(f"CVSS {escape_markdown_scalar(cvss)}")
            if epss is not None:
                meta.append(f"EPSS {escape_markdown_scalar(epss)}")
            meta_str = f" ({', '.join(meta)})" if meta else ""
            lines.append(f"- {escape_markdown_scalar(cid)}{_kev_badge(cve)}{meta_str}")
            desc = (cve.get("description") or "").strip()
            if desc:
                if not expand and len(desc) > _DESC_CAP:
                    desc = desc[:_DESC_CAP].rstrip() + "…"
                lines.append(f"  - {escape_markdown_scalar(desc)}")
        lines.append("")

    # ── Errors ──
    errored = [a for a in assets if a.get("status") == "error"]
    if errored:
        lines.append("## Errors")
        for a in errored:
            name = a.get("product") or a.get("name") or "—"
            errs = a.get("errors") or []
            detail = "; ".join(str(e) for e in errs) if errs else "enrichment failed"
            lines.append(f"- {escape_markdown_scalar(name)}: {escape_markdown_scalar(detail)}")
        lines.append("")

    return "\n".join(lines)


__all__ = ["escape_markdown_scalar", "render_briefing"]
