"""Render a scan **briefing** (from the SDK's ``ingest_scan``) into a Markdown playbook.

The parse + per-asset enrichment + KEV-first ranking all happen server-side / in the
SDK now (``client.inventory_manager.ingest_scan`` → parse → ``/v1/inventory-enrich``
→ structured briefing). This module owns ONLY the human-readable Markdown rendering of
that briefing — the CLI's one application-layer job. The raw structured briefing is what
``--json`` emits, so this is never on the JSON path.

Briefing shape (from ``ingest_scan``)::

    { "format", "parsed_count", "enrichment_id", "truncated"?,
      "recommended_actions": [{"cve_id","product","weaponization_score","kev","reason"}],
      "unverified_assets": [{"product","versions","match_detail"}],   # #348 — identity never resolved
      "report": {  # the /v1/inventory-enrich result, already KEV-first ranked
        "summary": {"asset_count","total_cves","total_kev","max_weaponization", ...},
        "assets":  [{"product","vendor","status","cve_count","kev_count","max_weaponization",
                     "top_cves": [{"cve_id","cvss_v3_score","cvss_v3_version","cvss_v4_score",
                                   "cvss_v2_score","epss","kev","weaponization_score","description"?}],
                     "errors": [...]}],
      } }
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

# Per-finding CVE-description cap in the Markdown playbook; lifted entirely under --expand.
_DESC_CAP = 500
# How many Recommended Actions to surface (stays curated even under --expand).
_TOP_ACTIONS = 10

# Structural ANYWHERE in a line — these stay escaped on the Markdown path. `.` is
# deliberately absent: it is only structural as `N.` at the start of a line, and every
# scalar here is interpolated mid-line after a prefix. Escaping it corrupted ordinary
# content (`scan.xml` -> `scan\.xml`) and the truncation marker below.
_MARKDOWN_INLINE = "\\`*_{}[]()!"
# Structural only at the START of a line. Every scalar is interpolated mid-line after a
# prefix, so escaping these mid-string buys no protection and corrupts ordinary content
# (`CVE-2023-38408` -> `CVE\-2023\-38408`, `windows-2019` -> `windows\-2019`). Same
# reasoning as `.` above. They ARE guarded at position 0: `render_briefing` emits its own
# `- ` / `  - ` / `### ` prefixes, and a value starting with one of these would open a
# nested list, heading, or table row inside that prefix. `>` is listed for completeness
# only: `html.escape` runs first and turns a leading `>` into `&gt;`, so this guard never
# sees it — the blockquote case is neutralized by entity-escaping, one step earlier.
_MARKDOWN_LEADING = "-+#>|"
# `str.startswith` takes a tuple; precomputed so the hot path doesn't rebuild it. NOT
# `escaped[:1] in _MARKDOWN_LEADING` — that is substring containment, and `"" in "-+#>|"`
# is True, so an empty scalar (`reason` defaults to `""`) came back as a bare backslash.
_MARKDOWN_LEADING_PREFIXES = tuple(_MARKDOWN_LEADING)
# The other leading structure: an ordered-list marker. CommonMark's is 1-9 digits then `.`
# or `)` then a space or end of line, so `1. injected` after the renderer's `- ` prefix
# nests an ordered list. `)` is already inline-escaped everywhere; `.` is deliberately not
# (see `_MARKDOWN_INLINE`), so the `N.` form needs its own position-0 check. The escape
# goes before the `.` (`1\. foo`), which is the only place CommonMark reads it.
_MARKDOWN_LEADING_ORDERED = re.compile(r"^(\d{1,9})\.(?=\s|$)")
# Translate tables are immutable, so build them once. The scalar renderers run ~4x per CVE
# (up to 200 CVEs x 200 assets at the engine's ceiling ≈ 161k calls per `ccc ingest`), where
# rebuilding this mapping per call cost ~0.2s of pure dict construction.
_INLINE_TABLE = str.maketrans({character: f"\\{character}" for character in _MARKDOWN_INLINE})
# ASCII control characters -> space. `Cc` is the ONLY non-printable category inside ASCII, so
# this single translate is equivalent to the general per-character walk in `plain_scalar`.
_ASCII_CONTROL_TABLE = {codepoint: " " for codepoint in (*range(32), 127)}


def plain_scalar(value: object) -> str:
    """Render an untrusted scalar as single-line plain text.

    This is the terminal destination AND the shared sanitization the Markdown destination
    starts from. It is the whole ANSI-injection / layout-break defense, so it runs on the
    terminal path too — a terminal is a *more* hostile sink than a Markdown file, not less:
    NFC normalization, control/format characters neutralized (`Cc` -> space, other `C*`
    dropped), collapsed to a single line. NFC and not NFKC because compatibility
    decomposition rewrites the CLI's own truncation marker `…` into `...` (and
    ligatures/fullwidth forms into ASCII). No `html.escape` and no structural escaping:
    `&`/`<`/`>` render literally at a terminal, and the backslashes are noise a reader has
    to look past. Markdown structure is `escape_markdown_scalar`'s job.

    Three tiers, all producing identical output. The general walk is a per-character Python
    loop over `unicodedata.category` and is the dominant cost of a large briefing, so the
    two fast paths dispatch to C-level string ops whenever there is nothing to strip —
    which is the overwhelmingly common case, and got hotter once the engine stopped
    truncating descriptions at 400 chars (they now run to ~2.4 KB).
    """
    text = str(value)
    # `str.isprintable()` is False for exactly what the walk neutralizes — every `C*` plus
    # every `Z*` except ASCII space — and NFC can introduce neither, so the walk is the
    # identity here and only the whitespace collapse has anything left to do.
    if text.isprintable():
        return " ".join(unicodedata.normalize("NFC", text).split())
    if text.isascii():  # NFC is the identity on ASCII, and `Cc` is its only non-printable class.
        return " ".join(text.translate(_ASCII_CONTROL_TABLE).split())
    characters: list[str] = []
    for character in unicodedata.normalize("NFC", text):
        category = unicodedata.category(character)
        if category == "Cc":
            characters.append(" ")
        elif not category.startswith("C"):
            characters.append(character)
    return " ".join("".join(characters).split())


def escape_markdown_scalar(value: object) -> str:
    """Render an untrusted scalar as single-line Markdown text (the file/pipe destination)."""
    escaped = html.escape(plain_scalar(value), quote=False).translate(_INLINE_TABLE)
    # Guard the leading position on the RESULTING string, not the input: by here a leading
    # `>` is already `&gt;` (so the guard is a documented no-op for it), and `&`/`<` can't
    # be misread as leading structure.
    if escaped.startswith(_MARKDOWN_LEADING_PREFIXES):
        escaped = "\\" + escaped
    elif escaped[:1].isdigit():
        escaped = _MARKDOWN_LEADING_ORDERED.sub(r"\1\\.", escaped, count=1)
    return escaped


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _kev_badge(cve: dict[str, Any]) -> str:
    return " **[KEV]**" if cve.get("kev") else ""


def render_briefing(briefing: dict[str, Any], *, scan_file: str, expand: bool = False, plain: bool = False) -> str:
    """Render the structured briefing into a Markdown playbook string.

    ``plain`` picks the *destination*, not the layout: the same Markdown playbook is
    emitted either way, but scalars are rendered unescaped for a terminal (the
    backslashes are literal noise there) and escaped for a file or a pipe. Default is
    the Markdown destination, so every existing caller is unaffected.

    It switches the SCALAR layer only — the structural markup this renderer emits itself
    (`#`/`###` headings, `_italics_`, `**[KEV]**` badges) is unchanged, so terminal output
    is unescaped Markdown rather than terminal-native text. That is deliberate: the command
    renders a Markdown playbook and stdout is one destination for it. Rendering the terminal
    path through Rich instead would be a larger change and its own ticket.
    """
    scalar = plain_scalar if plain else escape_markdown_scalar
    fmt = scalar(briefing.get("format", "scan"))
    safe_scan_file = scalar(scan_file)
    if briefing.get("empty") or briefing.get("parsed_count", 0) == 0:
        return f"# Scan briefing — {safe_scan_file}\n\nNo enrichable assets were found in this {fmt} file.\n"

    report = briefing.get("report") or {}
    summary = report.get("summary") or {}
    assets = report.get("assets") or []
    actions = briefing.get("recommended_actions") or []

    lines: list[str] = [f"# Scan briefing — {safe_scan_file}", ""]
    lines.append(
        f"_{fmt} · {scalar(briefing.get('parsed_count', 0))} assets · "
        f"{scalar(summary.get('total_cves', 0))} CVEs · "
        f"{scalar(summary.get('total_kev', 0))} KEV · "
        f"peak weaponization {scalar(summary.get('max_weaponization', 0))}_"
    )
    if briefing.get("truncated"):
        lines.append(
            f"\n> ⚠️ {scalar(briefing['truncated'])} assets over the asset limit "
            "(1,000, at most 200 product assets) were dropped."
        )
    lines.append("")

    # ── Recommended Actions (curated top-N, KEV-first) ──
    lines.append("## Recommended actions")
    if actions:
        for i, a in enumerate(actions[:_TOP_ACTIONS], 1):
            badge = " **[KEV]**" if a.get("kev") else ""
            lines.append(
                f"{i}. {scalar(a.get('cve_id', '—'))}{badge} — "
                f"{scalar(a.get('product', '—'))} "
                f"(weaponization {scalar(a.get('weaponization_score', 0))}) — "
                f"{scalar(a.get('reason', ''))}"
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
        head = f"### {scalar(name)}" + (f" ({scalar(vendor)})" if vendor else "")
        lines.append(head)
        lines.append(
            f"_{scalar(asset.get('cve_count', 0))} CVEs · "
            f"{scalar(asset.get('kev_count', 0))} KEV · "
            f"max weaponization {scalar(asset.get('max_weaponization', 0))}_"
        )
        cves = sorted(
            asset.get("top_cves") or [],
            key=lambda c: (0 if c.get("kev") else 1, -_num(c.get("weaponization_score"))),
        )
        for cve in cves:
            cid = cve.get("cve_id", "—")
            # The API publishes a score per CVSS version and no unversioned one. Name the version
            # in the briefing rather than printing a bare number: v3.1 and v4.0 base scores on the
            # same CVE differ materially. Precedence matches the server's (v3 -> v4 -> v2).
            cvss = cvss_label = None
            for family, default in (("v3", "v3"), ("v4", "v4.0"), ("v2", "v2.0")):
                candidate = cve.get(f"cvss_{family}_score")
                if candidate is not None:
                    cvss = candidate
                    cvss_label = cve.get("cvss_v3_version") if family == "v3" else default
                    break
            epss = cve.get("epss")
            meta = []
            if cvss is not None:
                meta.append(f"CVSS {cvss_label} {scalar(cvss)}")
            if epss is not None:
                meta.append(f"EPSS {scalar(epss)}")
            # Report schema 2.2 evidence: weaponised code and CISA's forensic-review flag change the response.
            mods = [m for m in cve.get("metasploit_modules") or [] if isinstance(m, dict)]
            if mods:
                meta.append(f"Metasploit {scalar(mods[0].get('rank_label') or mods[0].get('module_path') or 'module')}")
            if cve.get("kev_forensic_triage") == "Yes":
                meta.append("CISA advises forensic review")
            if cve.get("fixed_version"):
                meta.append(f"fixed in {scalar(cve['fixed_version'])}")
            meta_str = f" ({', '.join(meta)})" if meta else ""
            lines.append(f"- {scalar(cid)}{_kev_badge(cve)}{meta_str}")
            desc = (cve.get("description") or "").strip()
            if desc:
                if not expand and len(desc) > _DESC_CAP:
                    desc = desc[:_DESC_CAP].rstrip() + "…"
                lines.append(f"  - {scalar(desc)}")
        lines.append("")

    # ── Unverified assets (identity never resolved — #348) ──
    # Assets whose CPE/OSV identity never resolved (match none/cpe_fuzzy) carry no findings because
    # the engine could not LOOK, not because the inventory is clean — surface them so an empty
    # per-asset list above is not mistaken for a clean bill of health. Omitted when none.
    unverified = briefing.get("unverified_assets") or []
    if unverified:
        lines.append("## Unverified assets")
        lines.append("_No CPE/OSV identity resolved — these assets were not checked for vulnerabilities._")
        for entry in unverified:
            product = scalar(entry.get("product") or "—")
            versions = entry.get("versions") or []
            label = f"{product}@{scalar(versions[0])}" if versions else product
            detail = entry.get("match_detail")
            lines.append(f"- {label}" + (f" — {scalar(detail)}" if detail else ""))
        lines.append("")

    # ── Errors ──
    errored = [a for a in assets if a.get("status") == "error"]
    if errored:
        lines.append("## Errors")
        for a in errored:
            name = a.get("product") or a.get("name") or "—"
            errs = a.get("errors") or []
            detail = "; ".join(str(e) for e in errs) if errs else "enrichment failed"
            lines.append(f"- {scalar(name)}: {scalar(detail)}")
        lines.append("")

    return "\n".join(lines)


__all__ = ["escape_markdown_scalar", "plain_scalar", "render_briefing"]
