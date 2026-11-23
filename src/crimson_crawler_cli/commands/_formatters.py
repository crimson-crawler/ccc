"""Rich-table renderers and async helpers shared by the enrichment commands.

Every command turns the SDK response into a ``dict`` via ``to_dict()`` and
hands the same dict to both ``--json`` output and the matching renderer here,
so the human view and the JSON view never drift.

The async helpers (``run_async``, ``with_status``) wrap ``asyncio.run`` and
the Rich spinner used during long ``enrich_*`` waits. The spinner is
suppressed in JSON mode so piped output stays a single clean JSON blob.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any, Awaitable, Callable, Sequence, TypeVar

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import output

T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """Wrap :func:`asyncio.run` so commands can stay synchronous Typer entry points."""
    return asyncio.run(coro)


def with_status(message: str, coro: Awaitable[T]) -> T:
    """Run ``coro`` with a Rich spinner attached, unless in JSON mode."""
    if output.is_json_mode():
        return run_async(coro)
    console = output.get_console()
    with console.status(message, spinner="dots"):
        return run_async(coro)


def with_live_progress(message: str, make_coro: Callable[[Callable[[dict], None]], Awaitable[T]]) -> T:
    """Run an async enrichment with a LIVE progress bar + the streaming per-unit feed.

    ``make_coro(on_progress)`` builds the enrichment coroutine wired to the given progress callback (so
    the SDK calls back on every poll with the live job — ``{status, progress, events}``). The bar fills
    from ``job["progress"]`` and each NEW ``events[]`` line streams above it with the % it reached. In
    JSON mode the live UI is suppressed (a no-op callback) so piped output stays one clean JSON blob.
    """
    if output.is_json_mode():
        return run_async(make_coro(lambda _job: None))

    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

    console = output.get_error_console()  # progress UI on stderr; the report renders to stdout after
    progress = Progress(
        TextColumn("[bold]{task.description}"), BarColumn(), TaskProgressColumn(), console=console, transient=True
    )
    task = progress.add_task(message, total=1000)
    last_ts = {"v": ""}  # ts-keyed so the FIFO-capped buffer can't replay or skip lines

    def on_progress(job: dict) -> None:
        prog = job.get("progress")
        if isinstance(prog, (int, float)):
            progress.update(task, completed=int(prog * 1000))
        events = job.get("events") or []
        newest = last_ts["v"]
        for ev in events:
            if not isinstance(ev, dict):
                continue
            ts = str(ev.get("ts", ""))
            if ts <= last_ts["v"]:
                continue
            newest = max(newest, ts)
            style = {"warning": "yellow", "error": "red"}.get(str(ev.get("level")), "cyan")
            pct = ev.get("progress")
            tag = f" [dim]{round(pct * 100)}%[/dim]" if isinstance(pct, (int, float)) else ""
            progress.console.print(f"  [{style}]›[/{style}] {_trim(ev.get('message', ''), 500)}{tag}", highlight=False)
        last_ts["v"] = newest

    with progress:
        return run_async(make_coro(on_progress))


def _trim(value: Any, limit: int = 80) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").strip()
    if not output.is_expand_mode() and len(text) > limit:
        text = text[: limit - 1] + "…"
    return escape(text)


def _cap(items: list[Any], limit: int) -> list[Any]:
    """Return ``items`` truncated to ``limit`` rows, or all of them under --expand."""
    return items if output.is_expand_mode() else items[:limit]


def _maybe(value: Any, default: str = "—") -> str:
    if value is None or value == "":
        return default
    return escape(str(value))


# The API publishes a field set per CVSS version and no unversioned score, because a CVE serving
# both v3.1 and v4.0 has two real and materially different base scores. Render every version the
# record carries rather than silently picking one.
_CVSS_FAMILIES: tuple[tuple[str, str], ...] = (("v3", "v3"), ("v4", "v4.0"), ("v2", "v2.0"))


def _cvss_rows(cve: dict[str, Any]) -> list[tuple[str, str]]:
    """`(label, value)` pairs for every CVSS version present, e.g. `("CVSS v3.1", "7.3 (HIGH)")`.

    Empty when the CVE carries no score at all, so callers can render a single placeholder row.
    """
    rows: list[tuple[str, str]] = []
    for family, default_label in _CVSS_FAMILIES:
        score = cve.get(f"cvss_{family}_score")
        if score is None:
            continue
        label = cve.get("cvss_v3_version") if family == "v3" else None
        severity = cve.get(f"cvss_{family}_severity")
        value = f"{score} ({severity})" if severity else str(score)
        rows.append((f"CVSS {label or default_label}", escape(value)))
    return rows


def _cvss_compact(cve: dict[str, Any]) -> str:
    """One-cell summary for table columns: `"v3.1 7.3 · v4.0 5.5"`, or `"—"` when unscored."""
    parts = [f"{label.removeprefix('CVSS ')} {value.split(' (')[0]}" for label, value in _cvss_rows(cve)]
    return " · ".join(parts) if parts else "—"


def _cvss_severity(cve: dict[str, Any]) -> str:
    """Severity of the highest-precedence version present — for tables that keep a Severity column.

    Precedence mirrors the server's `services/cvss.py`: v3 first, then v4, then v2, except that a v3
    bucket holding 3.0 drops below v4.0. Kept alongside `_cvss_compact` rather than folded into it
    because collapsing score and severity into one cell dropped the severity from the search table.
    """
    order = (("v4", "v4.0"), ("v3", "v3"), ("v2", "v2.0")) if cve.get("cvss_v3_version") == "3.0" else _CVSS_FAMILIES
    for family, _ in order:
        severity = cve.get(f"cvss_{family}_severity")
        if severity:
            return escape(str(severity))
    return "—"


def _print_no_data(console: Console, target: str, *, hint: str | None = None) -> None:
    """Emit the shared "no data found" line for renderers.

    The v1 API never 404s — when it can't resolve an identifier it
    returns a shape-complete-but-empty response. Each renderer
    short-circuits on its own empty-signal and routes here so the
    four core commands speak with one voice. ``hint`` adds an
    optional same-line follow-up (e.g. the version-not-validated
    note for products).
    """
    suffix = f" {escape(hint)}" if hint else ""
    console.print(f"[yellow]No data found for {escape(target)}.[/yellow]{suffix}")


def _product_label(payload: dict[str, Any]) -> str:
    """Build a ``vendor/product@version`` label from echoed-back inputs."""
    product = payload.get("product") or "this product"
    vendor = payload.get("vendor")
    version = payload.get("version")
    label = f"{vendor}/{product}" if vendor else str(product)
    if version:
        label = f"{label}@{version}"
    return label


def _package_label(payload: dict[str, Any]) -> str:
    """Build an ``ecosystem/package@version`` label from echoed-back inputs."""
    package = payload.get("package") or "this package"
    ecosystem = payload.get("ecosystem")
    version = payload.get("version")
    label = f"{ecosystem}/{package}" if ecosystem else str(package)
    if version:
        label = f"{label}@{version}"
    return label


def _is_in_kev(kev: Any) -> bool:
    """Return ``True`` only when the KEV dict has ``in_kev: True``.

    Centralizes the truthy-dict trap — ``{"in_kev": False, ...}`` is a
    populated dict (so ``if kev:`` would be true) but represents a CVE
    that is *not* on the KEV catalog. Use this anywhere KEV listing is
    consulted as a boolean.
    """
    return isinstance(kev, dict) and bool(kev.get("in_kev"))


def _format_kev(kev: Any) -> str:
    """Build the rich KEV cell — surface due_date + ransomware flag when listed.

    The API returns ``None`` for unlisted CVEs and a dict for listed
    ones. CISA's whole point with KEV is the remediation deadline, so
    hiding that behind a bare "yes" is a UX bug.
    """
    if not _is_in_kev(kev):
        return "no"
    parts: list[str] = []
    due = kev.get("due_date")
    if due:
        parts.append(f"due {due}")
    if kev.get("ransomware"):
        parts.append("ransomware")
    return f"yes — {', '.join(parts)}" if parts else "yes"


def _kev_membership(row: dict[str, Any]) -> str:
    """Membership cell for a KEV catalog row — the row's own ``in_kev``, tri-state rendered.

    A KEV lookup for an unlisted CVE answers with one real row whose ``in_kev`` is ``False`` and
    whose catalogue fields are all ``None``. Rendering that row without a membership column left
    the answer expressed only as blank cells, which reads like an incomplete record rather than
    "not on the catalog". ``False`` is a claim; an absent or null ``in_kev`` is not, so it renders
    as unknown instead of collapsing into "no".
    """
    value = row.get("in_kev") if isinstance(row, dict) else None
    return "—" if value is None else _yes_no(value)


def _epss_value(epss: Any) -> Any:
    """Pull the EPSS probability from the dict, accepting both keys.

    The canonical API field is ``epss.epss``; the legacy SDK shape used
    ``epss.score``. Both are accepted so test fixtures and older
    consumers don't break. Returns ``None`` for non-dict / empty input
    so the caller can hand the result straight to ``_maybe`` or
    ``_format_epss_score``.
    """
    if not isinstance(epss, dict):
        return None
    return epss.get("epss") if "epss" in epss else epss.get("score")


def _format_epss_score(epss: Any, velocity: Any) -> str:
    """Render EPSS score with inline trend annotation when velocity is populated.

    A CVE at 0.50 climbing fast is worse than one at 0.70 holding
    steady — the raw probability hides the actionable signal.
    """
    score = _epss_value(epss)
    if score is None or score == "":
        return "—"
    score_str = str(score)
    if not isinstance(velocity, dict):
        return score_str
    trend = velocity.get("trend")
    delta = velocity.get("change_30d")
    if delta is None:
        delta = velocity.get("delta_30d")
    if trend and delta is not None:
        try:
            sign = "+" if float(delta) >= 0 else ""
            return f"{score_str} ({trend} {sign}{delta} 30d)"
        except (TypeError, ValueError):
            return f"{score_str} ({trend})"
    if trend:
        return f"{score_str} ({trend})"
    return score_str


def _ot_context_rows(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """Rows for the opt-in ``ot_context`` block, shared by the CVE and product renderers.

    Each row appears only when the token answered with something — the same contract as every
    other opt-in row. Untrusted strings are escaped at the read site because Rich renders markup.
    """
    ot = payload.get("ot_context")
    if not isinstance(ot, dict):
        return []
    rows: list[tuple[str, str]] = []
    sectors = [
        escape(str(row["sector"])) for row in ot.get("sectors") or [] if isinstance(row, dict) and row.get("sector")
    ]
    if sectors:
        rows.append(("OT sectors", _trim(", ".join(dict.fromkeys(sectors)), 80)))
    protocols = [escape(str(value)) for value in ot.get("protocols") or []]
    if protocols:
        rows.append(("OT protocols", _trim(", ".join(protocols), 80)))
    rf = [escape(str(value)) for value in ot.get("rf_technology") or []]
    if rf:
        rows.append(("RF technology", _trim(", ".join(rf), 80)))
    fix = ot.get("fix_availability")
    if isinstance(fix, dict):
        bits = [escape(str(fix.get("state") or "unknown"))]
        fixed = [str(value) for value in fix.get("fixed_versions") or []]
        if fixed:
            bits.append("fixed " + escape(", ".join(fixed[:3])))
        if fix.get("eol") is True:
            bits.append("EOL")
        rows.append(("Fix availability", " — ".join(bits)))
    kev_ot = ot.get("kev_ot")
    if isinstance(kev_ot, dict) and kev_ot.get("is_ot"):
        rows.append(("KEV OT vendor", escape(str(kev_ot.get("ot_vendor") or "yes"))))
    iec = ot.get("iec_62443")
    if isinstance(iec, dict) and iec.get("requirements"):
        rows.append(("IEC 62443", f"{len(iec['requirements'])} requirements"))
    return rows


def _count_with_top(items: Any, *, limit: int = 5) -> str:
    """Compose ``"<count> — <top N names>, …"`` from a list of objects.

    Falls back to a bare count when items don't carry usable ``name``
    fields, so e.g. ``"42 — Volt Typhoon, APT41, …"`` replaces the
    useless bare ``"42"`` for `enrich technique` group rows. The ``limit``
    cap lifts under ``--expand`` (via :func:`_cap`), so every name is
    listed and the ``…`` is dropped.
    """
    if not isinstance(items, list):
        return "0"
    count = len(items)
    # Escape here, not at the call sites. This helper composes a string that nine
    # ``add_row`` callers render with markup enabled, and a composed return value
    # is exactly what the semgrep taint rule cannot follow — so the escape has to
    # live where the untrusted field is read, matching sibling ``_maybe``/``_trim``.
    names = [escape(str(it.get("name"))) for it in items if isinstance(it, dict) and it.get("name")]
    if not names:
        return str(count)
    shown = _cap(names, limit)
    head = ", ".join(shown)
    suffix = f"{head}, …" if len(names) > len(shown) else head
    return f"{count} — {suffix}"


def _parse_cpe_uri(cpe: str) -> tuple[str, str]:
    """Extract ``(vendor, product)`` from a CPE 2.3 URI.

    The upstream's flat ``product`` field on each CPE match is often
    empty (only ``vendor`` survives the STIX normalisation), but the
    CPE 2.3 URI carries both at fixed positions:
    ``cpe:2.3:part:vendor:product:version:...``. Parsing the URI is a
    reliable client-side fallback. Returns empty strings on a malformed
    URI rather than raising — the caller already filters those out.
    """
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return "", ""
    parts = cpe.split(":")
    if len(parts) < 5:
        return "", ""
    return parts[3], parts[4]


def _resolve_vendor(payload: dict[str, Any]) -> tuple[str, str, str | None]:
    """Return ``(label, vendor_cell, footer_note)`` for the Vendor row.

    The API echoes ``vendor`` back verbatim from the request. When the
    caller passed ``--vendor`` we surface it as-is. When they didn't,
    the upstream uses a loose product-name substring search that spans
    every CPE dictionary entry mentioning the term. The matched CVEs
    are therefore a mix of distinct ``(vendor, product)`` pairs — e.g.
    a search for ``nginx`` returns ``f5/nginx``, ``kubernetes/ingress-nginx``,
    ``nginx/nginx_ingress_controller``. Listing just the vendor names
    is actionably misleading: ``--vendor kubernetes`` returns nothing
    because the kubernetes product is literally ``ingress-nginx``, not
    ``nginx``. Showing distinct ``vendor/product`` pairs makes the
    narrowing target obvious — the user sees the exact ``(vendor,
    product)`` combination they'd need to pass.

    The ``product`` field on each CPE match is often empty in practice
    (upstream STIX objects don't always expose a flat ``product`` key),
    so we fall back to parsing the CPE 2.3 URI when the dedicated
    field is missing.
    """
    explicit = payload.get("vendor")
    if explicit:
        return "Vendor", str(explicit), None
    cpe_matches = payload.get("cpe_matches") or []
    pairs: list[tuple[str, str]] = []
    for m in cpe_matches:
        if not isinstance(m, dict):
            continue
        vendor = m.get("vendor") or ""
        product = m.get("product") or ""
        if not vendor or not product:
            uri_vendor, uri_product = _parse_cpe_uri(m.get("cpe") or "")
            vendor = vendor or uri_vendor
            product = product or uri_product
        if not vendor:
            continue
        pairs.append((vendor, product))
    if not pairs:
        return "Vendor", "—", None
    counts = Counter(pairs)
    ranked = counts.most_common()

    def _fmt(pair: tuple[str, str]) -> str:
        vendor, product = pair
        return f"{vendor}/{product}" if product else vendor

    if len(ranked) == 1:
        return "Vendor", _fmt(ranked[0][0]), None
    shown = _cap(ranked, 3)
    head = ", ".join(_fmt(p) for p, _ in shown)
    cell = f"{head}, …" if len(ranked) > len(shown) else head
    note = (
        f"Matched {len(ranked)} vendor/product pairs across {len(cpe_matches)} "
        f"CPE entries. Pass --vendor <name> --product <name> to narrow."
    )
    return "Matched CPEs", cell, note


def _current_revision(value: Any) -> str:
    """Tri-state render of ``RevisionEntry.latest``: the source's own answer, or an em dash.

    The CTIButler KB histories carry no current-status at all — ``latest`` is null on every row —
    so this column stays empty for the ATT&CK-family surfaces rather than claiming, the way a bare
    falsy check did, that every row is known not to be the current one.
    """
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "—"


def _render_revision_history(console: Console, rows: Any) -> None:
    """Print an object's KB revision history (``include=['versions']``) as a small table.

    ``Current`` is tri-state (yes / no / —): the CVE path carries the source's own comparison,
    while the KB paths report no current-status and render the dash.
    """
    if not isinstance(rows, list) or not rows:
        return
    _records_table(
        console,
        title=f"Revision history ({len(rows)})",
        columns=(
            ("Modified", lambda row: _maybe(row.get("modified"))),
            ("Versions", lambda row: _joined(row.get("versions"), 30)),
            ("Current", lambda row: _current_revision(row.get("latest"))),
        ),
        rows=[row for row in rows if isinstance(row, dict)],
    )


def _render_exploits(console: Console, rows: Any) -> None:
    """Print exploit provenance (``include=['exploits']``) — the fields the coarse type flattens.

    ``exploit_type`` maps every source exploit onto a few maturity buckets, so the ExploitDB
    ``type``/``platform`` and its verified flag are the parts that decide whether an entry is
    actionable for a given environment. They are printed as their own columns rather than folded
    into the maturity label.
    """
    if not isinstance(rows, list) or not rows:
        return
    _records_table(
        console,
        title=f"Exploits ({len(rows)})",
        columns=(
            ("ID", lambda row: _maybe(row.get("exploitdb_id"))),
            ("Type", lambda row: _maybe(row.get("exploitdb_type"))),
            ("Platform", lambda row: _maybe(row.get("exploitdb_platform"))),
            ("Verified", lambda row: _yes_no(row.get("exploitdb_verified"))),
            ("Maturity", lambda row: _maybe(row.get("exploit_type"))),
            ("Created", lambda row: _trim(row.get("created"), 24)),
        ),
        rows=[row for row in rows if isinstance(row, dict)],
    )


def _render_weaknesses(console: Console, rows: Any) -> None:
    """Print CWE rows with the hierarchy/guidance fields, which the summary row alone hides.

    The CVE table reports a weakness COUNT; this is where the content lands — the hierarchy the
    weakness sits in, its MITRE categories/views, detection guidance and MITRE's exploit-likelihood
    rating, all of which are populated only when the corresponding layer was requested.
    """
    if not isinstance(rows, list) or not rows:
        return
    printable = [row for row in rows if isinstance(row, dict)]
    if not printable:
        return
    _records_table(
        console,
        title=f"Weaknesses ({len(printable)})",
        columns=(
            ("CWE", lambda row: _maybe(row.get("cwe_id"))),
            ("Name", lambda row: _trim(row.get("name"), 40)),
            ("Hierarchy", lambda row: _count_with_top(row.get("related_weaknesses"), limit=3)),
            ("Categories", lambda row: _count_with_top(row.get("categories"), limit=3)),
            ("Views", lambda row: _count_with_top(row.get("views"), limit=3)),
            ("Likelihood", lambda row: _maybe(row.get("likelihood_of_exploit"))),
            ("Detection", lambda row: _count_with_top(row.get("detection_methods"), limit=2)),
        ),
        rows=printable,
    )


# OSV's retraction signal is a timestamp, or an ND envelope boolean with its original timestamp.
# Either form marks a record that must not be treated as live.
# Retracted records reach these renderers from stored OSV lookups or saved enrichment reports.
# Neither table filters them out: the row stays (same
# record, same id, untouched in ``--json``), but it is labelled, kept out of the active count, and
# its ``fixed_versions`` are withheld — a retracted advisory's fix list is not a remediation.
def _withdrawn_date(row: dict[str, Any]) -> str:
    """The retraction timestamp when the advisory carries one, else ``""``."""
    value = row.get("withdrawn")
    if value is None or value is False or value == "":
        return ""
    if value is True:
        timestamp = row.get("withdrawn_at")
        return timestamp if isinstance(timestamp, str) and timestamp else "date unavailable"
    return str(value)


def _advisory_status(row: dict[str, Any]) -> str:
    """Status cell — ``withdrawn <date>`` when retracted, ``active`` otherwise."""
    withdrawn = _withdrawn_date(row)
    return f"withdrawn {_trim(withdrawn, 20)}" if withdrawn else "active"


def _advisory_fix_cell(row: dict[str, Any], limit: int) -> str:
    """Fixed-versions cell; a retracted advisory shows none, so none can read as a recommendation."""
    if _withdrawn_date(row):
        return "— (retracted)"
    return _joined(row.get("fixed_versions"), limit)


def _advisory_counts(advisories: list[dict[str, Any]]) -> tuple[int, int]:
    """``(active, retracted)`` counts — the active count is the one a reader can act on."""
    retracted = sum(1 for row in advisories if _withdrawn_date(row))
    return len(advisories) - retracted, retracted


def _advisory_title(label: str, advisories: list[dict[str, Any]]) -> str:
    """Table title: the ACTIVE count, with retractions called out instead of silently counted in."""
    active, retracted = _advisory_counts(advisories)
    return f"{label} ({active} active, {retracted} retracted)" if retracted else f"{label} ({active})"


def _advisory_retraction_note(console: Console, advisories: list[dict[str, Any]]) -> None:
    """Say once why a retracted row is still on screen — provenance, not a live finding."""
    _, retracted = _advisory_counts(advisories)
    if retracted:
        console.print(
            f"[yellow]{retracted} retracted advisory row(s) kept for provenance — "
            "their fixes are not current recommendations.[/yellow]"
        )


def _render_osv_advisories(console: Console, rows: Any) -> None:
    """Print OSV advisories with their VERSIONED CVSS vectors and their retraction state.

    One unlabelled ``cvss_vector`` could not say whether it was 3.1 or 4.0; the versioned fields
    exist so a reader can see which model scored the advisory — and so a v4 score is not silently
    dropped when a v3 entry comes first.

    The ``/vulns/{id}``-fed lane feeding this table returns retracted records, so a withdrawn
    advisory carries its own status cell and no fix — reported, never deleted.
    """
    if not isinstance(rows, list) or not rows:
        return
    printable = [row for row in rows if isinstance(row, dict)]
    if not printable:
        return
    _records_table(
        console,
        title=_advisory_title("OSV advisories", printable),
        columns=(
            ("Advisory", lambda row: _maybe(row.get("id"))),
            ("Status", _advisory_status),
            ("Severity", lambda row: _maybe(row.get("severity_label"))),
            ("CVSS v3", lambda row: _trim(row.get("cvss_v3_vector"), 30)),
            ("CVSS v4", lambda row: _trim(row.get("cvss_v4_vector"), 30)),
            ("Fixed", lambda row: _advisory_fix_cell(row, 24)),
            ("Summary", lambda row: _trim(row.get("summary"), 50)),
        ),
        rows=printable,
    )
    _advisory_retraction_note(console, printable)
    for row in _cap(printable, 20):
        if row.get("source_url"):
            console.print(f"{_maybe(row.get('id'))} source: {_maybe(row['source_url'])}")
        if row.get("attribution"):
            console.print(f"Attribution: {_maybe(row['attribution'])}")
        if row.get("licence") or row.get("licence_url"):
            console.print(f"Licence: {_maybe(row.get('licence'))} {_maybe(row.get('licence_url'), '')}".rstrip())


def _osv_completeness_note(console: Console, payload: dict[str, Any]) -> None:
    """Say when the OSV list on screen is not the whole indexed set — never leave a gap silent.

    ``osv_advisories_total`` is exact; fewer rows than that, or a truncation flag, means advisories
    were omitted (unreadable, link-only, over budget with no cursor) and the reasons are in ``errors``.
    """
    rows = payload.get("osv_advisories")
    shown = len(rows) if isinstance(rows, list) else 0
    raw_total = payload.get("osv_advisories_total")
    total = raw_total if isinstance(raw_total, int) and not isinstance(raw_total, bool) else None
    if payload.get("osv_advisories_truncated") or (total is not None and total > shown):
        count = f"{shown} of {total}" if total is not None else str(shown)
        detail = (
            "the omissions are listed in errors"
            if total is not None and total > shown
            else "some rows are compact or unreadable"
        )
        console.print(f"[yellow]OSV advisories incomplete: {count} shown; {detail}.[/yellow]")


def _render_linked_techniques(console: Console, techniques: Any) -> None:
    """Print the shared "Linked techniques" sub-table (ID / Name / Tactics, top 15).

    Used by every renderer that carries an ATT&CK technique list
    (``render_cve``, ``render_ioc``, ``render_cwe``) so the columns,
    truncation widths, and 15-row cap stay in one place. The cap and the
    per-cell trims both lift under ``--expand`` (via :func:`_cap` /
    :func:`_trim`). No-ops on an empty/absent list so callers can hand it
    the raw payload field.
    """
    if not techniques:
        return
    tech_table = Table(title="Linked techniques", show_lines=False)
    tech_table.add_column("ID", style="cyan")
    tech_table.add_column("Name")
    tech_table.add_column("Tactics", overflow="fold")
    for tech in _cap(techniques, 15):
        tech_table.add_row(
            _maybe(tech.get("technique_id")),
            _trim(tech.get("name"), 50),
            _trim(", ".join(tech.get("tactics") or []), 60),
        )
    console.print(tech_table)


def render_cve(console: Console, payload: dict[str, Any], requested_id: str | None = None) -> None:
    """Render CVE data and partial source results as Rich tables."""
    cve = payload.get("cve")
    missing_core = cve is None
    if missing_core:
        fields = (
            "epss",
            "kev",
            "cvss_bt",
            "cellular_core_entries",
            "jvn_advisories",
            "ot_vendor_advisories",
            "certfr_advisories",
            "cisa_campaigns",
            "csaf_advisories",
            "weakness_ranks",
            "ot_context",
            "ics_weakness",
            "iec_62443_requirements",
            "sigma_rules",
            "emb3d_threats",
            "affected_chipsets",
            "vulnrichment",
            "android_bulletin",
            "vince_advisories",
            "euvd",
            "cellular_annotations",
            "weaknesses",
            "techniques",
            "revision_history",
            "exploits",
            "poc",
            "osv_advisories",
            "errors",
        )
        if not any(payload.get(field) for field in fields):
            _print_no_data(console, requested_id or "this CVE")
            return
        cve = {"cve_id": requested_id or "unknown"}

    cve_id = cve.get("cve_id") or "unknown"

    table = Table(title=f"Crimson Crawler — {escape(str(cve_id))}", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("CVE", _maybe(cve.get("cve_id")))
    if missing_core:
        table.add_row("CVE record", "Not returned")
    # The record's own NVD state, printed before anything that reads as a live vulnerability: a
    # REJECTED (withdrawn/duplicate) or DEFERRED record otherwise looks exactly like an analyzed one
    # — same description, same scores, same remediation advice.
    status = cve.get("vuln_status")
    if status:
        table.add_row("Record status", _maybe(status))
    table.add_row("Description", _trim(cve.get("description"), 200))
    for cvss_label, cvss_value in _cvss_rows(cve) or [("CVSS", "—")]:
        table.add_row(cvss_label, cvss_value)
    table.add_row("Weaponization score", _maybe(payload.get("weaponization_score")))
    table.add_row("Published", _maybe(cve.get("published")))
    table.add_row("Has public exploit", _maybe(cve.get("has_public_exploit")))
    # Who ASSIGNED the record vs who SCORED it. They are routinely different organisations
    # (Apache assigns and NVD scores), so the split is stated rather than collapsed into one row.
    table.add_row("Assigning CNA", _maybe(cve.get("cna_name")))
    cvss_publishers = {
        cve.get("cvss_v2_source"),
        cve.get("cvss_v3_source"),
        cve.get("cvss_v4_source"),
    }
    publishers = ", ".join(sorted(item for item in cvss_publishers if item))
    if publishers:
        table.add_row("CVSS publisher", publishers)
    # The enrich/cve endpoint surfaces PoCs as the top-level ``poc`` list (populated
    # when ``poc`` is in the include set); ``cve.poc_count`` is left at its default 0
    # there, so derive the count from the list and fall back to the scalar for any
    # other producer that sets it. (#193)
    poc_count = len(payload.get("poc") or []) or cve.get("poc_count")
    table.add_row("PoC count", _maybe(poc_count))

    epss = payload.get("epss") or {}
    table.add_row("EPSS score", _format_epss_score(epss, payload.get("epss_velocity")))
    table.add_row("EPSS percentile", _maybe(epss.get("percentile")))

    table.add_row("KEV", _format_kev(payload.get("kev")))

    # #466: the cvss-bt Base+Threat composite, rendered only when the token was requested and the
    # corpus carried the CVE — an absent token prints nothing, as every opt-in row here does.
    cvss_bt = payload.get("cvss_bt")
    if isinstance(cvss_bt, dict) and cvss_bt.get("cvss_bt_threat") is not None:
        table.add_row(
            "CVSS-BT threat",
            f"{cvss_bt['cvss_bt_threat']} ({cvss_bt.get('cvss_bt_severity') or '—'})",
        )
    cellular_core = payload.get("cellular_core_entries") or []
    if cellular_core:
        table.add_row("Cellular core", ", ".join(str(row.get("implementation") or "") for row in cellular_core))
    jvn = payload.get("jvn_advisories") or []
    if jvn:
        table.add_row("JVN advisories", ", ".join(str(row.get("jvndb_id") or "") for row in jvn))
    ot_vendors = payload.get("ot_vendor_advisories") or []
    if ot_vendors:
        table.add_row(
            "OT vendor advisories",
            escape(", ".join(f"{row.get('source') or '?'}:{row.get('advisory_id') or '?'}" for row in ot_vendors)),
        )
    certfr = payload.get("certfr_advisories") or []
    if certfr:
        table.add_row(
            "CERT-FR advisories",
            escape(", ".join(f"{row.get('id') or '?'}{' [SCADA]' if row.get('scada') else ''}" for row in certfr)),
        )
    cisa_campaigns = payload.get("cisa_campaigns") or []
    if cisa_campaigns:
        table.add_row("CISA advisories", ", ".join(str(row.get("advisory_id") or "") for row in cisa_campaigns))

    csaf = payload.get("csaf_advisories") or []
    if csaf:
        ids = [a.get("tracking_id") for a in csaf if isinstance(a, dict) and a.get("tracking_id")]
        table.add_row("CSAF advisories", f"{len(ids)} ({', '.join(ids[:4])}{'…' if len(ids) > 4 else ''})")

    # #466 surface coverage: the remaining opt-ins render here, each only when the token was
    # requested and answered — the same contract as the CVSS-BT row above.
    ranks = [r for r in (payload.get("weakness_ranks") or []) if isinstance(r, dict) and r.get("rank") is not None]
    if ranks:
        top = min(ranks, key=lambda r: r["rank"])
        label = top.get("cwe_id") or top.get("category") or "—"
        table.add_row(
            "Top weakness rank",
            f"{top.get('list') or 'rank'} #{top['rank']} ({top.get('year') or '—'}) — {label}",
        )
    for label, value in _ot_context_rows(payload):
        table.add_row(label, value)
    if payload.get("ics_weakness"):
        table.add_row("ICS weakness view", _count_with_top(payload.get("ics_weakness")))
    iec_rows = payload.get("iec_62443_requirements") or []
    if iec_rows:
        table.add_row("IEC 62443", f"{len(iec_rows)} weakness mappings")
    if payload.get("sigma_rules"):
        table.add_row("Sigma rules", _count_with_top(payload.get("sigma_rules")))
    if payload.get("emb3d_threats"):
        table.add_row("EMB3D threats", _count_with_top(payload.get("emb3d_threats")))
    chipsets = [
        f"{c.get('vendor') or ''}:{c.get('product') or ''}".strip(":")
        for c in (payload.get("affected_chipsets") or [])
        if isinstance(c, dict)
    ]
    chipsets = [c for c in chipsets if c]
    if chipsets:
        table.add_row("Affected chipsets", f"{len(chipsets)} — {_trim(', '.join(_cap(chipsets, 5)), 80)}")
    vulnrichment = payload.get("vulnrichment")
    if isinstance(vulnrichment, dict) and vulnrichment.get("kev") is not None:
        table.add_row("Vulnrichment KEV", "yes" if vulnrichment.get("kev") else "no")
    # Alternate CVE sources: each opt-in renders only when it answered. Every server-derived
    # field is escaped at the read site (Rich renders markup; `[bold]` in a note title is text).
    bulletin = payload.get("android_bulletin")
    if isinstance(bulletin, dict) and bulletin.get("asb_id"):
        bits = [escape(str(bulletin["asb_id"]))]
        if bulletin.get("component"):
            bits.append(escape(str(bulletin["component"])))
        if bulletin.get("severity"):
            bits.append(f"severity {escape(str(bulletin['severity']))}")
        table.add_row("Android bulletin", " — ".join(bits))
        if bulletin.get("source_url"):
            table.add_row("Android source", _maybe(bulletin["source_url"]))
        if bulletin.get("attribution"):
            table.add_row("Android attribution", _maybe(bulletin["attribution"]))
        elif bulletin.get("licence"):
            table.add_row("Android licence", _maybe(bulletin["licence"]))
    vince = [v for v in (payload.get("vince_advisories") or []) if isinstance(v, dict) and v.get("vuid")]
    if vince:
        top = vince[0]
        label = str(top["vuid"])
        if top.get("title"):
            label += f": {top['title']}"
        count = f"{len(vince)} — " if len(vince) > 1 else ""
        table.add_row("CERT/CC notes", _trim(f"{count}{label}", 80))
    euvd = payload.get("euvd")
    if isinstance(euvd, dict) and euvd.get("euvd_id"):
        bits = [escape(str(euvd["euvd_id"]))]
        if euvd.get("exploited") is not None:
            bits.append("exploited" if euvd["exploited"] else "not marked exploited")
        if euvd.get("cvss_score") is not None:
            bits.append(f"CVSS {escape(str(euvd['cvss_score']))}")
        table.add_row("EUVD", " — ".join(bits))
    cellular = [c for c in (payload.get("cellular_annotations") or []) if isinstance(c, dict)]
    if cellular:
        row = cellular[0]
        tags = [str(t) for t in (row.get("tags") or []) if t]
        if not tags:
            tags = [name for name in ("native_5g", "lte", "auxiliary") if row.get(name)]
        table.add_row("Cellular dataset", f"{len(cellular)} — {_trim(', '.join(tags) or '—', 80)}")

    weaknesses = payload.get("weaknesses") or []
    table.add_row("CWE count", str(len(weaknesses)))
    techniques = payload.get("techniques") or []
    table.add_row("Techniques", str(len(techniques)))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)
    if missing_core:
        _records_table(
            console,
            title="Partial failures",
            columns=(
                ("Source", lambda row: _maybe(row.get("service"))),
                ("Error", lambda row: _maybe(row.get("error"))),
                ("Detail", lambda row: _maybe(row.get("detail"))),
            ),
            rows=errors,
        )

    _render_weaknesses(console, weaknesses)
    _render_revision_history(console, payload.get("revision_history"))
    _render_exploits(console, payload.get("exploits"))
    _render_osv_advisories(console, payload.get("osv_advisories"))
    _osv_completeness_note(console, payload)
    _render_linked_techniques(console, techniques)


def render_product(console: Console, payload: dict[str, Any]) -> None:
    """Render the response from ``enrich_product_full`` as a Rich table.

    The API echoes ``product``/``vendor``/``version`` back verbatim
    without validating them against the CPE dictionary. When both
    ``cpe_matches`` and ``cves`` are empty there are three causes we
    can't distinguish server-side — typo, unknown vendor/product, or
    real product with no published CVEs — so emit a "no data" line
    with the version-not-validated hint and let the user resolve it.
    """
    cpe_matches = payload.get("cpe_matches") or []
    cves = payload.get("cves") or []
    if not cpe_matches and not cves:
        _print_no_data(
            console,
            _product_label(payload),
            hint="Check vendor/product/version spelling — the version field isn't validated server-side.",
        )
        if payload.get("discovery_truncation_reason"):
            console.print(f"Discovery completeness: {escape(str(payload['discovery_truncation_reason']))}")
        return

    table = Table(title="Crimson Crawler — product", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    vendor_label, vendor_cell, vendor_note = _resolve_vendor(payload)
    table.add_row("Product", _maybe(payload.get("product")))
    table.add_row(vendor_label, vendor_cell)
    table.add_row("Version", _maybe(payload.get("version")))
    table.add_row("Highest weaponization score", _maybe(payload.get("highest_weaponization_score")))
    table.add_row("Matching CVEs", str(len(payload.get("cves") or [])))
    if "cves_discovered" in payload:
        table.add_row("Discovered CVEs", str(payload["cves_discovered"]))
        table.add_row("CVEs in rollups", str(payload.get("rollups_over", 0)))
        reason = payload.get("discovery_truncation_reason")
        table.add_row("Discovery completeness", escape(str(reason)) if reason else "complete")
    table.add_row("CPE matches", str(len(payload.get("cpe_matches") or [])))
    # #466: endoflife.date support/EOL block, present only when `lifecycle` was requested.
    lifecycle = payload.get("lifecycle")
    if isinstance(lifecycle, dict):
        eol = lifecycle.get("eol")
        # Escape where the untrusted field is read: `add_row` renders markup, so a product or
        # release string carrying `[...]` must never reach Rich raw.
        eol_cell = "supported" if eol is False else ("—" if eol is None else escape(str(eol)))
        latest = lifecycle.get("latest")
        table.add_row(
            "Lifecycle",
            "{cycle} — EOL {eol}{latest}".format(
                cycle=escape(str(lifecycle.get("cycle") or lifecycle.get("product") or "—")),
                eol=eol_cell,
                latest=f", latest {escape(str(latest))}" if latest else "",
            ),
        )
    for label, value in _ot_context_rows(payload):
        table.add_row(label, value)
    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)
    if vendor_note:
        console.print(f"[dim]Note: {escape(vendor_note)}[/dim]")

    cves = payload.get("cves") or []
    if cves:
        cve_table = Table(title="Top CVEs", show_lines=False)
        cve_table.add_column("CVE", style="cyan")
        cve_table.add_column("CVSS")
        cve_table.add_column("EPSS")
        cve_table.add_column("KEV")
        cve_table.add_column("Description", overflow="fold")
        for entry in _cap(cves, 10):
            cve = (entry.get("cve") or {}) if isinstance(entry, dict) else {}
            epss = entry.get("epss") if isinstance(entry, dict) else None
            kev = entry.get("kev") if isinstance(entry, dict) else None
            cve_table.add_row(
                _maybe(cve.get("cve_id") or (entry.get("discovered_cve_id") if isinstance(entry, dict) else None)),
                _cvss_compact(cve),
                _maybe(_epss_value(epss)),
                "yes" if _is_in_kev(kev) else "no",
                _trim(cve.get("description"), 70),
            )
        console.print(cve_table)


def render_package(console: Console, payload: dict[str, Any]) -> None:
    """Render the response from ``enrich_package_full`` as a Rich table.

    The package-ecosystem sibling of :func:`render_product`: OSV advisories +
    the CVEs they alias (enriched through the full chain). When both ``cves``
    and ``advisories`` are empty there are three indistinguishable causes —
    unknown package, a typo, or a package with no known vulnerabilities — so
    emit a "no data" line and let the user resolve it.

    A retracted advisory (``withdrawn`` set) stays listed and identified, but is
    excluded from the actionable counts and shows no fix.
    """
    cves = payload.get("cves") or []
    advisories = payload.get("advisories") or []
    printable_advisories = [row for row in advisories if isinstance(row, dict)]
    if not cves and not advisories:
        _print_no_data(
            console,
            _package_label(payload),
            hint="Check the ecosystem + package spelling (e.g. 'npm lodash', 'PyPI django').",
        )
        return

    table = Table(title="Crimson Crawler — package", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Package", _maybe(payload.get("package")))
    table.add_row("Ecosystem", _maybe(payload.get("ecosystem")))
    table.add_row("Version", _maybe(payload.get("version")))
    table.add_row("Highest weaponization score", _maybe(payload.get("highest_weaponization_score")))
    table.add_row("Matching CVEs", str(len(cves)))
    # The payload's own count when it carries one — an explicit ``0`` is a real answer, and
    # ``or len(advisories)`` read that 0 as "absent" and recomputed it from the list, resurrecting
    # exactly the number a retracted-advisory reduction had already dropped.
    count = payload.get("vulnerability_count")
    table.add_row("Advisories", str(count if count is not None else len(advisories)))
    active_advisories, retracted_advisories = _advisory_counts(printable_advisories)
    if retracted_advisories:
        table.add_row("Active advisories", f"{active_advisories} (excludes {retracted_advisories} retracted)")
    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    if cves:
        cve_table = Table(title="Top CVEs", show_lines=False)
        cve_table.add_column("CVE", style="cyan")
        cve_table.add_column("CVSS")
        cve_table.add_column("EPSS")
        cve_table.add_column("KEV")
        cve_table.add_column("Description", overflow="fold")
        for entry in _cap(cves, 10):
            cve = (entry.get("cve") or {}) if isinstance(entry, dict) else {}
            epss = entry.get("epss") if isinstance(entry, dict) else None
            kev = entry.get("kev") if isinstance(entry, dict) else None
            cve_table.add_row(
                _maybe(cve.get("cve_id")),
                _cvss_compact(cve),
                _maybe(_epss_value(epss)),
                "yes" if _is_in_kev(kev) else "no",
                _trim(cve.get("description"), 70),
            )
        console.print(cve_table)

    # OSV's ecosystem advisories (GHSA / PYSEC / RUSTSEC / GO — including the non-CVE findings the
    # CPE-keyed product endpoint can't reach). CVE-aliased ones are already enriched into Top CVEs.
    if printable_advisories:
        adv_table = Table(title=_advisory_title("OSV advisories", printable_advisories), show_lines=False)
        adv_table.add_column("ID", style="cyan")
        adv_table.add_column("Aliases")
        adv_table.add_column("Status")
        adv_table.add_column("Fixed")
        adv_table.add_column("Summary", overflow="fold")
        for adv in _cap(printable_advisories, 10):
            aliases = adv.get("cve_ids") or adv.get("aliases") or []
            adv_table.add_row(
                _maybe(adv.get("id")),
                _trim(", ".join(str(a) for a in aliases) if aliases else None, 28),
                _advisory_status(adv),
                _advisory_fix_cell(adv, 20),
                _trim(adv.get("summary") or adv.get("details"), 60),
            )
        console.print(adv_table)
        _advisory_retraction_note(console, printable_advisories)


def render_technique(
    console: Console,
    payload: dict[str, Any],
    requested_id: str | None = None,
) -> None:
    """Render the response from ``enrich_technique_full`` as a Rich table.

    Empty ``techniques`` means the ATT&CK id wasn't in the requested
    framework — short-circuit so the all-zeros table doesn't read as
    "technique exists but has no associations".
    """
    techniques = payload.get("techniques") or []
    # A technique id the framework does not know still answers a corpus opt-in: the live `lotl`
    # response carries `techniques: []` plus 648 `lol_drivers`. Only an entirely empty answer is
    # "no data".
    opt_in_rows = (
        "fight_techniques",
        "lolbas_binaries",
        "gtfobins_binaries",
        "hijacklibs_entries",
        "atomic_tests",
        "sigma_rules",
        "framework_mappings",
        "asset_classes",
        "cisa_campaigns",
        "lol_drivers",
    )
    if not techniques and not any(payload.get(key) for key in opt_in_rows):
        _print_no_data(console, requested_id or "this technique")
        return
    name = techniques[0].get("technique_id", "technique") if techniques else (requested_id or "technique")
    title = f"Crimson Crawler — {name}"
    table = Table(title=title, title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Techniques", str(len(techniques)))
    fight = payload.get("fight_techniques") or []
    if fight:
        table.add_row("FiGHT techniques", ", ".join(str(row.get("id") or "") for row in fight))
    lolbas = payload.get("lolbas_binaries") or []
    if lolbas:
        table.add_row("LOLBAS binaries", str(len(lolbas)))
    gtfobins = payload.get("gtfobins_binaries") or []
    if gtfobins:
        table.add_row("GTFOBins tools", _count_with_top(gtfobins))
    hijacklibs = payload.get("hijacklibs_entries") or []
    if hijacklibs:
        table.add_row("HijackLibs DLLs", _count_with_top(hijacklibs))
    table.add_row("Predictions", str(len(payload.get("predictions") or [])))
    table.add_row("Groups", _count_with_top(payload.get("groups")))
    table.add_row("Software", _count_with_top(payload.get("software")))
    table.add_row("Campaigns", _count_with_top(payload.get("campaigns")))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))
    asset = payload.get("asset")
    if isinstance(asset, dict):
        # The ICS-asset lookup's own result: `techniques` holds the asset's targets, so without this
        # row the table shows technique rows with no record of which asset answered.
        asset_label = " — ".join(str(part) for part in (asset.get("asset_id"), asset.get("name")) if part)
        table.add_row("ICS asset", _trim(asset_label, 80) if asset_label else "—")
    table.add_row("Threat level", _maybe(payload.get("threat_level")))
    # #466 surface coverage: detection + control corpora, each only when requested and answered.
    if payload.get("sigma_rules"):
        table.add_row("Sigma rules", _count_with_top(payload.get("sigma_rules")))
    mappings = [m for m in (payload.get("framework_mappings") or []) if isinstance(m, dict)]
    if mappings:
        families = sorted({str(m.get("framework")) for m in mappings if m.get("framework")})
        table.add_row(
            "Framework mappings",
            f"{len(mappings)} — {_trim(', '.join(_cap(families, 9)), 80)}",
        )
    if payload.get("asset_classes"):
        table.add_row("Asset classes", _count_with_top(payload.get("asset_classes")))
    cisa_campaigns = payload.get("cisa_campaigns") or []
    if cisa_campaigns:
        table.add_row("CISA advisories", ", ".join(str(row.get("advisory_id") or "") for row in cisa_campaigns))
    # #466: the LOTL corpus exercising this technique — LOLDrivers plus the facts-only GTFOBins
    # and HijackLibs rows. Named at the read site, escaped like every other server field.
    lotl = [d for d in (payload.get("lol_drivers") or []) if isinstance(d, dict)]
    if lotl:
        top = lotl[0]
        label = str(top.get("name") or top.get("id") or "entry")
        if top.get("category"):
            label += f" ({top['category']})"
        count = f"{len(lotl)} — " if len(lotl) > 1 else ""
        table.add_row("LOLDrivers", f"{count}{_trim(label, 80)}")
    # #466: Atomic Red Team tests for the technique, facts only (no command bodies).
    atomic = [t for t in (payload.get("atomic_tests") or []) if isinstance(t, dict)]
    if atomic:
        top = atomic[0]
        # `_trim` escapes its result (Rich renders markup), so the label is escaped exactly once here.
        label = _trim(str(top.get("name") or top.get("technique_id") or "test"), 80)
        total = payload.get("atomic_tests_total")
        size = f"{len(atomic)} of {total}" if isinstance(total, int) and total > len(atomic) else str(len(atomic))
        executor = f" · {escape(str(top['executor_name']))}" if top.get("executor_name") else ""
        table.add_row("Atomic Red Team tests", f"{size} — {label}{executor}")
    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    if techniques:
        detail = techniques[0]
        detail_table = Table(title="Primary technique", show_header=False)
        detail_table.add_column("field", style="bold")
        detail_table.add_column("value", overflow="fold")
        detail_table.add_row("ID", _maybe(detail.get("technique_id")))
        detail_table.add_row("Name", _maybe(detail.get("name")))
        detail_table.add_row("Tactics", _trim(", ".join(detail.get("tactics") or []), 120))
        detail_table.add_row("Platforms", _trim(", ".join(detail.get("platforms") or []), 120))
        if detail.get("impact_type"):
            detail_table.add_row("Impact", _joined(detail.get("impact_type"), 60))
        if detail.get("tactic_type"):
            detail_table.add_row("Mobile tactic type", _joined(detail.get("tactic_type"), 60))
        detail_table.add_row("Description", _trim(detail.get("description"), 240))
        console.print(detail_table)
        _render_analytic_details(console, detail)
        _render_f3_techniques(console, detail.get("f3_techniques"))
        _render_revision_history(console, detail.get("revision_history"))


def _render_f3_techniques(console: Console, rows: Any) -> None:
    """Print the MITRE F3 fraud techniques that resolve to this ATT&CK technique (``include=['fraud']``).

    The F3 corpus borrows 43 Enterprise ``T####`` ids; this is the reverse hop from the ATT&CK side,
    and it is opt-in because it is a second knowledge base behind its own read.
    """
    if not isinstance(rows, list) or not rows:
        return
    _records_table(
        console,
        title=f"F3 fraud techniques ({len(rows)})",
        columns=(
            ("Object", lambda row: _maybe(row.get("object_id"))),
            ("Name", lambda row: _trim(row.get("name"), 80)),
            ("URL", lambda row: _trim(row.get("url"), 80)),
        ),
        rows=[row for row in rows if isinstance(row, dict)],
    )


def _render_analytic_details(console: Console, detail: dict[str, Any]) -> None:
    """Print the per-analytic tunables and log sources (`include=['analytic_details']`).

    A v18 analytic's actionable half: the fields an operator tunes (``TargetDLLDirectory``,
    ``SignedImageValidation``) and the concrete log source/channel to configure. The default
    technique body carries only the analytic prose, so without this a detection strategy reads as
    a description rather than something implementable.
    """
    strategies = detail.get("detection_strategies") or []
    rows: list[tuple[str, str, str, str]] = []
    for strategy in strategies:
        if not isinstance(strategy, dict):
            continue
        for analytic in strategy.get("analytics_detail") or []:
            if not isinstance(analytic, dict):
                continue
            tunables = ", ".join(
                str(item.get("field"))
                for item in (analytic.get("mutable_elements") or [])
                if isinstance(item, dict) and item.get("field")
            )
            sources = ", ".join(
                str(item.get("name")) + (f" ({item.get('channel')})" if item.get("channel") else "")
                for item in (analytic.get("log_source_references") or [])
                if isinstance(item, dict) and item.get("name")
            )
            rows.append((_trim(strategy.get("name"), 30), _trim(analytic.get("name"), 40), tunables, sources))
    if not rows:
        return
    table = Table(title=f"Analytic details ({len(rows)})", show_lines=False)
    table.add_column("Strategy", overflow="fold")
    table.add_column("Analytic", overflow="fold")
    table.add_column("Tunable fields", overflow="fold")
    table.add_column("Log sources", overflow="fold")
    for row in rows[:15]:
        table.add_row(*(escape(cell) for cell in row))
    console.print(table)


def _threat_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the ``threat_assessment`` sub-dict, or an empty dict.

    The API returns ``None`` when MISP enrichment didn't run; normalise
    so callers can ``.get()`` without an isinstance dance.
    """
    ta = payload.get("threat_assessment")
    return ta if isinstance(ta, dict) else {}


def _on_warninglist(payload: dict[str, Any]) -> str:
    """Render the warninglist cell — the warninglist names when listed.

    A false-positive IOC (RFC1918 space, public DNS, CDN range) on a MISP
    warninglist is the single most actionable signal for artifact-enrichment, so surface
    the matched lists rather than a bare "yes".
    """
    wl = payload.get("warninglist")
    if not isinstance(wl, dict) or not wl.get("is_on_warninglist"):
        return "no"
    names = [n for n in (wl.get("warninglists") or []) if n]
    return f"yes — {_trim(', '.join(names), 60)}" if names else "yes"


def render_ioc(console: Console, payload: dict[str, Any]) -> None:
    """Render the response from ``enrich_ioc_full`` as a Rich table.

    The API echoes ``value``/``type_`` back verbatim and never 404s, so
    "nothing matched" is a shape-complete-but-empty response. When MISP
    found nothing and no ATT&CK techniques linked, short-circuit to the
    not-found line rather than render an all-zeros table that reads as
    "exists with no detail".
    """
    misp_attributes = payload.get("misp_attributes") or []
    misp_feed_hits = payload.get("misp_feed_hits") or []
    techniques = payload.get("techniques") or []
    network_context = payload.get("network_context")
    domain_context = payload.get("domain_context")
    listed_on = payload.get("listed_on") or []
    if (
        not misp_attributes
        and not misp_feed_hits
        and not techniques
        and not (network_context or domain_context or listed_on)
    ):
        _print_no_data(console, _maybe(payload.get("value"), "this indicator"))
        return

    ta = _threat_assessment(payload)
    title = f"Crimson Crawler — {_maybe(payload.get('value'))}"
    table = Table(title=title, title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Indicator", _maybe(payload.get("value")))
    # The generated model attribute is ``type_`` (reserved word) but its
    # ``to_dict()`` serialises back to the OpenAPI key ``type``.
    table.add_row("Type", _maybe(payload.get("type")))
    table.add_row("Verdict", _maybe(ta.get("verdict")))
    table.add_row("Threat score", _maybe(ta.get("threat_score")))
    table.add_row("MISP attributes", str(len(misp_attributes)))
    table.add_row("MISP feed hits", str(len(misp_feed_hits)))
    table.add_row("Sightings", _maybe(payload.get("sightings_count")))
    table.add_row("On warninglist", _on_warninglist(payload))
    # #466: CIRCL hashlookup / NSRL known-good verdict, present only for a hash indicator whose
    # token was requested. A known-good hit is a triage signal, so it is stated explicitly.
    hashlookup = payload.get("hashlookup")
    if isinstance(hashlookup, dict):
        if hashlookup.get("known"):
            verdict = "known-good" if hashlookup.get("nsrl") else "known"
            trust = hashlookup.get("trust")
            table.add_row("Hashlookup", f"{verdict} (trust {trust})" if trust is not None else verdict)
        else:
            table.add_row("Hashlookup", "unknown")
    cisa_campaigns = payload.get("cisa_campaigns") or []
    if cisa_campaigns:
        table.add_row("CISA advisories", ", ".join(str(row.get("advisory_id") or "") for row in cisa_campaigns))
    # #466 IOC network layer: ASN / registration country / prefix (IP values), RDAP registration facts
    # (domains and URL hosts), and the unified list-hit ledger (feeds + Spamhaus DROP/ASN-DROP).
    if isinstance(network_context, dict):
        asn = network_context.get("asn")
        as_name = network_context.get("as_name") or ""
        network = f"AS{asn} {as_name}".strip() if asn else "not routed / unknown"
        country = network_context.get("country") or "unknown country"
        prefix = network_context.get("prefix") or "no covering prefix"
        table.add_row("Network", f"{network}; {country}; {prefix}")
    if isinstance(domain_context, dict):
        age = domain_context.get("age_days")
        registered = domain_context.get("registration_date") or "unknown"
        registrar = domain_context.get("registrar") or "unknown registrar"
        table.add_row("Domain registration", f"{registered} ({age if age is not None else '?'} days); {registrar}")
    if listed_on:
        table.add_row(
            "Listed on",
            "; ".join(f"{row.get('source')}/{row.get('list')} ({row.get('match')})" for row in listed_on),
        )
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    _render_linked_techniques(console, techniques)


def render_cwe(console: Console, payload: dict[str, Any], requested_id: str | None = None) -> None:
    """Render the response from ``enrich_cwe_full`` as a Rich table.

    Two miss shapes, both handled before the detail table: ``weakness: null`` with a
    non-empty ``search_results`` is a ``--search`` call that matched — render the
    matches, because printing "no data" there would hide every hit; ``weakness: null``
    with neither is the API's graceful-degradation signal for an unresolved CWE id.

    The hierarchy, MITRE categories/views, detection guidance and exploit-likelihood
    rating are rendered from the weakness itself rather than as counts alone — they are
    the reason to request the CWE-bundle layers, and a bare count tells a reader nothing
    about *which* parent or view applies.
    """
    weakness = payload.get("weakness")
    if weakness is None:
        matches = payload.get("search_results") or []
        if not matches:
            _print_no_data(console, requested_id or "this CWE")
            return
        _records_table(
            console,
            title=f"Crimson Crawler — matches ({len(matches)})",
            columns=(
                ("CWE", lambda row: _maybe(row.get("cwe_id"))),
                ("Name", lambda row: _trim(row.get("name"), 40)),
                ("Description", lambda row: _trim(row.get("description"), 70)),
            ),
            rows=[row for row in matches if isinstance(row, dict)],
        )
        _errors_note(console, payload)
        return

    cwe_id = weakness.get("cwe_id") or "unknown"
    table = Table(title=f"Crimson Crawler — {escape(str(cwe_id))}", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("CWE", _maybe(weakness.get("cwe_id")))
    table.add_row("Name", _trim(weakness.get("name"), 80))
    table.add_row("Description", _trim(weakness.get("description"), 200))
    if weakness.get("revoked"):
        table.add_row("Revoked", "yes — MITRE has withdrawn this weakness")
    if weakness.get("is_generic"):
        table.add_row("Generic weakness", "yes — broad pillar/class; technique mappings may overlap across CVEs")
    table.add_row("Exploit likelihood", _maybe(weakness.get("likelihood_of_exploit")))

    capecs = payload.get("attack_patterns") or []
    table.add_row("CAPEC patterns", str(len(capecs)))
    techniques = payload.get("techniques") or []
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))
    related = weakness.get("related_weaknesses") or []
    table.add_row("Related weaknesses", str(len(related)))
    table.add_row("Categories", _count_with_top(weakness.get("categories"), limit=3))
    table.add_row("Views", _count_with_top(weakness.get("views"), limit=3))
    table.add_row("Detection methods", _count_with_top(weakness.get("detection_methods"), limit=3))

    freq = payload.get("exploitation_frequency")
    if isinstance(freq, dict) and freq.get("exploitation_class"):
        table.add_row("Exploitation class", _maybe(freq.get("exploitation_class")))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    if related:
        _records_table(
            console,
            title=f"CWE hierarchy ({len(related)})",
            columns=(
                ("Nature", lambda row: _maybe(row.get("nature"))),
                ("Related CWE", lambda row: _maybe(row.get("cwe_id"))),
            ),
            rows=[row for row in related if isinstance(row, dict)],
        )
    groupings = [*(weakness.get("categories") or []), *(weakness.get("views") or [])]
    if groupings:
        _records_table(
            console,
            title=f"Categories and views ({len(groupings)})",
            columns=(
                ("Grouping", lambda row: _maybe(row.get("grouping_id"))),
                ("Name", lambda row: _trim(row.get("name"), 60)),
            ),
            rows=[row for row in groupings if isinstance(row, dict)],
        )
    detection = weakness.get("detection_methods") or []
    if detection:
        body = "\n".join(f"  • {_trim(item, 100)}" for item in detection[:10])
        footer = f"\n  … {len(detection) - 10} more" if len(detection) > 10 else ""
        console.print(f"[bold]Detection methods[/bold]\n{body}{footer}")

    _render_revision_history(console, weakness.get("revision_history"))
    _render_linked_techniques(console, techniques)


def render_search_cti(
    console: Console,
    payload: dict[str, Any],
    requested_keyword: str | None = None,
) -> None:
    """Render the polymorphic ``SearchCTIResponse.results`` list.

    Empty ``results`` means no matches. That is NOT the same as "nothing to show": the opt-in
    ``kb_versions`` layer is deployment metadata about which revision answered, so it is rendered
    even when the search itself matched nothing — returning early here would make
    ``--include kb_versions`` silently useless on exactly the query where a KB staleness question
    is most likely to be asked.
    """
    results = payload.get("results") or []
    versions = payload.get("knowledgebase_versions") or []
    if not results:
        label = f'"{requested_keyword}"' if requested_keyword else "this query"
        _print_no_data(console, label)
        _render_kb_versions(console, versions)
        _errors_note(console, payload)
        return
    table = Table(title=f"Crimson Crawler — search results ({len(results)})", show_lines=False)
    table.add_column("Source", style="cyan")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Score")
    table.add_column("Description", overflow="fold")
    for item in results:
        if not isinstance(item, dict):
            continue
        attack_id = (
            item.get("attack_id")
            or item.get("technique_id")
            or item.get("group_id")
            or item.get("capec_id")
            or item.get("cwe_id")
            or ""
        )
        table.add_row(
            _maybe(item.get("_source")),
            _maybe(attack_id),
            _trim(item.get("name"), 40),
            _maybe(item.get("relevance_score")),
            _trim(item.get("description"), 80),
        )
    console.print(table)

    _render_kb_versions(console, versions)
    _errors_note(console, payload)


def _render_kb_versions(console: Console, rows: Any) -> None:
    """Print the installed-vs-available revision of each requested knowledge base.

    Read-only deployment metadata: it answers "is the KB behind this answer current", including the
    CVE-side partial-copy coverage counts where they exist (coverage, NOT a sync guarantee).
    """
    if not isinstance(rows, list) or not rows:
        return
    _records_table(
        console,
        title=f"Knowledge-base versions ({len(rows)})",
        columns=(
            ("KB", lambda row: _maybe(row.get("knowledge_base"))),
            ("Installed", lambda row: _maybe(row.get("installed_latest"))),
            ("Available", lambda row: _maybe(row.get("available_latest"))),
            ("CVE-side copy", lambda row: _maybe(row.get("vulmatch_object_count"))),
        ),
        rows=[row for row in rows if isinstance(row, dict)],
    )


# -- shared building blocks for the search / assess / entity renderers ----------- #

_Cell = Callable[[dict[str, Any]], str]


def _errors_note(console: Console, payload: dict[str, Any]) -> None:
    """Print the shared "Partial failures: N" line when the payload collected errors.

    Every ``/v1`` response carries ``errors[]`` instead of raising on a partial
    upstream failure, so every renderer ends with this line.
    """
    errors = payload.get("errors") or []
    if errors:
        console.print(f"[yellow]Partial failures: {len(errors)}[/yellow]")


def _summary_note(console: Console, payload: dict[str, Any]) -> None:
    """Print the endpoint's AI ``summary`` when the include set asked for one."""
    summary = payload.get("summary")
    if summary:
        console.print(f"[bold]Summary:[/bold] {_trim(summary, 400)}")


def _pct(value: Any) -> str:
    """A 0–1 probability or percentile as ``97.3%``; ``—`` when absent."""
    return f"{float(value) * 100:.1f}%" if isinstance(value, (int, float)) and not isinstance(value, bool) else "—"


def _metasploit(row: dict[str, Any]) -> str:
    mods = [m for m in row.get("metasploit_modules") or [] if isinstance(m, dict)]
    if not mods:
        return "—"
    first = mods[0]
    label = str(first.get("rank_label") or first.get("module_path") or "module")
    return escape(label + (f" +{len(mods) - 1}" if len(mods) > 1 else ""))


def _fixed_in(row: dict[str, Any]) -> str:
    return _trim(row.get("fixed_version") or ", ".join(row.get("fixed_versions") or []) or "—", 24)


def render_vulnerability_detail(console: Console, rows: list[dict[str, Any]], *, title: str, id_key: str) -> None:
    """Report schema 2.2 per-CVE evidence: KEV, Metasploit, EPSS + percentile, CWE, fix — one row per CVE.

    Shared by the artifact (``id_key="value"``) and inventory (``id_key="cve_id"``) renderers. Evidence is
    kept in separate columns (observed exploitation vs weaponised code vs prediction), never one flag."""
    _records_table(
        console,
        title=title,
        columns=(
            ("CVE", lambda row: _maybe(row.get(id_key))),
            ("KEV", lambda row: _yes_no(row.get("kev") or row.get("kev_due_date") or row.get("kev_due"))),
            ("Metasploit", _metasploit),
            ("EPSS", lambda row: _pct(row.get("epss"))),
            ("Percentile", lambda row: _pct(row.get("epss_percentile"))),
            (
                "LEV",
                lambda row: _pct(
                    (row.get("lev") or {}).get("probability") if isinstance(row.get("lev"), dict) else None
                ),
            ),
            ("CWE", lambda row: _joined(row.get("cwe_ids"), 20)),
            ("Fixed in", _fixed_in),
        ),
        rows=rows,
        limit=10,
    )


def _records_table(
    console: Console,
    *,
    title: str,
    columns: Sequence[tuple[str, _Cell]],
    rows: Any,
    limit: int = 20,
) -> None:
    """Print a list of dicts as a Rich table from a ``(header, cell)`` column spec.

    The many-rows sibling of :func:`_render_linked_techniques`: the search,
    assess, and batch payloads differ only in their column set, so the table
    construction, the first-column highlight, the row cap (lifted by ``--expand``
    via :func:`_cap`), and the non-dict row skip live here once. No-ops on an
    empty or absent list so callers can hand it a raw payload field.

    The leading column is the row's identifier, so it is kept unwrapped: an id
    Rich has folded across two lines ("CVE-2024-\\n3400") can't be copied,
    pasted, or grepped. Under ``--expand`` nothing is held back and it folds
    like the rest.
    """
    usable = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    if not usable:
        return
    table = Table(title=title, show_lines=False)
    for index, (header, _) in enumerate(columns):
        leading = index == 0
        table.add_column(
            header,
            style="cyan" if leading else "",
            overflow="fold",
            no_wrap=leading and not output.is_expand_mode(),
        )
    for row in _cap(usable, limit):
        table.add_row(*(cell(row) for _, cell in columns))
    console.print(table)


def _yes_no(value: Any) -> str:
    return "yes" if value else "no"


def _joined(value: Any, limit: int = 40) -> str:
    """Trim-render a list of scalars as a comma-joined cell."""
    return _trim(", ".join(str(item) for item in value), limit) if isinstance(value, list) and value else "—"


# Primary-entity key → its identifier field(s), in the order :func:`_primary_entity`
# probes them. One entry per entity enrichment endpoint: atlas, disarm, f3 and cloak
# all return ``technique`` — F3/CLOAK's ``FrameworkObjectDetail`` names the framework id
# ``object_id`` where the ATLAS/DISARM ``TechniqueDetail`` uses ``technique_id``, so the
# entity's own field decides — capec returns ``attack_pattern``, the rest name the entity
# after the endpoint.
_ENTITY_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("technique", ("technique_id", "object_id")),
    ("campaign", ("campaign_id",)),
    ("attack_pattern", ("capec_id",)),
    ("d3fend", ("d3fend_id",)),
    ("group", ("group_id",)),
    ("location", ("location_id",)),
    ("sector", ("sector_id",)),
    ("software", ("software_id",)),
)

# Optional scalar rows, printed only when the resolved entity carries the field.
# One list spans all eleven entity types; each populates the few that apply to it.
_ENTITY_ROWS: tuple[tuple[str, str], ...] = (
    ("Object type", "object_type"),
    ("Type", "software_type"),
    ("Form", "d3fend_form"),
    ("Abstraction", "abstraction"),
    ("Severity", "severity"),
    ("Likelihood", "likelihood"),
    ("Country", "country"),
    ("Region", "region"),
    ("First seen", "first_seen"),
    ("Last seen", "last_seen"),
)

# Response layers counted in the "Layers" row, in reading order.
_LAYER_FIELDS: tuple[str, ...] = (
    "linked_techniques",
    "related_atlas_techniques",
    # DISARM's technique-to-technique family links (e.g. a technique's parent tactic family). Omitted
    # here, the CLI's "Layers" row and the technique sub-table silently lost the DISARM family
    # entirely, even though the API populates it whenever the entity resolves.
    "related_disarm_techniques",
    "techniques",
    "related_techniques",
    "groups",
    "software",
    "campaigns",
    "cves",
    "mitigations",
    "detections",
    "defend",
    "nist_controls",
    "predictions",
    "misp",
    "knowledgebase",
)


def _entity_id(row: dict[str, Any]) -> str:
    """Best-effort identifier for a heterogeneous entity or search-match row."""
    for _, fields in _ENTITY_FIELDS:
        for field in fields:
            value = row.get(field)
            if value:
                return str(value)
    return "—"


def _primary_entity(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return the payload's resolved entity dict and its id field, or ``(None, "")``."""
    for key, fields in _ENTITY_FIELDS:
        entity = payload.get(key)
        if isinstance(entity, dict):
            return entity, next((field for field in fields if entity.get(field)), fields[0])
    return None, ""


def _technique_rows(payload: dict[str, Any], entity: dict[str, Any]) -> list[Any]:
    """Pick the payload's technique layer, falling back to the entity's own list.

    Group / software / campaign / location / sector responses carry no top-level
    technique layer — the techniques hang off the entity, where the API may
    serialise them as bare id strings. Keep only dict rows so
    :func:`_render_linked_techniques` always gets objects to read.
    """
    for key in (
        "linked_techniques",
        "related_atlas_techniques",
        "related_disarm_techniques",
        "techniques",
        "related_techniques",
    ):
        rows = payload.get(key)
        if isinstance(rows, list) and rows:
            return [row for row in rows if isinstance(row, dict)]
    rows = entity.get("techniques")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def render_entity(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render any of the eleven entity enrichment responses (atlas … software).

    All eleven share one shape: either a resolved primary entity named after
    the endpoint, or — for a ``--search`` call — a ``search_results`` list, plus
    whichever graph layers the preset walked. One renderer covers them because
    the only real variance is which key holds the entity, and
    :func:`_primary_entity` resolves that. Falls through to the match table and
    then to :func:`_print_no_data`, mirroring how the four core renderers handle
    the API's shape-complete-but-empty miss.
    """
    entity, id_field = _primary_entity(payload)
    if entity is None:
        matches = [row for row in (payload.get("search_results") or []) if isinstance(row, dict)]
        if not matches:
            _print_no_data(console, requested or "this lookup")
            return
        columns: list[tuple[str, _Cell]] = [
            ("ID", _entity_id),
            ("Name", lambda row: _trim(row.get("name"), 40)),
        ]
        # Only the detail models that still declare `aliases` (group / software / campaign /
        # location / sector / defend) can fill this column: ATT&CK, ATLAS and DISARM share
        # `TechniqueDetail`, and F3/CLOAK `FrameworkObjectDetail`, all of which dropped the
        # field. Rendering it unconditionally printed a blank column for five of the eleven
        # entity types, so it appears only when a match actually carries one.
        if any(row.get("aliases") for row in matches):
            columns.append(("Aliases", lambda row: _joined(row.get("aliases"))))
        columns.append(("Description", lambda row: _trim(row.get("description"), 70)))
        _records_table(
            console,
            title=f"Crimson Crawler — matches ({len(matches)})",
            columns=columns,
            rows=matches,
        )
        _errors_note(console, payload)
        return

    table = Table(title="Crimson Crawler — enrichment", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("ID", _maybe(entity.get(id_field)))
    table.add_row("Name", _trim(entity.get("name"), 80))
    if entity.get("aliases"):
        table.add_row("Aliases", _joined(entity.get("aliases"), 100))
    if entity.get("tactics"):
        table.add_row("Tactics", _joined(entity.get("tactics"), 80))
    for label, field in _ENTITY_ROWS:
        if entity.get(field):
            table.add_row(label, _maybe(entity[field]))
    layers = []
    for key in _LAYER_FIELDS:
        rows = payload.get(key)
        if isinstance(rows, list) and rows:
            layers.append(f"{key.replace('_', ' ')} {len(rows)}")
    if layers:
        table.add_row("Layers", " · ".join(layers))
    if entity.get("description"):
        table.add_row("Description", _trim(entity["description"], 300))
    if entity.get("url"):
        table.add_row("Reference", _maybe(entity["url"]))
    console.print(table)

    # The entity's own KB revision history (`include=['versions']`). Every entity endpoint can
    # attach one, so it is rendered here for all eleven rather than per-endpoint.
    _render_revision_history(console, entity.get("revision_history"))
    _render_linked_techniques(console, _technique_rows(payload, entity))
    _summary_note(console, payload)
    _errors_note(console, payload)


def render_batch(console: Console, payload: dict[str, Any]) -> None:
    """Render ``EnrichBatchResponse.results`` — one row per submitted item.

    Batch is per-item fault tolerant: a failed item still returns a row, with
    its own ``errors[]``, so the per-row error count is the interesting column.
    """
    results = payload.get("results") or []
    if not results:
        _print_no_data(console, "this batch")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — batch enrichment ({len(results)})",
        columns=(
            ("#", lambda row: _maybe(row.get("index"))),
            ("Type", lambda row: _maybe(row.get("type"))),
            ("Identifier", lambda row: _trim(row.get("identifier"), 40)),
            ("Status", lambda row: _maybe(row.get("status"))),
            ("Errors", lambda row: str(len(row.get("errors") or []))),
        ),
        rows=results,
        limit=50,
    )
    _errors_note(console, payload)


def render_poc_source(console: Console, payload: dict[str, Any]) -> None:
    """Render ``FetchPoCSourceResponse`` — the analyzer's read of an exploit repo."""
    repo_url = payload.get("repo_url") or "this repository"
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    if not summary:
        _print_no_data(console, repo_url, hint="The analyzer returned no exploit summary.")
        _errors_note(console, payload)
        return
    table = Table(title="Crimson Crawler — PoC source", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Repository", _maybe(payload.get("repo_url")))
    table.add_row("Trigger", _trim(summary.get("trigger"), 200))
    table.add_row("Affected path", _trim(summary.get("affected_path"), 120))
    table.add_row("Mitigation", _trim(summary.get("mitigation"), 200))
    preconditions = summary.get("preconditions") or []
    if preconditions:
        table.add_row("Preconditions", _joined(preconditions, 200))
    console.print(table)
    _errors_note(console, payload)


def render_job(console: Console, payload: dict[str, Any]) -> None:
    """Render an async enrichment job status read (artifact or inventory engine).

    Both engines return the same job envelope, so the two ``status`` commands
    share this renderer. The finished ``result`` report is deliberately not
    expanded — that is what ``--json`` / ``--output`` are for.
    """
    table = Table(title="Crimson Crawler — enrichment job", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Enrichment", _maybe(payload.get("enrichment_id")))
    table.add_row("Status", _maybe(payload.get("status")))
    progress = payload.get("progress")
    table.add_row("Progress", f"{progress}%" if progress is not None else "—")
    if payload.get("queue_position") is not None:
        table.add_row("Queue position", _maybe(payload.get("queue_position")))
    table.add_row("Created", _maybe(payload.get("created_at")))
    table.add_row("Updated", _maybe(payload.get("updated_at")))
    error = payload.get("error") if isinstance(payload.get("error"), dict) else None
    if error:
        table.add_row("Error", _trim(f"{error.get('step')}/{error.get('service')}: {error.get('error')}", 200))
    table.add_row("Result", "ready" if payload.get("result") else "pending")
    console.print(table)

    _records_table(
        console,
        title="Stages",
        columns=(
            ("Stage", lambda row: _maybe(row.get("label") or row.get("key"))),
            ("Status", lambda row: _maybe(row.get("status"))),
            ("Progress", lambda row: _maybe(row.get("progress"))),
            ("Detail", lambda row: _trim(row.get("detail"), 60)),
        ),
        rows=payload.get("stages"),
    )


def render_submit(console: Console, payload: dict[str, Any], poll_hint: str | None = None) -> None:
    """Render a ``202`` engine submit acknowledgement (enrichment id + queue status).

    The submit returns immediately; ``poll_hint`` names the command that reads
    the job so the next step is on screen rather than in the docs.
    """
    table = Table(title="Crimson Crawler — enrichment submitted", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Enrichment", _maybe(payload.get("enrichment_id")))
    table.add_row("Status", _maybe(payload.get("status")))
    console.print(table)
    if poll_hint and payload.get("enrichment_id"):
        console.print(f"Poll it with: [bold]{escape(poll_hint)} {_maybe(payload['enrichment_id'])}[/bold]")


# -- search renderers ----------------------------------------------------------- #


def _cve_statistics_parts(statistics: dict[str, Any]) -> list[str]:
    parts = []
    total = statistics.get("cve_total_count")
    if total is not None:
        parts.append(f"[bold]{_maybe(total)}[/bold] CVEs in this deployment")
    latest = statistics.get("latest_cve")
    if latest is not None:
        parts.append(f"latest {_maybe(latest)}")
    modified = statistics.get("cve_modified_since") or {}
    deltas = [f"{key} {_maybe(modified[key])}" for key in ("d1", "d7", "d30") if modified.get(key) is not None]
    if deltas:
        parts.append("modified " + " / ".join(deltas))
    return parts


def render_search_cve(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchCVEResponse`` — matched CVEs, plus the coverage/CNA layers.

    `statistics` and `cnas` are extra layers on the same response, so they are rendered even when the
    CVE match set is empty (a directory/coverage call passes no filters).
    """
    statistics = payload.get("statistics") or {}
    cnas = payload.get("cnas") or []
    results = payload.get("results") or []
    if not results:
        failed = any(
            error.get("step") in {"get_cve", "search_cve_by_cpe", "search_cves_by_cwe", "search_cves_advanced"}
            and error.get("error") != "not_found"
            for error in payload.get("errors") or []
            if isinstance(error, dict)
        )
        console.print(
            "[dim]CVE search failed; matching results are unavailable.[/dim]"
            if failed
            else "[dim]No matching CVEs for this query.[/dim]"
        )
    if statistics:
        parts = _cve_statistics_parts(statistics)
        if parts:
            console.print(" · ".join(parts))
    if cnas:
        # GLOBAL CNA directory (include=['cna']) — every CNA the deployment knows, NOT the CNA that
        # assigned any particular CVE. Use `enrich cve`'s `cve.cna_name` for that per-CVE fact.
        _records_table(
            console,
            title=f"Crimson Crawler — CNA directory ({len(cnas)} of the deployment's CNAs)",
            columns=(
                ("CNA", lambda row: _trim(row.get("name"), 34)),
                ("Contact", lambda row: _trim(row.get("contact_information"), 34)),
                ("Identity", lambda row: _trim(row.get("identity_id"), 40)),
            ),
            rows=cnas,
        )
    if not results:
        _errors_note(console, payload)
        return
    _records_table(
        console,
        title=f"Crimson Crawler — CVE search ({len(results)})",
        columns=(
            ("CVE", lambda row: _maybe(row.get("cve_id"))),
            ("Severity", lambda row: _cvss_severity(row)),
            ("CVSS", lambda row: _cvss_compact(row)),
            ("Weaponization", lambda row: _maybe(row.get("weaponization_score"))),
            ("Exploit", lambda row: _yes_no(row.get("has_public_exploit"))),
            ("CWEs", lambda row: _joined(row.get("cwe_ids"), 24)),
            ("Description", lambda row: _trim(row.get("description"), 60)),
        ),
        rows=results,
    )
    _errors_note(console, payload)


def render_search_csaf(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchCSAFResponse.advisories`` — the seeded CSAF corpus.

    ``total`` is the unpaginated match count, so the title states the page against it; a
    CVE-less advisory renders exactly like any other row (its CVE count is 0).
    """
    advisories = payload.get("advisories") or []
    total = int(payload.get("total") or 0)
    if not advisories:
        _print_no_data(console, requested or "the CSAF corpus")
        return
    table = Table(title=f"CSAF advisories — {len(advisories)} of {total}")
    table.add_column("Tracking id", no_wrap=True)
    table.add_column("Publisher", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("TLP")
    table.add_column("CVEs", justify="right")
    table.add_column("Models", justify="right")
    table.add_column("Remediations", justify="right")
    table.add_column("Current release", no_wrap=True)
    table.add_column("Title")
    for advisory in advisories:
        table.add_row(
            escape(str(advisory.get("tracking_id") or "")),
            escape(str(advisory.get("publisher_name") or "")),
            escape(str(advisory.get("advisory_kind") or "—")),
            escape(str(advisory.get("tlp_label") or "")),
            str(len(advisory.get("cve_ids") or [])),
            str(len(advisory.get("affected_models") or [])),
            str(len(advisory.get("remediations") or [])),
            escape(str(advisory.get("current_release_date") or "")),
            escape(str(advisory.get("title") or "")),
        )
    console.print(table)
    sectors = sorted({sector for advisory in advisories for sector in (advisory.get("sectors") or [])})
    if sectors:
        console.print(f"[dim]Sectors: {escape(', '.join(sectors))}[/dim]")


def render_search_kev(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchKEVResponse.results`` — CISA Known Exploited Vulnerabilities.

    ``statistics`` is an extra layer on the same response, so it renders even when the catalog
    match set is empty (``ccc search kev --include statistics`` with no filters is a coverage call).

    An unlisted CVE still comes back as one row (``in_kev: false``, catalogue fields null), so the
    table's membership column is what carries the negative answer; the row's blanks are a real
    "the catalogue holds nothing for this CVE", not a half-filled entry.
    """
    statistics = payload.get("statistics") or {}
    results = payload.get("results") or []
    if not results:
        failed = any(
            error.get("step") in {"get_kev", "search_kev"} and error.get("error") != "not_found"
            for error in payload.get("errors") or []
            if isinstance(error, dict)
        )
        console.print(
            "[dim]KEV search failed; matching results are unavailable.[/dim]"
            if failed
            else "[dim]No matching KEV entries for this query.[/dim]"
        )
    if statistics:
        by_year = statistics.get("kev_by_year") or []
        counts = [int(row["count"]) for row in by_year] if all(row.get("count") is not None for row in by_year) else []
        delta = statistics.get("kev_created_since") or {}
        parts = [f"[bold]{sum(counts)}[/bold] KEV entries in this deployment"] if counts else []
        deltas = [f"{key} {_maybe(delta[key])}" for key in ("d1", "d7", "d30", "d365") if delta.get(key) is not None]
        if deltas:
            parts.append("added " + " / ".join(deltas))
        if not parts:
            parts = _cve_statistics_parts(statistics)
        if parts:
            console.print(" · ".join(parts))
    if not results:
        _errors_note(console, payload)
        return
    _records_table(
        console,
        title=f"Crimson Crawler — KEV search ({len(results)})",
        columns=(
            ("CVE", lambda row: _maybe(row.get("cve_id"))),
            # Membership leads, because it is the answer: a CVE that is not on the catalog comes
            # back as a row with ``in_kev: false`` and nothing else filled in, and without this
            # column that row is indistinguishable from a catalogue entry with missing metadata.
            ("In KEV", _kev_membership),
            ("Vendor", lambda row: _trim(row.get("vendor_project"), 24)),
            ("Product", lambda row: _trim(row.get("product"), 24)),
            ("Added", lambda row: _maybe(row.get("date_added"))),
            ("Due", lambda row: _maybe(row.get("due_date"))),
            ("Ransomware", lambda row: _yes_no(row.get("ransomware"))),
            ("Vulnerability", lambda row: _trim(row.get("vulnerability_name") or row.get("name"), 50)),
        ),
        rows=results,
    )
    _errors_note(console, payload)


def render_search_d3fend(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchD3FENDResponse.results`` — matching defensive techniques."""
    results = payload.get("results") or []
    if not results:
        _print_no_data(console, requested or "this query")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — D3FEND search ({len(results)})",
        columns=(
            ("ID", lambda row: _maybe(row.get("d3fend_id"))),
            ("Form", lambda row: _maybe(row.get("d3fend_form"))),
            ("Name", lambda row: _trim(row.get("name"), 40)),
            ("Aliases", lambda row: _joined(row.get("aliases"))),
            ("Description", lambda row: _trim(row.get("description"), 70)),
        ),
        rows=results,
    )
    _errors_note(console, payload)


def render_search_knowledgebase(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchKnowledgebaseResponse.results`` — hybrid RAG passage hits."""
    results = payload.get("results") or []
    if not results:
        _print_no_data(console, requested or "this query")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — knowledge base search ({len(results)})",
        columns=(
            ("Collection", lambda row: _maybe(row.get("collection"))),
            ("Score", lambda row: _maybe(row.get("score"))),
            ("Source", lambda row: _trim(row.get("source"), 40)),
            ("Content", lambda row: _trim(row.get("content"), 90)),
        ),
        rows=results,
        limit=10,
    )
    _errors_note(console, payload)


def render_search_misp(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchMISPResponse`` — the attribute hits plus their parent events.

    The only search response with two result lists, so it prints two tables and
    treats "both empty" as the miss signal.
    """
    attributes = payload.get("attributes") or []
    events = payload.get("events") or []
    reports = payload.get("event_reports") or []
    if not attributes and not events and not reports:
        _print_no_data(console, requested or "this query")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — MISP attributes ({len(attributes)})",
        columns=(
            ("Type", lambda row: _maybe(row.get("type"))),
            ("Value", lambda row: _trim(row.get("value"), 40)),
            ("Category", lambda row: _trim(row.get("category"), 24)),
            ("Event", lambda row: _maybe(row.get("event_id"))),
            ("Sightings", lambda row: _maybe(row.get("sighting_count"))),
            ("IDS", lambda row: _yes_no(row.get("to_ids"))),
            ("Tags", lambda row: _joined(row.get("tags"), 40)),
        ),
        rows=attributes,
    )
    _records_table(
        console,
        title=f"MISP events ({len(events)})",
        columns=(
            ("Event", lambda row: _maybe(row.get("id"))),
            ("Date", lambda row: _maybe(row.get("date"))),
            ("Org", lambda row: _trim(row.get("org"), 24)),
            ("Threat", lambda row: _maybe(row.get("threat_level_id"))),
            ("Attrs", lambda row: _maybe(row.get("attribute_count"))),
            ("Info", lambda row: _trim(row.get("info"), 60)),
        ),
        rows=events,
    )
    if payload.get("misp_events_truncated"):
        console.print("Events summarized. Full bodies: --include misp_events_full")
    if reports:
        _records_table(
            console,
            title=f"MISP event reports ({len(reports)})",
            columns=(
                ("Report", lambda row: _maybe(row.get("id"))),
                ("Event", lambda row: _maybe(row.get("event_id"))),
                ("Name", lambda row: _trim(row.get("name"), 40)),
                ("Content", lambda row: _trim(row.get("content"), 70)),
            ),
            rows=reports,
        )
    _errors_note(console, payload)


def render_search_poc(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchPoCResponse.results`` — public exploit repositories for a CVE."""
    results = payload.get("results") or []
    label = payload.get("cve_id") or requested or "this CVE"
    if not results:
        _print_no_data(console, label)
        return
    total = payload.get("total")
    shown = f"{len(results)} of {total}" if total else str(len(results))
    _records_table(
        console,
        title=f"Crimson Crawler — PoC repositories for {label} ({shown})",
        columns=(
            ("Repository", lambda row: _trim(row.get("repo_name"), 40)),
            ("Owner", lambda row: _trim(row.get("owner"), 24)),
            ("Stars", lambda row: _maybe(row.get("stargazers_count"))),
            ("Forks", lambda row: _maybe(row.get("forks_count"))),
            ("Updated", lambda row: _maybe(row.get("updated_at"))),
            ("URL", lambda row: _trim(row.get("repo_url"), 60)),
        ),
        rows=results,
        limit=25,
    )
    _errors_note(console, payload)


def render_search_vendor(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchVendorResponse`` — one vendor's CPE catalog, or the vendor directory."""
    vendors = payload.get("vendors") or []
    if vendors:
        # Directory mode (no VENDOR given): which vendors exist, with catalogue sizes.
        _records_table(
            console,
            title=f"Crimson Crawler — vendor directory ({len(vendors)})",
            columns=(
                ("Vendor", lambda row: _trim(row.get("vendor"), 40)),
                ("Products", lambda row: str(row.get("products_count", ""))),
                ("Softwares", lambda row: str(row.get("softwares_count", ""))),
            ),
            rows=vendors,
        )
        _errors_note(console, payload)
        return
    products = payload.get("products") or []
    label = payload.get("vendor") or requested or "this vendor"
    if not products:
        _print_no_data(console, label)
        return
    total = payload.get("total_products")
    # `products` holds one row per CPE entry, so its length counts ROWS while `total_products` counts
    # DISTINCT products — different units, and the old `len(products) of total_products` rendered a
    # broken-looking ratio ("23 of 4") whenever a product carried several versions. Name each unit.
    rows = len(products)
    row_word = "row" if rows == 1 else "rows"
    shown = f"{total} products · {rows} {row_word}" if total else str(rows)
    _records_table(
        console,
        title=f"Crimson Crawler — {label} products ({shown})",
        columns=(
            ("Product", lambda row: _trim(row.get("product"), 30)),
            ("Version", lambda row: _maybe(row.get("version"))),
            ("CPE", lambda row: _trim(row.get("cpe"), 60)),
            ("Title", lambda row: _trim(row.get("title"), 50)),
        ),
        rows=products,
        limit=50,
    )
    _errors_note(console, payload)


# -- assess renderers ----------------------------------------------------------- #


def render_assess_group_exposure(console: Console, payload: dict[str, Any]) -> None:
    """Render ``AssessGroupExposureResponse`` — the multi-group overlap view."""
    groups = payload.get("groups") or []
    techniques = payload.get("techniques") or []
    if not groups and not techniques:
        _print_no_data(console, "this group set")
        _errors_note(console, payload)
        return
    overlap = payload.get("overlap_analysis") if isinstance(payload.get("overlap_analysis"), dict) else {}
    table = Table(title="Crimson Crawler — group exposure", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Groups", _count_with_top(groups))
    table.add_row("Techniques", str(len(techniques)))
    if overlap:
        table.add_row("Shared techniques", _maybe(overlap.get("shared_count")))
        table.add_row("Combined unique", _maybe(overlap.get("combined_unique")))
        table.add_row("Shared tactics", _joined(overlap.get("shared_tactics"), 80))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))
    table.add_row("Predictions", _count_with_top(payload.get("predictions")))
    table.add_row("D3FEND countermeasures", str(len(payload.get("defend") or [])))
    table.add_row("NIST controls", str(len(payload.get("nist_controls") or [])))
    console.print(table)

    _render_linked_techniques(console, techniques)
    _summary_note(console, payload)
    _errors_note(console, payload)


def render_assess_ioc_portfolio(console: Console, payload: dict[str, Any]) -> None:
    """Render ``AssessIOCPortfolioResponse`` — the batch-IOC threat rollup."""
    attributes = payload.get("misp_attributes") or []
    techniques = payload.get("techniques") or []
    if not attributes and not techniques:
        _print_no_data(console, "these indicators")
        _errors_note(console, payload)
        return
    table = Table(title="Crimson Crawler — IOC portfolio", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Indicators assessed", _maybe(payload.get("indicators_assessed")))
    attr_total = payload.get("misp_attributes_total") or len(attributes)
    attr_cell = (
        f"{len(attributes)} of {attr_total}" if payload.get("misp_attributes_truncated") else str(len(attributes))
    )
    table.add_row("MISP attributes", attr_cell)
    events = payload.get("misp_events") or []
    event_total = payload.get("misp_events_total") or len(events)
    event_cell = f"{len(events)} of {event_total}" if payload.get("misp_events_truncated") else str(len(events))
    table.add_row("MISP events", event_cell)
    table.add_row("Total sightings", _maybe(payload.get("total_sightings")))
    table.add_row("Warninglist hits", str(len(payload.get("warninglist_hits") or [])))
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Groups", _count_with_top(payload.get("groups")))
    table.add_row("Software", _count_with_top(payload.get("software")))
    table.add_row("Campaigns", _count_with_top(payload.get("campaigns")))
    table.add_row("Mitigations", str(len(payload.get("mitigations") or [])))
    table.add_row("Detections", str(len(payload.get("detections") or [])))
    console.print(table)

    _render_linked_techniques(console, techniques)
    _summary_note(console, payload)
    _errors_note(console, payload)


def render_assess_technique_coverage(console: Console, payload: dict[str, Any]) -> None:
    """Render ``AssessTechniqueCoverageResponse`` — defensive coverage + priority gaps."""
    techniques = payload.get("techniques") or []
    coverage = payload.get("coverage_score") if isinstance(payload.get("coverage_score"), dict) else {}
    if not techniques and not coverage:
        _print_no_data(console, "these techniques")
        _errors_note(console, payload)
        return
    table = Table(title="Crimson Crawler — technique coverage", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Techniques", _maybe(coverage.get("total_techniques") or len(techniques)))
    if coverage:
        mitigated = f"{_maybe(coverage.get('mitigated_count'))} ({_maybe(coverage.get('mitigation_pct'))}%)"
        detected = f"{_maybe(coverage.get('detected_count'))} ({_maybe(coverage.get('detection_pct'))}%)"
        table.add_row("Mitigated", mitigated)
        table.add_row("Detected", detected)
        table.add_row("Uncovered", _joined(coverage.get("uncovered_techniques"), 80))
    table.add_row("Mitigations", str(len(payload.get("mitigations") or [])))
    table.add_row("Detections", str(len(payload.get("detections") or [])))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))
    table.add_row("NIST controls", str(len(payload.get("nist_controls") or [])))
    console.print(table)

    _records_table(
        console,
        title="Priority gaps",
        columns=(
            ("Technique", lambda row: _maybe(row.get("technique_id"))),
            ("Name", lambda row: _trim(row.get("name"), 40)),
            ("Gap score", lambda row: _maybe(row.get("gap_score"))),
            ("Top tactic", lambda row: _trim(row.get("top_tactic"), 24)),
            ("KEV", lambda row: _yes_no(row.get("has_kev_cves"))),
            ("Reason", lambda row: _trim(row.get("reason"), 60)),
        ),
        rows=payload.get("priority_gaps"),
        limit=15,
    )
    _summary_note(console, payload)
    _errors_note(console, payload)


def render_assess_vulnerability_exposure(console: Console, payload: dict[str, Any]) -> None:
    """Render ``AssessVulnerabilityExposureResponse`` — the multi-CVE exposure rollup."""
    cves = payload.get("cves") or []
    if not cves:
        _print_no_data(console, "these CVEs")
        _render_osv_advisories(console, payload.get("osv_advisories"))
        _osv_completeness_note(console, payload)
        _errors_note(console, payload)
        return
    table = Table(title="Crimson Crawler — vulnerability exposure", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("CVEs", str(len(cves)))
    table.add_row("KEV entries", str(len(payload.get("kev_entries") or [])))
    table.add_row("Max weaponization", _maybe(payload.get("max_weaponization_score")))
    table.add_row("Avg weaponization", _maybe(payload.get("avg_weaponization_score")))
    table.add_row("Likely tactics", _joined(payload.get("likely_tactics"), 80))
    table.add_row("Techniques", str(len(payload.get("techniques") or [])))
    table.add_row("Exploits", str(len(payload.get("exploits") or [])))
    table.add_row("Chained CVE pairs", str(len(payload.get("chained_cve_pairs") or [])))
    table.add_row("NIST controls", str(len(payload.get("nist_controls") or [])))
    console.print(table)

    _records_table(
        console,
        title="Prioritized remediation",
        columns=(
            ("Rank", lambda row: _maybe(row.get("priority_rank"))),
            ("CVE", lambda row: _maybe(row.get("cve_id"))),
            ("Score", lambda row: _maybe(row.get("adjusted_priority_score"))),
            ("Effort", lambda row: _maybe(row.get("effort"))),
            ("Reason", lambda row: _trim(row.get("reason"), 70)),
        ),
        rows=payload.get("prioritized_remediation"),
        limit=15,
    )
    _render_osv_advisories(console, payload.get("osv_advisories"))
    _osv_completeness_note(console, payload)
    _summary_note(console, payload)
    _errors_note(console, payload)


__all__ = [
    "render_assess_group_exposure",
    "render_assess_ioc_portfolio",
    "render_assess_technique_coverage",
    "render_assess_vulnerability_exposure",
    "render_batch",
    "render_cve",
    "render_cwe",
    "render_entity",
    "render_ioc",
    "render_job",
    "render_package",
    "render_poc_source",
    "render_product",
    "render_search_cti",
    "render_search_cve",
    "render_search_d3fend",
    "render_search_kev",
    "render_search_knowledgebase",
    "render_search_misp",
    "render_search_poc",
    "render_search_vendor",
    "render_submit",
    "render_technique",
    "run_async",
    "with_status",
]
