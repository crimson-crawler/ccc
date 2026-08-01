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
    names = [it.get("name") for it in items if isinstance(it, dict) and it.get("name")]
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
    """Render the response from ``enrich_cve_full`` as a Rich table.

    When the API returns ``cve: null`` (its graceful-degradation
    signal for unresolved CVE ids) the empty-cell layout would read
    as "exists with no detail" — short-circuit to ``_print_no_data``
    instead.
    """
    cve = payload.get("cve")
    if cve is None:
        _print_no_data(console, requested_id or "this CVE")
        return

    cve_id = cve.get("cve_id") or "unknown"

    table = Table(title=f"Crimson Crawler — {escape(str(cve_id))}", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("CVE", _maybe(cve.get("cve_id")))
    table.add_row("Description", _trim(cve.get("description"), 200))
    table.add_row("CVSS", f"{_maybe(cve.get('cvss_score'))} ({_maybe(cve.get('cvss_severity'))})")
    table.add_row("Weaponization score", _maybe(payload.get("weaponization_score")))
    table.add_row("Published", _maybe(cve.get("published")))
    table.add_row("Has public exploit", _maybe(cve.get("has_public_exploit")))
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

    weaknesses = payload.get("weaknesses") or []
    table.add_row("CWE count", str(len(weaknesses)))
    techniques = payload.get("techniques") or []
    table.add_row("Techniques", str(len(techniques)))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

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
    table.add_row("CPE matches", str(len(payload.get("cpe_matches") or [])))
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
                _maybe(cve.get("cve_id")),
                _maybe(cve.get("cvss_score")),
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
    """
    cves = payload.get("cves") or []
    advisories = payload.get("advisories") or []
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
    table.add_row("Advisories", str(payload.get("vulnerability_count") or len(advisories)))
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
                _maybe(cve.get("cvss_score")),
                _maybe(_epss_value(epss)),
                "yes" if _is_in_kev(kev) else "no",
                _trim(cve.get("description"), 70),
            )
        console.print(cve_table)

    # OSV's ecosystem advisories (GHSA / PYSEC / RUSTSEC / GO — including the non-CVE findings the
    # CPE-keyed product endpoint can't reach). CVE-aliased ones are already enriched into Top CVEs.
    if advisories:
        adv_table = Table(title="OSV advisories", show_lines=False)
        adv_table.add_column("ID", style="cyan")
        adv_table.add_column("Aliases")
        adv_table.add_column("Fixed")
        adv_table.add_column("Summary", overflow="fold")
        for adv in _cap(advisories, 10):
            if not isinstance(adv, dict):
                continue
            aliases = adv.get("cve_ids") or adv.get("aliases") or []
            fixed = adv.get("fixed_versions") or []
            adv_table.add_row(
                _maybe(adv.get("id")),
                _trim(", ".join(str(a) for a in aliases) if aliases else None, 28),
                _trim(", ".join(str(f) for f in fixed) if fixed else None, 20),
                _trim(adv.get("summary") or adv.get("details"), 60),
            )
        console.print(adv_table)


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
    if not techniques:
        _print_no_data(console, requested_id or "this technique")
        return
    title = f"Crimson Crawler — {techniques[0].get('technique_id', 'technique')}"
    table = Table(title=title, title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Predictions", str(len(payload.get("predictions") or [])))
    table.add_row("Groups", _count_with_top(payload.get("groups")))
    table.add_row("Software", _count_with_top(payload.get("software")))
    table.add_row("Campaigns", _count_with_top(payload.get("campaigns")))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))
    table.add_row("Threat level", _maybe(payload.get("threat_level")))
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
        detail_table.add_row("Description", _trim(detail.get("description"), 240))
        console.print(detail_table)


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
    if not misp_attributes and not misp_feed_hits and not techniques:
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
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    _render_linked_techniques(console, techniques)


def render_cwe(console: Console, payload: dict[str, Any], requested_id: str | None = None) -> None:
    """Render the response from ``enrich_cwe_full`` as a Rich table.

    When the API returns ``weakness: null`` (its graceful-degradation
    signal for an unresolved CWE id) the empty-cell layout would read as
    "exists with no detail" — short-circuit to ``_print_no_data`` instead.
    """
    weakness = payload.get("weakness")
    if weakness is None:
        _print_no_data(console, requested_id or "this CWE")
        return

    cwe_id = weakness.get("cwe_id") or "unknown"
    table = Table(title=f"Crimson Crawler — {escape(str(cwe_id))}", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value", overflow="fold")
    table.add_row("CWE", _maybe(weakness.get("cwe_id")))
    table.add_row("Name", _trim(weakness.get("name"), 80))
    table.add_row("Description", _trim(weakness.get("description"), 200))
    table.add_row("Abstraction", _maybe(weakness.get("abstraction")))
    table.add_row("Status", _maybe(weakness.get("status")))

    capecs = payload.get("attack_patterns") or []
    table.add_row("CAPEC patterns", str(len(capecs)))
    techniques = payload.get("techniques") or []
    table.add_row("Techniques", str(len(techniques)))
    table.add_row("Linked CVEs", str(len(payload.get("cves") or [])))

    freq = payload.get("exploitation_frequency")
    if isinstance(freq, dict) and freq.get("exploitation_class"):
        table.add_row("Exploitation class", _maybe(freq.get("exploitation_class")))

    errors = payload.get("errors") or []
    if errors:
        table.add_row("Errors", str(len(errors)))
    console.print(table)

    _render_linked_techniques(console, techniques)


def render_search_cti(
    console: Console,
    payload: dict[str, Any],
    requested_keyword: str | None = None,
) -> None:
    """Render the polymorphic ``SearchCTIResponse.results`` list.

    Empty ``results`` means no matches — short-circuit so we don't
    render a five-column table header with no rows.
    """
    results = payload.get("results") or []
    if not results:
        label = f'"{requested_keyword}"' if requested_keyword else "this query"
        _print_no_data(console, label)
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

    _errors_note(console, payload)


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


# Primary-entity key → its identifier field, in the order :func:`_primary_entity`
# probes them. One entry per entity enrichment endpoint: atlas and disarm both
# return ``technique``, capec returns ``attack_pattern``, the rest name the entity
# after the endpoint.
_ENTITY_FIELDS: tuple[tuple[str, str], ...] = (
    ("technique", "technique_id"),
    ("campaign", "campaign_id"),
    ("attack_pattern", "capec_id"),
    ("d3fend", "d3fend_id"),
    ("group", "group_id"),
    ("location", "location_id"),
    ("sector", "sector_id"),
    ("software", "software_id"),
)

# Optional scalar rows, printed only when the resolved entity carries the field.
# One list spans all nine entity types; each populates the few that apply to it.
_ENTITY_ROWS: tuple[tuple[str, str], ...] = (
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
    "techniques",
    "related_techniques",
    "countermeasures",
    "groups",
    "software",
    "campaigns",
    "cves",
    "sectors",
    "locations",
    "mitigations",
    "detections",
    "defend",
    "nist_controls",
    "predictions",
    "misp",
    "knowledgebase",
    "web",
)


def _entity_id(row: dict[str, Any]) -> str:
    """Best-effort identifier for a heterogeneous entity or search-match row."""
    for _, field in _ENTITY_FIELDS:
        value = row.get(field)
        if value:
            return str(value)
    return "—"


def _primary_entity(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return the payload's resolved entity dict and its id field, or ``(None, "")``."""
    for key, field in _ENTITY_FIELDS:
        entity = payload.get(key)
        if isinstance(entity, dict):
            return entity, field
    return None, ""


def _technique_rows(payload: dict[str, Any], entity: dict[str, Any]) -> list[Any]:
    """Pick the payload's technique layer, falling back to the entity's own list.

    Group / software / campaign / location / sector responses carry no top-level
    technique layer — the techniques hang off the entity, where the API may
    serialise them as bare id strings. Keep only dict rows so
    :func:`_render_linked_techniques` always gets objects to read.
    """
    for key in ("linked_techniques", "techniques", "related_techniques"):
        rows = payload.get(key)
        if isinstance(rows, list) and rows:
            return [row for row in rows if isinstance(row, dict)]
    rows = entity.get("techniques")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def render_entity(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render any of the nine entity enrichment responses (atlas … software).

    All nine share one shape: either a resolved primary entity named after the
    endpoint, or — for a ``--search`` call — a ``search_results`` list, plus
    whichever graph layers the preset walked. One renderer covers them because
    the only real variance is which key holds the entity, and
    :func:`_primary_entity` resolves that. Falls through to the match table and
    then to :func:`_print_no_data`, mirroring how the four core renderers handle
    the API's shape-complete-but-empty miss.
    """
    entity, id_field = _primary_entity(payload)
    if entity is None:
        matches = payload.get("search_results") or []
        if not matches:
            _print_no_data(console, requested or "this lookup")
            return
        _records_table(
            console,
            title=f"Crimson Crawler — matches ({len(matches)})",
            columns=(
                ("ID", _entity_id),
                ("Name", lambda row: _trim(row.get("name"), 40)),
                ("Aliases", lambda row: _joined(row.get("aliases"))),
                ("Description", lambda row: _trim(row.get("description"), 70)),
            ),
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


def render_search_cve(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchCVEResponse.results`` — one row per matched CVE."""
    results = payload.get("results") or []
    if not results:
        _print_no_data(console, requested or "this query")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — CVE search ({len(results)})",
        columns=(
            ("CVE", lambda row: _maybe(row.get("cve_id"))),
            ("Severity", lambda row: _maybe(row.get("cvss_severity"))),
            ("CVSS", lambda row: _maybe(row.get("cvss_score"))),
            ("Weaponization", lambda row: _maybe(row.get("weaponization_score"))),
            ("Exploit", lambda row: _yes_no(row.get("has_public_exploit"))),
            ("CWEs", lambda row: _joined(row.get("cwe_ids"), 24)),
            ("Description", lambda row: _trim(row.get("description"), 60)),
        ),
        rows=results,
    )
    _errors_note(console, payload)


def render_search_kev(console: Console, payload: dict[str, Any], requested: str | None = None) -> None:
    """Render ``SearchKEVResponse.results`` — CISA Known Exploited Vulnerabilities."""
    results = payload.get("results") or []
    if not results:
        _print_no_data(console, requested or "the KEV catalog")
        return
    _records_table(
        console,
        title=f"Crimson Crawler — KEV search ({len(results)})",
        columns=(
            ("CVE", lambda row: _maybe(row.get("cve_id"))),
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
            ("Counters", lambda row: str(len(row.get("linked_techniques") or []))),
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
    if not attributes and not events:
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
    """Render ``SearchVendorResponse.products`` — the CPE catalog for one vendor."""
    products = payload.get("products") or []
    label = payload.get("vendor") or requested or "this vendor"
    if not products:
        _print_no_data(console, label)
        return
    total = payload.get("total_products")
    shown = f"{len(products)} of {total}" if total else str(len(products))
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
    table.add_row("MISP attributes", str(len(attributes)))
    table.add_row("MISP events", str(len(payload.get("misp_events") or [])))
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
