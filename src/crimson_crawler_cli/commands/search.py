"""The ``ccc search`` sub-app — the eight ``/v1/search/*`` endpoints plus ``techniques``.

Search is the discovery half of the API: find the identifiers, then feed them to
``ccc enrich``. Every command calls a convenience method on
:class:`CrawlerClient` — command code goes through the typed SDK wrappers only,
never the raw escape hatch or the SDK's auto-built model package.

Two shapes live here. ``cti`` / ``d3fend`` / ``knowledgebase`` / ``poc`` /
``vendor`` / ``techniques`` require their query or identifier, so it is a
required positional. ``cve`` / ``kev`` / ``misp`` are pure filter endpoints where
every field is optional — their positional (free-text query, CVE id, and
attribute value respectively) is optional too, so a bare ``ccc search kev`` lists
the catalog. ``cve`` / ``kev`` / ``misp`` and the query-shaped ``cti`` /
``d3fend`` carry ``include`` on their request models, so each has an
``--include`` passthrough; no search command has a preset (the walk depth,
the corpus-statistics opt-in, and the ``sightings`` opt-in are the caller's to
choose — matching ``search_techniques``).

``ccc search techniques`` and the deprecated top-level ``ccc search-techniques``
alias share one implementation in :mod:`search_techniques`.
"""

from __future__ import annotations

import re
from enum import Enum
from functools import partial
from typing import Annotated, Any

import typer

from .. import auth, output
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from . import _formatters
from .search_techniques import search_techniques_command

app = typer.Typer(
    name="search",
    help="Search CVEs, KEV, the CTI graph, D3FEND, the knowledge base, MISP, PoCs, and vendor catalogs.",
    no_args_is_help=True,
)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

LimitOption = Annotated[int, typer.Option("--limit", min=1, max=100, help="Maximum number of results to return.")]
PageOption = Annotated[int, typer.Option("--page", min=1, help="1-based result page.")]
NoIncludesOption = Annotated[bool, typer.Option("--no-includes", help="Omit all optional result layers.")]


def _search_includes(include: list[str] | None, no_includes: bool) -> list[str] | None:
    if no_includes and include:
        raise BadInputError("--no-includes cannot be combined with --include.")
    return [] if no_includes else include


class CSAFSort(str, Enum):
    """Ordering for ``ccc search csaf --sort``."""

    newest = "newest"
    oldest = "oldest"


class CTISource(str, Enum):
    """Knowledge bases ``ccc search cti --source`` can span."""

    attack = "attack"
    cwe = "cwe"
    capec = "capec"
    atlas = "atlas"
    disarm = "disarm"
    f3 = "f3"
    cloak = "cloak"


class CTIType(str, Enum):
    """STIX object types accepted by ``ccc search cti --type``."""

    attack_pattern = "attack-pattern"
    intrusion_set = "intrusion-set"
    malware = "malware"
    tool = "tool"
    campaign = "campaign"
    weakness = "weakness"
    course_of_action = "course-of-action"


class D3FENDForm(str, Enum):
    """D3FEND node kinds accepted by ``ccc search d3fend --form``."""

    tactic = "tactic"
    mitigation = "mitigation"
    sub_mitigation = "sub-mitigation"
    artifact = "artifact"


class Collection(str, Enum):
    """Knowledge-base collections accepted by ``ccc search knowledgebase --collection``."""

    main = "main"
    large = "large"
    user = "user"
    red_team = "red_team"


class VulnStatus(str, Enum):
    """NVD analysis states accepted by ``ccc search cve --vuln-status``."""

    analyzed = "Analyzed"
    awaiting_analysis = "Awaiting Analysis"
    undergoing_analysis = "Undergoing Analysis"
    deferred = "Deferred"
    modified = "Modified"
    received = "Received"
    rejected = "Rejected"


class CVESort(str, Enum):
    """Result orderings accepted by ``ccc search cve --sort``."""

    created_ascending = "created_ascending"
    created_descending = "created_descending"
    modified_ascending = "modified_ascending"
    modified_descending = "modified_descending"
    epss_score_descending = "epss_score_descending"
    cvss_score_descending = "x_opencti_cvss_base_score_descending"


class RansomwareStatus(str, Enum):
    """KEV ransomware-campaign flag accepted by ``ccc search kev --ransomware-status``."""

    known = "Known"
    unknown = "Unknown"


def _run_search(label: str, call: Any, render: Any) -> None:
    """Resolve auth, run ``call`` under the spinner, and render the payload.

    ``call`` takes the live client and returns the SDK coroutine; ``render`` is
    the matching :mod:`_formatters` renderer, already bound to its label. Keeps
    every command body to its flag validation plus one lambda.
    """
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await call(client)
            return response.to_dict()

    payload = _formatters.with_status(f"Searching {label}…", _call())
    output.render(payload, render)


@app.command("cve", help="Search CVEs by text, CWE/CAPEC/ATT&CK linkage, severity, EPSS, or KEV status.")
@handle_errors
def cve_command(
    query: Annotated[
        str | None,
        typer.Argument(help="Free-text query over CVE descriptions.", show_default=False),
    ] = None,
    cve_id: Annotated[str | None, typer.Option("--cve-id", help="Exact CVE id.", show_default=False)] = None,
    cwe_id: Annotated[
        str | None,
        typer.Option("--cwe-id", help="Only CVEs mapped to this CWE.", show_default=False),
    ] = None,
    attack_id: Annotated[
        str | None,
        typer.Option("--attack-id", help="Only CVEs linked to this ATT&CK technique.", show_default=False),
    ] = None,
    capec_id: Annotated[
        str | None,
        typer.Option("--capec-id", help="Only CVEs linked to this CAPEC pattern.", show_default=False),
    ] = None,
    cpe: Annotated[
        str | None,
        typer.Option("--cpe", help="Only CVEs affecting this CPE URI.", show_default=False),
    ] = None,
    cvss_min: Annotated[
        float | None,
        typer.Option("--cvss-min", min=0.0, max=10.0, help="Minimum CVSS base score.", show_default=False),
    ] = None,
    epss_min: Annotated[
        float | None,
        typer.Option("--epss-min", min=0.0, max=1.0, help="Minimum EPSS exploit probability.", show_default=False),
    ] = None,
    kev_only: Annotated[bool, typer.Option("--kev-only", help="Only CVEs in the CISA KEV catalog.")] = False,
    vuln_status: Annotated[
        VulnStatus | None,
        typer.Option("--vuln-status", help="NVD analysis state.", case_sensitive=False, show_default=False),
    ] = None,
    sort: Annotated[
        CVESort | None,
        typer.Option("--sort", help="Result ordering.", case_sensitive=False, show_default=False),
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Result layers, repeatable; an explicit list replaces the server defaults. "
            "Options: details, statistics (corpus coverage "
            "+ freshness counts), cna (the CNA directory), epss_reports (daily EPSS history per returned "
            "CVE), kb_rankings (top 100 per KB without trends), kb_rankings_full (all rows and trends).",
            show_default=False,
        ),
    ] = None,
    no_includes: NoIncludesOption = False,
    limit: LimitOption = 50,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Filter the CVE corpus. At least one query or filter is required.

    An unfiltered call would page the entire corpus, so require something to
    narrow on rather than sending a request the caller almost certainly did not
    mean. ``--limit``/``--page`` alone do not count as filters.
    """
    include = _search_includes(include, no_includes)
    filters = (query, cve_id, cwe_id, attack_id, capec_id, cpe, cvss_min, epss_min, vuln_status)
    if not kev_only and all(value is None for value in filters):
        raise BadInputError("Pass a query or at least one filter (--cve-id, --cwe-id, --kev-only, …).")

    label = f"'{query}'" if query else "CVEs"
    _run_search(
        label,
        lambda client: client.search_cve(
            query,
            cve_id=cve_id,
            cwe_id=cwe_id,
            attack_id=attack_id,
            capec_id=capec_id,
            cpe=cpe,
            cvss_min=cvss_min,
            epss_min=epss_min,
            kev_only=kev_only,
            vuln_status=vuln_status.value if vuln_status else None,
            sort=sort.value if sort else None,
            include=include,
            limit=limit,
            page=page,
        ),
        partial(_formatters.render_search_cve, requested=label),
    )


@app.command("kev", help="Search the CISA Known Exploited Vulnerabilities catalog.")
@handle_errors
def kev_command(
    cve_id: Annotated[
        str | None,
        typer.Argument(help="CVE id to look up in KEV (omit to list the catalog).", show_default=False),
    ] = None,
    ransomware_status: Annotated[
        RansomwareStatus | None,
        typer.Option(
            "--ransomware-status",
            help="Filter by known use in ransomware campaigns.",
            case_sensitive=False,
            show_default=False,
        ),
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Result layers to use, repeatable; replaces the default ['statistics']. "
            "Only 'statistics' is supported; use --no-includes for none. It reports deployment-wide "
            "corpus coverage (CVE/KEV totals, per-year counts, and creation deltas).",
            show_default=False,
        ),
    ] = None,
    no_includes: NoIncludesOption = False,
    limit: LimitOption = 50,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one CVE's KEV entry, or page the catalog with optional filters."""
    include = _search_includes(include, no_includes)
    if cve_id is not None and not _CVE_PATTERN.match(cve_id):
        raise BadInputError(f"Malformed CVE id: {cve_id!r} (expected CVE-YYYY-NNNN…)")
    normalized = cve_id.upper() if cve_id else None
    label = normalized or "the KEV catalog"
    _run_search(
        label,
        lambda client: client.search_kev(
            cve_id=normalized,
            ransomware_status=ransomware_status.value if ransomware_status else None,
            include=include,
            limit=limit,
            page=page,
        ),
        partial(_formatters.render_search_kev, requested=label),
    )


@app.command("csaf", help="Search the seeded CSAF vendor-advisory corpus, including CVE-less advisories.")
@handle_errors
def csaf_command(
    cve_id: Annotated[
        str | None, typer.Option("--cve", help="Only advisories naming this CVE.", show_default=False)
    ] = None,
    advisory_id: Annotated[
        str | None, typer.Option("--advisory-id", help="Exact CSAF tracking id.", show_default=False)
    ] = None,
    publisher: Annotated[
        str | None, typer.Option("--publisher", help="Publisher name substring.", show_default=False)
    ] = None,
    sector: Annotated[
        str | None, typer.Option("--sector", help="Exact critical-infrastructure sector.", show_default=False)
    ] = None,
    product: Annotated[
        str | None, typer.Option("--product", help="Product-name substring.", show_default=False)
    ] = None,
    cpe: Annotated[str | None, typer.Option("--cpe", help="CPE substring.", show_default=False)] = None,
    tlp: Annotated[str | None, typer.Option("--tlp", help="Exact TLP label.", show_default=False)] = None,
    sort: Annotated[
        CSAFSort, typer.Option("--sort", help="Order by current release date.", case_sensitive=False)
    ] = CSAFSort.newest,
    limit: LimitOption = 20,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Search the CSAF corpus — the door for CVE-less advisories."""
    if cve_id is not None and not _CVE_PATTERN.match(cve_id):
        raise BadInputError(f"Malformed CVE id: {cve_id!r} (expected CVE-YYYY-NNNN…)")
    label = f"CSAF advisories for {publisher}" if publisher else "the CSAF corpus"
    _run_search(
        label,
        lambda client: client.search_csaf(
            cve_id=cve_id.upper() if cve_id else None,
            advisory_id=advisory_id,
            publisher=publisher,
            sector=sector,
            product=product,
            cpe=cpe,
            tlp=tlp,
            sort=sort.value,
            limit=limit,
            page=page,
        ),
        partial(_formatters.render_search_csaf, requested=label),
    )


@app.command("cti", help="Search the CTI knowledge graph — ATT&CK, CWE, CAPEC, ATLAS, DISARM in one query.")
@handle_errors
def cti_command(
    query: Annotated[str, typer.Argument(help="Free-text query (e.g. 'credential dumping').", show_default=False)],
    sources: Annotated[
        list[CTISource] | None,
        typer.Option(
            "--source",
            help="Knowledge base to search, repeatable (default: attack, cwe, capec).",
            case_sensitive=False,
            show_default=False,
        ),
    ] = None,
    types: Annotated[
        list[CTIType] | None,
        typer.Option("--type", help="STIX object type, repeatable.", case_sensitive=False, show_default=False),
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Extra response layer, repeatable. The only accepted value is 'kb_versions' — the "
            "installed vs available revision of each requested knowledge base, so a content gap can be "
            "told apart from a stale KB. Reported even when the search itself matches nothing.",
            show_default=False,
        ),
    ] = None,
    limit: LimitOption = 20,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Search across the CTI knowledge bases, returning a polymorphic result list.

    The broad sibling of ``ccc search techniques``, which is this endpoint
    pre-scoped to ATT&CK attack-patterns.

    ``--include kb_versions`` answers "which KB revision answered me" — it is
    read-only metadata about the deployment, not a result filter.
    """
    if not query.strip():
        raise BadInputError("Search query must not be empty.")
    _run_search(
        f"'{query}'",
        lambda client: client.search_cti(
            query,
            sources=[source.value for source in sources] if sources else None,
            types=[kind.value for kind in types] if types else None,
            include=list(include) if include else None,
            limit=limit,
            page=page,
        ),
        partial(_formatters.render_search_cti, requested_keyword=query),
    )


@app.command("d3fend", help="Search D3FEND defensive techniques, tactics, mitigations, and artifacts.")
@handle_errors
def d3fend_command(
    query: Annotated[str, typer.Argument(help="Free-text query (e.g. 'network traffic').", show_default=False)],
    form: Annotated[
        D3FENDForm | None,
        typer.Option("--form", help="Restrict to one D3FEND node kind.", case_sensitive=False, show_default=False),
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Result layers to use, repeatable; replaces the default ['versions']. "
            "Only 'versions' is supported; use --no-includes for none. It adds revision history.",
            show_default=False,
        ),
    ] = None,
    no_includes: NoIncludesOption = False,
    limit: LimitOption = 20,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Find the countermeasures that answer an offensive technique."""
    include = _search_includes(include, no_includes)
    if not query.strip():
        raise BadInputError("Search query must not be empty.")
    _run_search(
        f"'{query}'",
        lambda client: client.search_d3fend(
            query,
            d3fend_form=form.value if form else None,
            limit=limit,
            page=page,
            include=include,
        ),
        partial(_formatters.render_search_d3fend, requested=f"'{query}'"),
    )


@app.command("knowledgebase", help="Hybrid semantic search over the curated red-team knowledge base.")
@handle_errors
def knowledgebase_command(
    query: Annotated[str, typer.Argument(help="Natural-language question or phrase.", show_default=False)],
    collections: Annotated[
        list[Collection] | None,
        typer.Option(
            "--collection",
            help="Collection to search, repeatable (default: red_team).",
            case_sensitive=False,
            show_default=False,
        ),
    ] = None,
    alpha: Annotated[
        float,
        typer.Option("--alpha", min=0.0, max=1.0, help="Hybrid weighting: 0 = keyword only, 1 = vector only."),
    ] = 0.7,
    limit: LimitOption = 10,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Retrieve grounded passages from the knowledge base."""
    if not query.strip():
        raise BadInputError("Search query must not be empty.")
    _run_search(
        f"'{query}'",
        lambda client: client.search_knowledgebase(
            query,
            collections=[collection.value for collection in collections] if collections else None,
            alpha=alpha,
            limit=limit,
        ),
        partial(_formatters.render_search_knowledgebase, requested=f"'{query}'"),
    )


@app.command("misp", help="Search our curated MISP (public threat feeds) by value, type, tag, event, or date range.")
@handle_errors
def misp_command(
    value: Annotated[
        str | None,
        typer.Argument(help="Attribute value to look up (IP, domain, hash, URL).", show_default=False),
    ] = None,
    type_attribute: Annotated[
        str | None,
        typer.Option("--type", help="MISP attribute type (e.g. ip-dst, domain, sha256).", show_default=False),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="MISP attribute category.", show_default=False),
    ] = None,
    event_id: Annotated[
        str | None,
        typer.Option("--event-id", help="Restrict to one event.", show_default=False),
    ] = None,
    eventinfo: Annotated[
        str | None,
        typer.Option("--eventinfo", help="Match against the event's info/title text.", show_default=False),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", help="MISP tag, repeatable.", show_default=False),
    ] = None,
    date_from: Annotated[
        str | None,
        typer.Option("--date-from", help="Earliest event date (YYYY-MM-DD).", show_default=False),
    ] = None,
    date_to: Annotated[
        str | None,
        typer.Option("--date-to", help="Latest event date (YYYY-MM-DD).", show_default=False),
    ] = None,
    published: Annotated[
        bool | None,
        typer.Option("--published/--no-published", help="Filter on event published state.", show_default=False),
    ] = None,
    to_ids: Annotated[
        bool | None,
        typer.Option("--to-ids/--no-to-ids", help="Filter on the attribute's IDS-actionable flag.", show_default=False),
    ] = None,
    threat_level_id: Annotated[
        str | None,
        typer.Option("--threat-level", help="MISP threat level id (1 = high … 4 = undefined).", show_default=False),
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            help="Result layers, repeatable; replaces the default event_reports, tags and version. "
            "'sightings' makes MISP return the inline Sighting "
            "array, so each attribute's (and each returned event's) sighting count is real rather than 0; "
            "'event_reports' adds the analyst-written reports for the events the search resolved; 'stats' "
            "adds per-event attribute/object/sighting counts; 'tags' the instance's tag vocabulary; "
            "'feeds' the configured feed previews; 'objects' returns full events with resolved object "
            "references; 'misp_events_full' returns full event bodies; 'version' the MISP version.",
            show_default=False,
        ),
    ] = None,
    no_includes: NoIncludesOption = False,
    limit: LimitOption = 50,
    page: PageOption = 1,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Query the MISP feeds. At least one filter is required.

    Every field on this endpoint is optional, so an unfiltered call would page
    the whole feed — require something to narrow on instead.

    ``--include sightings`` fills in each attribute's sighting count; without it
    every attribute comes back with a zero count.
    """
    include = _search_includes(include, no_includes)
    filters = (value, type_attribute, category, event_id, eventinfo, tags, date_from, date_to, threat_level_id)
    if published is None and to_ids is None and all(item is None for item in filters):
        raise BadInputError("Pass a value or at least one filter (--type, --tag, --event-id, --date-from, …).")

    label = value or "MISP"
    _run_search(
        label,
        lambda client: client.search_misp(
            value=value,
            type_attribute=type_attribute,
            category=category,
            event_id=event_id,
            eventinfo=eventinfo,
            tags=tags,
            date_from=date_from,
            date_to=date_to,
            published=published,
            to_ids=to_ids,
            threat_level_id=threat_level_id,
            include=include,
            limit=limit,
            page=page,
        ),
        partial(_formatters.render_search_misp, requested=label),
    )


@app.command("poc", help="Find public proof-of-concept exploit repositories for a CVE.")
@handle_errors
def poc_command(
    cve_id: Annotated[str, typer.Argument(help="CVE identifier (e.g. CVE-2024-3400).", show_default=False)],
    limit: LimitOption = 25,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """List the exploit repositories tracked for one CVE.

    Feed a returned ``repo_url`` to ``ccc enrich poc-source`` to have the
    exploit's trigger and affected path analyzed.
    """
    if not _CVE_PATTERN.match(cve_id):
        raise BadInputError(f"Malformed CVE id: {cve_id!r} (expected CVE-YYYY-NNNN…)")
    normalized = cve_id.upper()
    _run_search(
        f"PoCs for {normalized}",
        lambda client: client.search_poc(normalized, limit=limit),
        partial(_formatters.render_search_poc, requested=normalized),
    )


@app.command(
    "vendor",
    help="List a vendor's products and CPE entries — or browse the vendor directory (omit VENDOR).",
)
@handle_errors
def vendor_command(
    vendor: Annotated[
        str | None,
        typer.Argument(help="Vendor name (e.g. apache). Omit to list the vendor directory.", show_default=False),
    ] = None,
    q: Annotated[
        str | None,
        typer.Option("--q", help="Wildcard filter on vendor name (directory mode only).", show_default=False),
    ] = None,
    limit: LimitOption = 50,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Resolve a vendor's product catalog, or browse which vendors exist at all."""
    if vendor is not None and not vendor.strip():
        raise BadInputError("Vendor name must not be empty.")
    if vendor is None and q is None:
        label = "vendor directory"
    elif vendor is None:
        label = f"vendors matching {q!r}"
    else:
        label = f"{vendor} products"
    _run_search(
        label,
        lambda client: client.search_vendor(vendor, q=q, limit=limit),
        partial(_formatters.render_search_vendor, requested=label),
    )


@app.command("techniques", help="Keyword search across the ATT&CK knowledge base.")
@handle_errors
def techniques_command(
    keyword: Annotated[str, typer.Argument(help="Search term (e.g. 'credential dumping')", show_default=False)],
    limit: LimitOption = 20,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Forward to :func:`search_techniques.search_techniques_command`.

    Shares its implementation with the deprecated top-level ``ccc
    search-techniques`` alias, so both spellings stay behaviourally identical.
    """
    search_techniques_command(keyword, limit=limit)


__all__ = [
    "app",
    "CTISource",
    "CTIType",
    "Collection",
    "CVESort",
    "D3FENDForm",
    "RansomwareStatus",
    "VulnStatus",
    "cve_command",
    "kev_command",
    "cti_command",
    "d3fend_command",
    "knowledgebase_command",
    "misp_command",
    "poc_command",
    "vendor_command",
    "techniques_command",
]
