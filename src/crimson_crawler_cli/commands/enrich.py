"""The ``ccc enrich`` sub-app — all 17 enrichment endpoints.

Six single-target chains (``cve``, ``product``, ``package``, ``ioc``, ``cwe``,
``technique``), nine knowledge-graph entities (``atlas``, ``campaign``,
``capec``, ``defend``, ``disarm``, ``group``, ``location``, ``sector``,
``software``), plus ``batch`` and ``poc-source``.

Each invokes a convenience method on :class:`CrawlerClient` — command code
goes through the typed SDK wrappers only, never the raw escape hatch or the
SDK's auto-built model package. Identifiers whose format is canonical (CVE,
CWE, ATT&CK/DISARM technique, ATLAS, CAPEC, campaign, group, software, and the
``poc-source`` repository URL) are validated against a local regex so
malformed input exits ``64`` without a wasted network round trip; the
slug-shaped id spaces (D3FEND, location, sector) are sent verbatim. The nine
entity commands take a direct id *or* ``--search TEXT``, exactly one. The
product positional argument accepts ``vendor/product`` shorthand; explicit
``--vendor``/``--product``/``--version`` flags override any inference. IOC
values are free-form (no client-side format check) but the ``--type`` flag is
constrained to the MISP-style attribute types the API accepts.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable

import typer

from crimson_crawler_client import presets

from .. import auth, output, paths
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from . import _formatters

app = typer.Typer(
    name="enrich",
    help="Run enrichment chains for CVEs, products, packages, IOCs, and the ATT&CK/CAPEC/D3FEND graph.",
    no_args_is_help=True,
)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
# DISARM numbers its influence-operation techniques in the same ``Tnnnn`` space
# as ATT&CK, so the two share one pattern; only the error label differs.
_DISARM_PATTERN = _TECHNIQUE_PATTERN
_ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$", re.IGNORECASE)
_CAPEC_PATTERN = re.compile(r"^CAPEC-\d+$", re.IGNORECASE)
_CAMPAIGN_PATTERN = re.compile(r"^C\d{4}$", re.IGNORECASE)
_GROUP_PATTERN = re.compile(r"^G\d{4}$", re.IGNORECASE)
_SOFTWARE_PATTERN = re.compile(r"^S\d{4}$", re.IGNORECASE)
_REPO_URL_PATTERN = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/?$", re.IGNORECASE)

# The batch orchestrator's server-side cap: the 51st item is a 422.
_BATCH_MAX_ITEMS = 50


class Framework(str, Enum):
    """ATT&CK matrix variants exposed by ``ccc enrich technique --framework``."""

    enterprise = "enterprise"
    ics = "ics"
    mobile = "mobile"


class IOCType(str, Enum):
    """MISP-style attribute types accepted by ``ccc enrich ioc --type``.

    Mirrors the SDK's documented ``ioc_type`` values; ``ip-dst`` is the
    default to match the API default at ``client.py:enrich_ioc_full``.
    """

    ip_dst = "ip-dst"
    ip_src = "ip-src"
    domain = "domain"
    hostname = "hostname"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    url = "url"


# Shared flags for the nine entity commands. ``--search`` is the alternative to
# a direct id lookup; ``--framework`` only appears on the three whose request
# model carries the field (campaign, group, software) plus ``technique``.
SearchOption = Annotated[
    str | None,
    typer.Option("--search", help="Search by name/description instead of a direct id lookup.", show_default=False),
]
FrameworkOption = Annotated[
    Framework,
    typer.Option("--framework", help="ATT&CK matrix variant.", case_sensitive=False),
]


@app.command("cve", help="Enrich a CVE — CWE, CAPEC, ATT&CK techniques, EPSS, KEV, MISP, knowledge base.")
@handle_errors
def cve_command(
    cve_id: Annotated[
        str,
        typer.Argument(help="CVE identifier (e.g. CVE-2024-3400)", show_default=False),
    ],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Walk the full CVE chain and render the result."""
    if not _CVE_PATTERN.match(cve_id):
        raise BadInputError(f"Malformed CVE id: {cve_id!r} (expected CVE-YYYY-NNNN…)")
    resolved = auth.resolve_auth()
    normalized = cve_id.upper()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            # Layer "poc" onto the default walk so the renderer's "PoC count"
            # row is populated — the API only fills poc_count when "poc" is in
            # the include set (#193). The SDK preset itself stays unchanged.
            response = await client.enrich_cve_full(normalized, include=[*presets.CVE_FULL_WALK, "poc"])
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {normalized}…", _call())
    output.render(payload, partial(_formatters.render_cve, requested_id=normalized))


@app.command("product", help="Enrich a product — matching CVEs, severity, exploit signals, techniques.")
@handle_errors
def product_command(
    target: Annotated[
        str | None,
        typer.Argument(
            help="Product name, or 'vendor/product' shorthand (omit when using --product/--vendor).",
            show_default=False,
        ),
    ] = None,
    vendor: Annotated[str | None, typer.Option("--vendor", help="Override the vendor name.")] = None,
    product: Annotated[str | None, typer.Option("--product", help="Override the product name.")] = None,
    version: Annotated[
        str | None,
        typer.Option(
            "--version",
            help="Filter CVEs to those affecting this version (major-line: '7' matches 7.x; '2.4.51' exact + ranges).",
        ),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Parse ``vendor/product`` or use explicit flags, then call ``enrich_product_full``."""
    inferred_vendor: str | None = None
    inferred_product: str | None = None
    if target:
        if "/" in target:
            inferred_vendor, inferred_product = (part.strip() for part in target.split("/", 1))
        else:
            inferred_product = target.strip()

    final_vendor = vendor or inferred_vendor
    final_product = product or inferred_product
    if not final_product:
        raise BadInputError("Specify a product via positional arg, --product, or 'vendor/product'.")

    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.enrich_product_full(
                final_product,
                version=version,
                vendor=final_vendor,
            )
            return response.to_dict()

    label = f"{final_vendor + '/' if final_vendor else ''}{final_product}"
    if version:
        label = f"{label} @ {version}"
    payload = _formatters.with_status(f"Enriching {label}…", _call())
    output.render(payload, _formatters.render_product)


@app.command("package", help="Enrich an open-source package — OSV advisories + matching CVEs (npm/PyPI/Go/…).")
@handle_errors
def package_command(
    ecosystem: Annotated[
        str,
        typer.Argument(help="Package ecosystem (e.g. npm, PyPI, Go, Maven, crates.io).", show_default=False),
    ],
    package: Annotated[
        str,
        typer.Argument(help="Package name as published in its registry (e.g. lodash, django).", show_default=False),
    ],
    version: Annotated[
        str | None,
        typer.Option("--version", help="Installed version to filter advisories to."),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Enrich an open-source package via ``enrich_package_full`` (OSV.dev) and render it.

    The package-ecosystem sibling of ``ccc enrich product``: OSV.dev supplies the advisories
    and the CVEs they alias are enriched through the same chain. ``ecosystem`` + ``package``
    map straight onto the SDK's two positional args.
    """
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.enrich_package_full(ecosystem, package, version=version)
            return response.to_dict()

    label = f"{ecosystem}/{package}" + (f" @ {version}" if version else "")
    payload = _formatters.with_status(f"Enriching {label}…", _call())
    output.render(payload, _formatters.render_package)


@app.command("ioc", help="Enrich an IOC — MISP attributes, ATT&CK links, knowledge base/web context.")
@handle_errors
def ioc_command(
    value: Annotated[
        str,
        typer.Argument(help="Indicator value (IP, domain, hostname, hash, or URL).", show_default=False),
    ],
    ioc_type: Annotated[
        IOCType,
        typer.Option("--type", help="MISP-style attribute type.", case_sensitive=False),
    ] = IOCType.ip_dst,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Enrich an IOC via ``enrich_ioc_full`` and render the result."""
    resolved = auth.resolve_auth()

    async def _call() -> dict:
        async with build_client(resolved) as client:
            # Layer the includes the renderer needs onto the default walk: the
            # Sightings / On-warninglist / Linked-CVEs rows are only populated
            # when "sightings" / "warninglist" / "cves" are requested (#191/#193).
            response = await client.enrich_ioc_full(
                value,
                ioc_type=ioc_type.value,
                include=[*presets.IOC_FULL_WALK, "warninglist", "sightings", "cves"],
            )
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {value} ({ioc_type.value})…", _call())
    output.render(payload, _formatters.render_ioc)


@app.command("cwe", help="Enrich a CWE — CAPEC attack patterns, ATT&CK techniques, TIE predictions.")
@handle_errors
def cwe_command(
    cwe_id: Annotated[
        str,
        typer.Argument(help="CWE identifier (e.g. CWE-79)", show_default=False),
    ],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Validate the CWE id locally, then walk the CWE chain and render it."""
    if not _CWE_PATTERN.match(cwe_id):
        raise BadInputError(f"Malformed CWE id: {cwe_id!r} (expected CWE-NNN…)")
    resolved = auth.resolve_auth()
    normalized = cwe_id.upper()

    async def _call() -> dict:
        async with build_client(resolved) as client:
            # "cves" drives both the Linked-CVEs row and the Exploitation-class
            # row (exploitation_frequency is computed only when CVEs resolve);
            # the default CWE_FULL_WALK omits it (#191/#193).
            response = await client.enrich_cwe_full(normalized, include=[*presets.CWE_FULL_WALK, "cves"])
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {normalized}…", _call())
    output.render(payload, partial(_formatters.render_cwe, requested_id=normalized))


@app.command("technique", help="Enrich an ATT&CK technique — adversary attribution, linked CVEs, Navigator.")
@handle_errors
def technique_command(
    technique_id: Annotated[
        str,
        typer.Argument(help="ATT&CK technique (e.g. T1190, T1059.001)", show_default=False),
    ],
    framework: Annotated[
        Framework,
        typer.Option("--framework", help="ATT&CK matrix variant.", case_sensitive=False),
    ] = Framework.enterprise,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Validate the technique id locally, then call ``enrich_technique_full`` and render it.

    Returns the technique detail plus tactics, the groups/software/campaigns using it, linked CVEs,
    and Navigator JSON — the closest thing the API exposes to a one-shot "attack path" view.
    """
    if not _TECHNIQUE_PATTERN.match(technique_id):
        raise BadInputError(f"Malformed technique id: {technique_id!r} (expected T1190 or T1059.001)")
    normalized = technique_id.upper()
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            # "cves" drives the Linked-CVEs row; the default TECHNIQUE_FULL preset omits it (#191/#193).
            response = await client.enrich_technique_full(
                [normalized],
                framework=framework.value,
                include=[*presets.TECHNIQUE_FULL, "cves"],
            )
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {normalized} ({framework.value})…", _call())
    output.render(payload, partial(_formatters.render_technique, requested_id=normalized))


# -- entity endpoints (id-or-search) -------------------------------------------- #


def _resolve_target(
    identifier: str | None,
    search: str | None,
    *,
    label: str,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str | None, str]:
    """Validate the id-or-search pair; return ``(normalized_id, spinner_label)``.

    The nine entity endpoints each accept a direct identifier *or* a text
    search. Requiring exactly one keeps the request unambiguous and costs no
    round trip. ``pattern``, when given, is that id space's canonical format —
    those ids are also case-normalized. Slug-shaped id spaces (D3FEND,
    location, sector) pass no pattern and are sent verbatim.
    """
    if identifier and search:
        raise BadInputError(f"Pass either a {label} or --search, not both.")
    if not identifier:
        if not search:
            raise BadInputError(f"Pass a {label} or --search TEXT.")
        return None, f"'{search}'"
    if pattern is None:
        return identifier, identifier
    if not pattern.match(identifier):
        raise BadInputError(f"Malformed {label}: {identifier!r}")
    normalized = identifier.upper()
    return normalized, normalized


def _run_entity_enrich(label: str, call: Callable[[Any], Awaitable[Any]]) -> None:
    """Resolve auth, run ``call`` under the spinner, and render the entity payload.

    The nine entity endpoints differ only in which SDK method they call and
    which flags feed it, so each command body stays one validation step plus
    one lambda. Every response shares the
    "primary entity or ``search_results``, plus walked layers" shape that
    :func:`_formatters.render_entity` reads.
    """
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await call(client)
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {label}…", _call())
    output.render(payload, partial(_formatters.render_entity, requested=label))


@app.command("atlas", help="Enrich an ATLAS AI/ML attack technique — ATT&CK links, groups, case studies.")
@handle_errors
def atlas_command(
    technique_id: Annotated[
        str | None,
        typer.Argument(help="ATLAS technique id (e.g. AML.T0043).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one ATLAS technique, or search the AI/ML matrix by text."""
    normalized, label = _resolve_target(technique_id, search, label="ATLAS technique id", pattern=_ATLAS_PATTERN)
    _run_entity_enrich(label, lambda client: client.enrich_atlas_full(normalized, search=search))


@app.command("campaign", help="Enrich an ATT&CK campaign — techniques, attributed groups, software, CVEs.")
@handle_errors
def campaign_command(
    campaign_id: Annotated[
        str | None,
        typer.Argument(help="ATT&CK campaign id (e.g. C0028).", show_default=False),
    ] = None,
    search: SearchOption = None,
    framework: FrameworkOption = Framework.enterprise,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one ATT&CK campaign, or search campaigns by name/description."""
    normalized, label = _resolve_target(campaign_id, search, label="campaign id", pattern=_CAMPAIGN_PATTERN)
    _run_entity_enrich(
        f"{label} ({framework.value})",
        lambda client: client.enrich_campaign_full(normalized, search=search, framework=framework.value),
    )


@app.command("capec", help="Enrich a CAPEC attack pattern — ATT&CK techniques, linked CWEs, CVEs, adversaries.")
@handle_errors
def capec_command(
    capec_id: Annotated[
        str | None,
        typer.Argument(help="CAPEC identifier (e.g. CAPEC-66).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one CAPEC attack pattern, or search attack patterns by text."""
    normalized, label = _resolve_target(capec_id, search, label="CAPEC id", pattern=_CAPEC_PATTERN)
    _run_entity_enrich(label, lambda client: client.enrich_capec_full(normalized, search=search))


@app.command("defend", help="Enrich a D3FEND defensive technique — the ATT&CK techniques it counters.")
@handle_errors
def defend_command(
    d3fend_id: Annotated[
        str | None,
        typer.Argument(help="D3FEND identifier (e.g. D3-AL).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one D3FEND countermeasure, or search defensive techniques by text."""
    normalized, label = _resolve_target(d3fend_id, search, label="D3FEND id")
    _run_entity_enrich(label, lambda client: client.enrich_defend_full(normalized, search=search))


@app.command("disarm", help="Enrich a DISARM disinformation technique — countermeasures, actors, campaigns.")
@handle_errors
def disarm_command(
    technique_id: Annotated[
        str | None,
        typer.Argument(help="DISARM technique id (e.g. T0001).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one DISARM technique, or search the influence-operations matrix."""
    normalized, label = _resolve_target(technique_id, search, label="DISARM technique id", pattern=_DISARM_PATTERN)
    _run_entity_enrich(label, lambda client: client.enrich_disarm_full(normalized, search=search))


@app.command("group", help="Enrich an ATT&CK group — techniques, software, campaigns, targeted sectors, CVEs.")
@handle_errors
def group_command(
    group_id: Annotated[
        str | None,
        typer.Argument(help="ATT&CK group id (e.g. G0016).", show_default=False),
    ] = None,
    search: SearchOption = None,
    framework: FrameworkOption = Framework.enterprise,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one adversary group, or search groups by name/alias (e.g. 'APT28')."""
    normalized, label = _resolve_target(group_id, search, label="group id", pattern=_GROUP_PATTERN)
    _run_entity_enrich(
        f"{label} ({framework.value})",
        lambda client: client.enrich_group_full(normalized, search=search, framework=framework.value),
    )


@app.command("location", help="Enrich an ATT&CK location — groups and techniques targeting that country/region.")
@handle_errors
def location_command(
    location_id: Annotated[
        str | None,
        typer.Argument(help="ATT&CK location id (e.g. L0001).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one location, or search by country/region name (e.g. 'United States')."""
    normalized, label = _resolve_target(location_id, search, label="location id")
    _run_entity_enrich(label, lambda client: client.enrich_location_full(normalized, search=search))


@app.command("sector", help="Enrich an industry sector — the groups and techniques that target it.")
@handle_errors
def sector_command(
    sector_id: Annotated[
        str | None,
        typer.Argument(help="Sector identifier (e.g. financial-services).", show_default=False),
    ] = None,
    search: SearchOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one sector, or search sectors by name (e.g. 'healthcare')."""
    normalized, label = _resolve_target(sector_id, search, label="sector id")
    _run_entity_enrich(label, lambda client: client.enrich_sector_full(normalized, search=search))


@app.command("software", help="Enrich ATT&CK software — techniques it implements, groups using it, linked CVEs.")
@handle_errors
def software_command(
    software_id: Annotated[
        str | None,
        typer.Argument(help="ATT&CK software id (e.g. S0154).", show_default=False),
    ] = None,
    search: SearchOption = None,
    framework: FrameworkOption = Framework.enterprise,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Look up one malware/tool entry, or search by name/alias (e.g. 'Cobalt Strike')."""
    normalized, label = _resolve_target(software_id, search, label="software id", pattern=_SOFTWARE_PATTERN)
    _run_entity_enrich(
        f"{label} ({framework.value})",
        lambda client: client.enrich_software_full(normalized, search=search, framework=framework.value),
    )


# -- batch + PoC source --------------------------------------------------------- #


def _load_batch_items(items_file: Path | None, inline: list[str] | None) -> list[dict[str, Any]]:
    """Collect batch items from a JSON file and/or repeated ``--item`` flags.

    Accepts either a bare JSON array or the ``{"items": [...]}`` envelope, since
    both read naturally as "the request body". Every item must be a JSON object
    carrying the endpoint's ``type`` discriminator. The 50-item cap is the
    server's (a 51st item is a ``422``); rejecting it here saves the round trip.
    """
    items: list[dict[str, Any]] = []
    if items_file is not None:
        try:
            loaded = json.loads(items_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BadInputError(f"{items_file} is not valid JSON: {exc}") from exc
        if isinstance(loaded, dict):
            loaded = loaded.get("items")
        if not isinstance(loaded, list):
            raise BadInputError(f"{items_file} must hold a JSON array of items, or {{'items': [...]}}.")
        items.extend(loaded)
    for raw in inline or []:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BadInputError(f"--item is not valid JSON: {raw!r} ({exc})") from exc
        items.append(parsed)
    if not items:
        raise BadInputError("Provide a JSON items file and/or at least one --item.")
    non_objects = [index for index, item in enumerate(items) if not isinstance(item, dict)]
    if non_objects:
        raise BadInputError(f"Batch items must be JSON objects; item(s) {non_objects} are not.")
    untyped = [index for index, item in enumerate(items) if not item.get("type")]
    if untyped:
        raise BadInputError(f"Every batch item needs a 'type' discriminator; item(s) {untyped} have none.")
    if len(items) > _BATCH_MAX_ITEMS:
        raise BadInputError(f"Batch accepts at most {_BATCH_MAX_ITEMS} items ({len(items)} given).")
    return items


@app.command("batch", help="Run up to 50 enrich lookups in one request — mixed types, per-item results.")
@handle_errors
def batch_command(
    items_file: Annotated[
        Path | None,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help='JSON file holding an array of items, or {"items": [...]}.',
            show_default=False,
        ),
    ] = None,
    items: Annotated[
        list[str] | None,
        typer.Option(
            "--item",
            help='Inline JSON item, repeatable (e.g. \'{"type":"cve","cve_id":"CVE-2024-3400"}\').',
            show_default=False,
        ),
    ] = None,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the full batch result JSON to a file instead of summarizing."),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Fan a mixed list of enrichment lookups through the batch orchestrator.

    Each item names one of the enrich types plus that type's identifier fields
    and its own ``include`` list, so the batch body — not a CLI preset — owns
    the per-item depth. Items fail independently: a bad item returns a row with
    its own ``errors[]`` rather than failing the request.
    """
    if output_path is not None:
        paths.ensure_writable_output(output_path)  # fail before any billable API work
    body = _load_batch_items(items_file, items)
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.enrich_batch(body)
            return response.to_dict()

    payload = _formatters.with_status(f"Enriching {len(body)} items…", _call())
    if output_path is not None:
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not output.is_json_mode():
            output.get_error_console().print(f"Batch result written to {output_path}")
        return
    output.render(payload, _formatters.render_batch)


@app.command("poc-source", help="Analyze a public exploit repository — trigger, affected path, mitigation.")
@handle_errors
def poc_source_command(
    repo_url: Annotated[
        str,
        typer.Argument(help="GitHub repository URL (e.g. https://github.com/amlweems/xzbot).", show_default=False),
    ],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Fetch and summarize a PoC repository's source via ``enrich_poc_source``.

    The companion to ``ccc search poc``: that finds the repositories, this reads
    one and reports what the exploit actually touches.
    """
    if not _REPO_URL_PATTERN.match(repo_url):
        raise BadInputError(f"Malformed repository URL: {repo_url!r} (expected https://github.com/owner/repo)")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.enrich_poc_source(repo_url)
            return response.to_dict()

    payload = _formatters.with_status(f"Analyzing {repo_url}…", _call())
    output.render(payload, _formatters.render_poc_source)


__all__ = [
    "app",
    "Framework",
    "cve_command",
    "product_command",
    "package_command",
    "ioc_command",
    "cwe_command",
    "technique_command",
    "atlas_command",
    "campaign_command",
    "capec_command",
    "defend_command",
    "disarm_command",
    "group_command",
    "location_command",
    "sector_command",
    "software_command",
    "batch_command",
    "poc_source_command",
]
