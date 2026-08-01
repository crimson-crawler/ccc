"""The ``ccc assess`` sub-app — the four ``/v1/assess/*`` portfolio endpoints.

Where ``ccc enrich`` answers "tell me everything about this one thing", assess
answers "given this *set*, what is my exposure": which techniques several groups
share, what a batch of indicators adds up to, how well a technique list is
covered by mitigations and detections, and how a CVE list should be remediated.

Each command calls a convenience method on :class:`CrawlerClient` — command code
goes through the typed SDK wrappers only, never the raw escape hatch or the SDK's
auto-built model package. All four request models carry ``include``, so all four
take a repeatable ``--include LAYER`` passthrough; there is no preset, the server
default applies when the flag is absent. The two list-shaped endpoints validate
their identifiers locally, so a typo exits ``64`` without a round trip.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer

from .. import auth, output
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from . import _formatters

app = typer.Typer(
    name="assess",
    help="Assess a portfolio: group exposure, IOC batches, technique coverage, vulnerability exposure.",
    no_args_is_help=True,
)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_GROUP_PATTERN = re.compile(r"^G\d{4}$", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
# A MISP attribute type token: lowercase, hyphens, and the `filename|md5` pipe.
_TYPE_PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9|_-]*$")

# Hash length → MISP attribute type, for `--ioc` values given without a type.
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

# The API caps both list endpoints at 50 entries; a 51st is a 422.
_MAX_ITEMS = 50

# SSVC stakeholder profile: field → the values the API accepts. Drives both the
# `--stakeholder KEY=VALUE` parse and its error messages.
_STAKEHOLDER_FIELDS: dict[str, tuple[str, ...]] = {
    "method": ("deployer", "cisa_coordinator"),
    "exposure": ("small", "controlled", "open"),
    "mission_prevalence": ("minimal", "support", "essential"),
    "human_impact": ("low", "medium", "high", "very_high"),
    "public_wellbeing_impact": ("minimal", "material", "irreversible"),
}

IncludeOption = Annotated[
    list[str] | None,
    typer.Option(
        "--include",
        help="Response layer to include, repeatable (default: the server's).",
        show_default=False,
    ),
]


class Framework(str, Enum):
    """ATT&CK matrix variants exposed by ``--framework``."""

    enterprise = "enterprise"
    ics = "ics"
    mobile = "mobile"


FrameworkOption = Annotated[
    Framework,
    typer.Option("--framework", help="ATT&CK matrix variant.", case_sensitive=False),
]


def _run_assess(label: str, call: Any, render: Any) -> None:
    """Resolve auth, run ``call`` under the spinner, and render the payload."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await call(client)
            return response.to_dict()

    payload = _formatters.with_status(f"Assessing {label}…", _call())
    output.render(payload, render)


def _validate_ids(values: list[str], pattern: re.Pattern[str], *, label: str) -> list[str]:
    """Upper-case and format-check an identifier list, or exit ``64``.

    Reports every offender at once rather than one per run — a caller pasting a
    list wants the whole list triaged in one go.
    """
    if not values:
        raise BadInputError(f"Pass at least one {label}.")
    if len(values) > _MAX_ITEMS:
        raise BadInputError(f"At most {_MAX_ITEMS} {label}s per request ({len(values)} given).")
    normalized = [value.upper() for value in values]
    malformed = [value for value in normalized if not pattern.match(value)]
    if malformed:
        raise BadInputError(f"Malformed {label}(s): {', '.join(malformed)}")
    return normalized


def _infer_ioc_type(value: str) -> str:
    """Guess the MISP attribute type for a bare ``--ioc`` value.

    Only the unambiguous shapes: URL scheme, dotted quad, IPv6's hex-and-colon
    alphabet, the three hash lengths, then anything dotted as a domain. Anything
    else is rejected so a mistyped indicator can't silently be assessed under
    the wrong type — prefix it with ``TYPE=`` to be explicit.
    """
    if value.startswith(("http://", "https://")):
        return "url"
    if _IPV4_PATTERN.match(value):
        return "ip-dst"
    if ":" in value and set(value) <= set("0123456789abcdefABCDEF:"):
        return "ip-dst"
    if _HEX_PATTERN.match(value) and len(value) in _HASH_TYPES:
        return _HASH_TYPES[len(value)]
    if "." in value:
        return "domain"
    raise BadInputError(f"Cannot infer a type for {value!r} — pass it as TYPE=VALUE (e.g. hostname={value}).")


def _load_indicators(iocs: list[str] | None, indicators_file: Path | None) -> list[dict[str, str]]:
    """Build the ``indicators`` list from ``--ioc`` flags and/or a JSON file.

    ``--ioc`` accepts ``TYPE=VALUE`` or a bare value whose type is inferred from
    its shape. The file form takes a bare JSON array (or the ``{"indicators":
    [...]}`` envelope) of ``{"value", "type"}`` objects, so a mixed portfolio can
    be kept under version control.
    """
    indicators: list[dict[str, str]] = []
    if indicators_file is not None:
        try:
            loaded = json.loads(indicators_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BadInputError(f"{indicators_file} is not valid JSON: {exc}") from exc
        if isinstance(loaded, dict):
            loaded = loaded.get("indicators")
        if not isinstance(loaded, list):
            raise BadInputError(f"{indicators_file} must hold a JSON array of indicators.")
        for entry in loaded:
            if not isinstance(entry, dict) or not entry.get("value"):
                raise BadInputError(f"Each indicator needs a 'value': {entry!r}")
            value = str(entry["value"])
            indicators.append({"value": value, "type": str(entry.get("type") or _infer_ioc_type(value))})
    for raw in iocs or []:
        prefix, separator, value = raw.partition("=")
        # Only a plausible MISP type token counts as a TYPE= prefix, so a URL
        # carrying a query string (`https://host/p?a=b`) still infers as a url.
        if separator and value and _TYPE_PREFIX_PATTERN.match(prefix):
            indicators.append({"value": value, "type": prefix})
        else:
            indicators.append({"value": raw, "type": _infer_ioc_type(raw)})
    if not indicators:
        raise BadInputError("Provide at least one --ioc, or an indicators --file.")
    if len(indicators) > _MAX_ITEMS:
        raise BadInputError(f"At most {_MAX_ITEMS} indicators per request ({len(indicators)} given).")
    return indicators


def _parse_stakeholder(pairs: list[str] | None) -> dict[str, str] | None:
    """Turn ``--stakeholder KEY=VALUE`` flags into the SSVC profile, or ``None``.

    Returns ``None`` when the flag was never passed so the field is omitted from
    the body entirely and the API's own defaults apply. Unknown keys and values
    are rejected locally against :data:`_STAKEHOLDER_FIELDS`, listing the
    accepted set — a server-side ``422`` here would be a wasted round trip.
    """
    if not pairs:
        return None
    profile: dict[str, str] = {}
    for raw in pairs:
        key, _, value = raw.partition("=")
        key, value = key.strip(), value.strip()
        allowed = _STAKEHOLDER_FIELDS.get(key)
        if allowed is None:
            raise BadInputError(f"Unknown stakeholder key {key!r}. One of: {', '.join(_STAKEHOLDER_FIELDS)}.")
        if value not in allowed:
            raise BadInputError(f"Invalid {key}={value!r}. One of: {', '.join(allowed)}.")
        profile[key] = value
    return profile


@app.command("group-exposure", help="Compare adversary groups — shared techniques, tactic overlap, linked CVEs.")
@handle_errors
def group_exposure_command(
    group_ids: Annotated[
        list[str] | None,
        typer.Option("--group-id", help="ATT&CK group id (e.g. G0016), repeatable.", show_default=False),
    ] = None,
    search: Annotated[
        list[str] | None,
        typer.Option("--search", help="Group name or alias (e.g. APT28), repeatable.", show_default=False),
    ] = None,
    framework: FrameworkOption = Framework.enterprise,
    include: IncludeOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Assess one or more groups' combined exposure surface.

    With two or more groups the response also carries ``overlap_analysis`` —
    the shared techniques and tactics that make a single detection cover both.
    """
    if not group_ids and not search:
        raise BadInputError("Pass at least one --group-id or --search.")
    normalized = _validate_ids(group_ids, _GROUP_PATTERN, label="group id") if group_ids else None
    label = ", ".join(normalized or search or [])
    _run_assess(
        label,
        lambda client: client.assess_group_exposure(
            group_ids=normalized,
            search=search,
            framework=framework.value,
            include=include,
        ),
        _formatters.render_assess_group_exposure,
    )


@app.command("ioc-portfolio", help="Assess up to 50 indicators at once — MISP hits, shared techniques, actors.")
@handle_errors
def ioc_portfolio_command(
    iocs: Annotated[
        list[str] | None,
        typer.Option(
            "--ioc",
            help="Indicator as TYPE=VALUE, or a bare value whose type is inferred. Repeatable.",
            show_default=False,
        ),
    ] = None,
    indicators_file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            exists=True,
            dir_okay=False,
            readable=True,
            help='JSON array of {"value","type"} objects.',
            show_default=False,
        ),
    ] = None,
    include: IncludeOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Roll a batch of indicators up into one threat picture.

    The batch sibling of ``ccc enrich ioc``: one request resolves every
    indicator against MISP and folds the hits into a shared technique, actor,
    and campaign view instead of N unrelated lookups.
    """
    indicators = _load_indicators(iocs, indicators_file)
    _run_assess(
        f"{len(indicators)} indicators",
        lambda client: client.assess_ioc_portfolio(indicators, include=include),
        _formatters.render_assess_ioc_portfolio,
    )


@app.command("technique-coverage", help="Score defensive coverage of a technique list — mitigations, detections, gaps.")
@handle_errors
def technique_coverage_command(
    technique_ids: Annotated[
        list[str],
        typer.Argument(help="ATT&CK technique ids (e.g. T1190 T1059.001).", show_default=False),
    ],
    framework: FrameworkOption = Framework.enterprise,
    include: IncludeOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Score how well a technique list is mitigated and detected, and rank the gaps."""
    normalized = _validate_ids(list(technique_ids), _TECHNIQUE_PATTERN, label="technique id")
    _run_assess(
        f"{len(normalized)} techniques ({framework.value})",
        lambda client: client.assess_technique_coverage(
            normalized,
            framework=framework.value,
            include=include,
        ),
        _formatters.render_assess_technique_coverage,
    )


@app.command("vulnerability-exposure", help="Assess a CVE list — weaponization, exploit chains, ranked remediation.")
@handle_errors
def vulnerability_exposure_command(
    cve_ids: Annotated[
        list[str],
        typer.Argument(help="CVE identifiers (e.g. CVE-2024-3400 CVE-2021-44228).", show_default=False),
    ],
    stakeholder: Annotated[
        list[str] | None,
        typer.Option(
            "--stakeholder",
            help="SSVC profile entry as KEY=VALUE, repeatable (method, exposure, mission_prevalence, "
            "human_impact, public_wellbeing_impact).",
            show_default=False,
        ),
    ] = None,
    include: IncludeOption = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Assess a CVE portfolio and rank its remediation.

    ``--stakeholder`` supplies the SSVC decision context; omit it entirely and
    the API's own defaults apply.
    """
    normalized = _validate_ids(list(cve_ids), _CVE_PATTERN, label="CVE id")
    profile = _parse_stakeholder(stakeholder)
    _run_assess(
        f"{len(normalized)} CVEs",
        lambda client: client.assess_vulnerability_exposure(
            normalized,
            stakeholder=profile,
            include=include,
        ),
        _formatters.render_assess_vulnerability_exposure,
    )


__all__ = [
    "app",
    "Framework",
    "group_exposure_command",
    "ioc_portfolio_command",
    "technique_coverage_command",
    "vulnerability_exposure_command",
]
