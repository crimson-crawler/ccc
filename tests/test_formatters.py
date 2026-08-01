"""Unit tests for the Rich-table renderers and async helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from rich.console import Console

from crimson_crawler_cli import output
from crimson_crawler_cli.commands import _formatters

# Output-mode singletons are reset around every test by the autouse
# ``_reset_output_modes`` fixture in conftest.py.


def _capture(renderer, payload: dict, width: int = 200) -> str:
    console = Console(record=True, width=width, color_system=None)
    renderer(console, payload)
    return console.export_text()


def test_render_cve_escapes_untrusted_rich_markup() -> None:
    description = "[red]owned[/red] [link=https://evil.example]click[/link] citation [1]"
    text = _capture(
        _formatters.render_cve,
        {"cve": {"cve_id": "CVE-2000-0001", "description": description}},
    )
    assert description in text


def test_render_cve_includes_score_and_techniques() -> None:
    """Populated CVE renders severity + weaponization + KEV details + EPSS trend."""
    payload = {
        "cve": {
            "cve_id": "CVE-2024-3400",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "description": "PAN-OS bypass",
            "has_public_exploit": True,
            "poc_count": 3,
            "published": "2024-04-12",
        },
        "epss": {"epss": 0.94, "percentile": 0.99},
        "epss_velocity": {"trend": "rising", "change_30d": 0.12},
        "kev": {"in_kev": True, "due_date": "2024-05-01", "ransomware": True},
        "weaponization_score": 87.5,
        "weaknesses": [{"cwe_id": "CWE-77"}],
        "techniques": [
            {"technique_id": "T1059", "name": "Command", "tactics": ["execution"]},
        ],
        "errors": [{"source": "misp"}],
    }
    text = _capture(_formatters.render_cve, payload)
    assert "CVE-2024-3400" in text
    assert "9.8" in text
    assert "CRITICAL" in text
    assert "87.5" in text  # weaponization score row
    assert "0.94" in text and "rising" in text  # EPSS score + velocity inline
    assert "due 2024-05-01" in text and "ransomware" in text  # KEV details
    assert "T1059" in text
    assert "Errors" in text


def test_render_cve_poc_count_from_top_level_list() -> None:
    """PoC count comes from the top-level ``poc`` list, not ``cve.poc_count`` (#193).

    The enrich/cve endpoint populates the ``poc`` list when ``poc`` is in the
    include set but leaves ``cve.poc_count`` at its default 0, so the renderer
    must count the list.
    """
    payload = {
        "cve": {"cve_id": "CVE-2025-24813", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "poc_count": 0},
        "poc": [{"html_url": "https://github.com/a/b"}, {"html_url": "https://github.com/c/d"}],
    }
    text = _capture(_formatters.render_cve, payload)
    poc_row = next(line for line in text.splitlines() if "PoC count" in line)
    assert "2" in poc_row  # 2 from the list, not 0 from cve.poc_count


def test_render_cve_poc_count_falls_back_to_scalar() -> None:
    """With no top-level ``poc`` list, fall back to ``cve.poc_count``."""
    payload = {"cve": {"cve_id": "CVE-X", "cvss_score": 7.0, "cvss_severity": "HIGH", "poc_count": 5}}
    text = _capture(_formatters.render_cve, payload)
    poc_row = next(line for line in text.splitlines() if "PoC count" in line)
    assert "5" in poc_row


def test_render_cve_handles_legacy_score_epss_key() -> None:
    """Fall back to ``epss.score`` when ``epss.epss`` isn't present (older SDKs)."""
    payload = {
        "cve": {"cve_id": "CVE-X", "cvss_score": 7.0, "cvss_severity": "HIGH"},
        "epss": {"score": 0.5, "percentile": 0.8},
    }
    text = _capture(_formatters.render_cve, payload)
    assert "0.5" in text


def test_format_kev_unlisted_returns_no() -> None:
    """``None`` and dicts with ``in_kev: False`` both render as "no"."""
    assert _formatters._format_kev(None) == "no"
    assert _formatters._format_kev({"in_kev": False, "due_date": "2024-01-01"}) == "no"


def test_format_kev_listed_surfaces_due_date_and_ransomware() -> None:
    """When KEV is active, surface both metadata fields independently."""
    assert _formatters._format_kev({"in_kev": True}) == "yes"
    assert _formatters._format_kev({"in_kev": True, "due_date": "2024-05-01"}) == "yes — due 2024-05-01"
    assert _formatters._format_kev({"in_kev": True, "ransomware": True}) == "yes — ransomware"
    assert (
        _formatters._format_kev({"in_kev": True, "due_date": "2024-05-01", "ransomware": True})
        == "yes — due 2024-05-01, ransomware"
    )


def test_format_epss_score_with_velocity_inline() -> None:
    """Accepts both ``epss.epss`` (canonical) and ``epss.score`` (legacy) keys.

    Velocity dict also accepts ``change_30d`` or ``delta_30d`` (alias).
    """
    assert (
        _formatters._format_epss_score({"epss": 0.94}, {"trend": "rising", "change_30d": 0.12})
        == "0.94 (rising +0.12 30d)"
    )
    assert (
        _formatters._format_epss_score({"score": 0.5}, {"trend": "stable", "delta_30d": -0.01})
        == "0.5 (stable -0.01 30d)"
    )
    assert _formatters._format_epss_score({"epss": 0.5}, {"trend": "rising"}) == "0.5 (rising)"
    assert _formatters._format_epss_score({"epss": 0.5}, None) == "0.5"
    assert _formatters._format_epss_score({}, None) == "—"
    assert _formatters._format_epss_score(None, None) == "—"


def test_count_with_top_composes_count_and_names() -> None:
    """Joins up to N names with ellipsis when truncated; bare count otherwise."""
    items = [{"name": f"G{i}"} for i in range(8)]
    assert _formatters._count_with_top(items, limit=5) == "8 — G0, G1, G2, G3, G4, …"
    assert _formatters._count_with_top([{"name": "A"}, {"name": "B"}]) == "2 — A, B"
    # No usable names → bare count.
    assert _formatters._count_with_top([]) == "0"
    assert _formatters._count_with_top([{"id": "x"}]) == "1"
    assert _formatters._count_with_top(None) == "0"


def test_count_with_top_lists_all_names_under_expand() -> None:
    """--expand lifts the name cap and drops the trailing ellipsis."""
    items = [{"name": f"G{i}"} for i in range(8)]
    output.set_expand_mode(True)
    assert _formatters._count_with_top(items, limit=5) == "8 — G0, G1, G2, G3, G4, G5, G6, G7"


def test_render_cve_handles_missing_fields() -> None:
    """Empty payload (``cve: null``) emits the not-found line, no table."""
    text = _capture(_formatters.render_cve, {})
    assert "No data found" in text
    assert "Crimson Crawler" not in text


def test_render_cve_not_found_echoes_requested_id() -> None:
    """The ``requested_id`` value is echoed verbatim into the not-found message.

    Uses a deliberately synthetic id (`CVE-9999-99999`) so the test stays
    decoupled from whatever CVEs happen to be in the live seed — the
    assertion is about parameter passthrough, not about any specific CVE.
    """
    console = Console(record=True, width=200, color_system=None)
    sentinel = "CVE-9999-99999"
    _formatters.render_cve(console, {"cve": None}, requested_id=sentinel)
    text = console.export_text()
    assert f"No data found for {sentinel}" in text


def test_render_product_lists_top_cves() -> None:
    """Top CVEs sub-table renders real EPSS values and uses the in_kev signal.

    Mixes the canonical ``epss.epss`` key, the legacy ``epss.score``
    fallback, a real KEV listing (``in_kev: True``), and the truthy-dict
    trap (``in_kev: False`` populated dict) to lock in the fix.
    """
    payload = {
        "product": "nginx",
        "vendor": "nginx",
        "version": "1.25",
        "highest_weaponization_score": 0.81,
        "cpe_matches": [{"cpe": "cpe:2.3:a:nginx"}],
        "cves": [
            {
                "cve": {"cve_id": "CVE-2023-44487", "cvss_score": 7.5, "description": "rapid reset"},
                "epss": {"epss": 0.42},  # canonical key
                "kev": {"in_kev": True, "vendor_inventory": "nginx"},
            },
            {
                "cve": {"cve_id": "CVE-2024-00001", "cvss_score": 5.0, "description": "legacy shape"},
                "epss": {"score": 0.07},  # legacy SDK key still works
                "kev": {"in_kev": False, "vendor_inventory": "nginx"},  # truthy-dict trap
            },
        ],
        "errors": [],
    }
    text = _capture(_formatters.render_product, payload)
    assert "CVE-2023-44487" in text
    assert "0.42" in text  # canonical EPSS
    assert "0.07" in text  # legacy EPSS still flows through
    # Both KEV cells should be visible; truthy-dict CVE must say "no"
    # (assert structurally — the second CVE row is the truthy-dict case)
    lines = text.splitlines()
    in_kev_false_row = next(line for line in lines if "CVE-2024-00001" in line)
    assert " no " in in_kev_false_row
    in_kev_true_row = next(line for line in lines if "CVE-2023-44487" in line)
    assert " yes " in in_kev_true_row


def test_is_in_kev_handles_truthy_dict_trap() -> None:
    """Pre-existing truthy-dict bug: ``{"in_kev": False, ...}`` must report False."""
    assert _formatters._is_in_kev(None) is False
    assert _formatters._is_in_kev({}) is False
    assert _formatters._is_in_kev({"in_kev": False, "vendor_inventory": "x"}) is False
    assert _formatters._is_in_kev({"in_kev": True}) is True


def test_epss_value_accepts_both_keys() -> None:
    """Both canonical ``epss.epss`` and legacy ``epss.score`` are accepted."""
    assert _formatters._epss_value({"epss": 0.5}) == 0.5
    assert _formatters._epss_value({"score": 0.3}) == 0.3
    # canonical wins when both are present
    assert _formatters._epss_value({"epss": 0.5, "score": 0.3}) == 0.5
    assert _formatters._epss_value({}) is None
    assert _formatters._epss_value(None) is None


def test_render_product_handles_no_cves() -> None:
    """Empty cpe_matches + empty cves → not-found line with version hint."""
    text = _capture(
        _formatters.render_product,
        {"product": "openssl", "vendor": "openssl", "version": "999.999"},
    )
    assert "No data found for openssl/openssl@999.999" in text
    assert "version field isn't validated" in text
    assert "Crimson Crawler — product" not in text


def test_render_product_falls_back_to_product_only_label() -> None:
    """No vendor + no version → label is just the product name."""
    text = _capture(_formatters.render_product, {"product": "openssl"})
    assert "No data found for openssl" in text


def test_render_product_lists_vendor_product_pairs() -> None:
    """No explicit vendor → "Matched CPEs" row lists distinct vendor/product pairs.

    Mirrors the live nginx case where the upstream's loose product-name
    substring search spans multiple ``(vendor, product)`` namespaces.
    Listing the pairs (``f5/nginx``, ``kubernetes/ingress-nginx``, …)
    makes the narrowing target obvious: the user sees that
    ``--vendor kubernetes`` alone won't work because the kubernetes
    product is literally ``ingress-nginx``.
    """
    payload = {
        "product": "nginx",
        "vendor": None,
        "cpe_matches": [
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "kubernetes", "product": "ingress-nginx"},
            {"vendor": "nginx", "product": "nginx_ingress_controller"},
        ],
        "cves": [{"cve": {"cve_id": "CVE-2024-0000"}}],
    }
    text = _capture(_formatters.render_product, payload)
    assert "Matched CPEs" in text
    assert "f5/nginx" in text
    assert "kubernetes/ingress-nginx" in text
    assert "nginx/nginx_ingress_controller" in text
    assert "Matched 3 vendor/product pairs across 4 CPE entries" in text


def test_resolve_vendor_prefers_explicit_over_derived() -> None:
    """Explicit vendor wins — vendor inference only fires when the root field is null."""
    payload = {
        "vendor": "nginx",
        "cpe_matches": [{"vendor": "f5", "product": "nginx"}],
    }
    assert _formatters._resolve_vendor(payload) == ("Vendor", "nginx", None)


def test_resolve_vendor_returns_dash_when_no_vendors_anywhere() -> None:
    """Empty cpe_matches (or matches without vendor field) → dash + no note."""
    assert _formatters._resolve_vendor({"cpe_matches": []}) == ("Vendor", "—", None)
    assert _formatters._resolve_vendor({"cpe_matches": [{"cpe": "x"}]}) == ("Vendor", "—", None)


def test_resolve_vendor_single_pair_keeps_singular_label() -> None:
    """All CPE matches share one vendor/product pair → "Vendor: v/p", no footer note."""
    payload = {
        "cpe_matches": [
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "f5", "product": "nginx"},
        ]
    }
    assert _formatters._resolve_vendor(payload) == ("Vendor", "f5/nginx", None)


def test_resolve_vendor_single_pair_without_product_shows_vendor_only() -> None:
    """Single vendor with no product field → just the vendor name (no trailing slash)."""
    payload = {"cpe_matches": [{"vendor": "f5"}, {"vendor": "f5"}]}
    assert _formatters._resolve_vendor(payload) == ("Vendor", "f5", None)


def test_resolve_vendor_multi_pair_lists_top_three() -> None:
    """Multiple distinct pairs → "Matched CPEs" label, top 3 in cell, count in note."""
    payload = {
        "cpe_matches": [
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "kubernetes", "product": "ingress-nginx"},
            {"vendor": "nginx", "product": "nginx_ingress_controller"},
        ]
    }
    label, cell, note = _formatters._resolve_vendor(payload)
    assert label == "Matched CPEs"
    assert cell == "f5/nginx, kubernetes/ingress-nginx, nginx/nginx_ingress_controller"
    assert note == (
        "Matched 3 vendor/product pairs across 4 CPE entries. Pass --vendor <name> --product <name> to narrow."
    )


def test_resolve_vendor_multi_pair_truncates_beyond_three() -> None:
    """More than 3 distinct pairs → top 3 followed by ellipsis."""
    payload = {
        "cpe_matches": [
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "kubernetes", "product": "ingress-nginx"},
            {"vendor": "nginx", "product": "nginx_ingress_controller"},
            {"vendor": "openresty", "product": "openresty"},
        ]
    }
    label, cell, note = _formatters._resolve_vendor(payload)
    assert label == "Matched CPEs"
    assert cell == "f5/nginx, kubernetes/ingress-nginx, nginx/nginx_ingress_controller, …"
    assert "Matched 4 vendor/product pairs across 5 CPE entries" in note


def test_resolve_vendor_lists_all_pairs_under_expand() -> None:
    """--expand lifts the 3-pair cap: all four pairs render, no trailing ellipsis.

    The exact-equality assertion on ``cell`` is the authoritative check — it
    pins every pair, the order, and the absence of a ``, …`` suffix in one shot,
    without relying on a membership test for the ellipsis glyph (which would be
    fooled by a product name that legitimately contained ``…``).
    """
    payload = {
        "cpe_matches": [
            {"vendor": "f5", "product": "nginx"},
            {"vendor": "kubernetes", "product": "ingress-nginx"},
            {"vendor": "nginx", "product": "nginx_ingress_controller"},
            {"vendor": "openresty", "product": "openresty"},
        ]
    }
    output.set_expand_mode(True)
    label, cell, note = _formatters._resolve_vendor(payload)
    assert label == "Matched CPEs"
    assert cell == "f5/nginx, kubernetes/ingress-nginx, nginx/nginx_ingress_controller, openresty/openresty"
    assert "Matched 4 vendor/product pairs across 4 CPE entries" in note


def test_resolve_vendor_same_vendor_different_products_lists_both_pairs() -> None:
    """One vendor, two products → two distinct pairs, shown separately."""
    payload = {
        "cpe_matches": [
            {"vendor": "nginx", "product": "nginx"},
            {"vendor": "nginx", "product": "nginx_ingress_controller"},
        ]
    }
    label, cell, _note = _formatters._resolve_vendor(payload)
    assert label == "Matched CPEs"
    assert cell == "nginx/nginx, nginx/nginx_ingress_controller"


def test_resolve_vendor_parses_product_from_cpe_uri_when_missing() -> None:
    """Upstream often leaves ``product`` empty — parse it from the CPE 2.3 URI.

    Live data has ``vendor`` populated but ``product`` empty on every
    CPE match. Without the URI fallback the cell would collapse to
    bare vendor names, hiding the actionable narrowing target.
    """
    payload = {
        "cpe_matches": [
            {"vendor": "f5", "product": "", "cpe": "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"},
            {"vendor": "kubernetes", "product": "", "cpe": "cpe:2.3:a:kubernetes:ingress-nginx:0.21:*:*:*:*:*:*:*"},
        ]
    }
    label, cell, _note = _formatters._resolve_vendor(payload)
    assert label == "Matched CPEs"
    assert cell == "f5/nginx, kubernetes/ingress-nginx"


def test_parse_cpe_uri_handles_well_formed_string() -> None:
    """Standard CPE 2.3 URI → ``(vendor, product)`` at positions 3, 4."""
    assert _formatters._parse_cpe_uri("cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*") == ("f5", "nginx")


def test_parse_cpe_uri_returns_empty_on_malformed_input() -> None:
    """Missing prefix or too few colons → empty tuple, no exception."""
    assert _formatters._parse_cpe_uri("") == ("", "")
    assert _formatters._parse_cpe_uri("not-a-cpe-uri") == ("", "")
    assert _formatters._parse_cpe_uri("cpe:2.3:a:f5") == ("", "")


def test_render_technique_emits_primary_details() -> None:
    """Populated technique renders count + top names per category."""
    payload = {
        "techniques": [
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "platforms": ["Linux"],
                "description": "exploit",
            }
        ],
        "predictions": [{"technique_id": "T1190"}],
        "groups": [{"name": "APT28"}, {"name": "FIN7"}],
        "software": [{"name": "COATHANGER"}],
        "campaigns": [{"name": "Operation MidnightEclipse"}],
        "cves": [],
        "threat_level": "high",
    }
    text = _capture(_formatters.render_technique, payload)
    assert "T1190" in text
    assert "Exploit Public-Facing Application" in text
    assert "APT28" in text and "FIN7" in text  # top group names surfaced
    assert "COATHANGER" in text
    assert "Operation MidnightEclipse" in text


def test_render_technique_handles_empty_response() -> None:
    """Empty techniques list → not-found line, no table."""
    text = _capture(_formatters.render_technique, {})
    assert "No data found" in text
    assert "Crimson Crawler" not in text


def test_render_technique_not_found_echoes_requested_id() -> None:
    """``requested_id`` is echoed verbatim into the empty-techniques message.

    Uses a deliberately synthetic id (`T9999`) so the test stays decoupled
    from whatever techniques happen to be in the live seed.
    """
    console = Console(record=True, width=200, color_system=None)
    sentinel = "T9999"
    _formatters.render_technique(console, {"techniques": []}, requested_id=sentinel)
    text = console.export_text()
    assert f"No data found for {sentinel}" in text


def test_render_search_cti_handles_empty_results() -> None:
    """Empty results list → not-found line, no header-only table."""
    text = _capture(_formatters.render_search_cti, {"results": []})
    assert "No data found" in text
    assert "Source" not in text  # five-column header would carry "Source"


def test_render_search_cti_not_found_echoes_keyword() -> None:
    """``requested_keyword`` is echoed (quoted) into the empty-results message."""
    console = Console(record=True, width=200, color_system=None)
    sentinel = "zzzznooneeverusesthiskeyword"
    _formatters.render_search_cti(console, {"results": []}, requested_keyword=sentinel)
    text = console.export_text()
    assert f'No data found for "{sentinel}"' in text


def test_render_search_cti_pulls_fields_defensively() -> None:
    payload = {
        "results": [
            {
                "_source": "attack",
                "attack_id": "T1003",
                "name": "OS Credential Dumping",
                "relevance_score": 0.91,
                "description": "lots of detail",
            },
            {"_source": "capec", "capec_id": "CAPEC-88", "name": "OS Command Injection"},
            "not-a-dict",  # exercises the isinstance guard
        ],
        "errors": [{"source": "ctibutler"}],
    }
    text = _capture(_formatters.render_search_cti, payload)
    assert "T1003" in text
    assert "CAPEC-88" in text
    assert "Partial failures" in text


def test_render_ioc_emits_verdict_and_techniques() -> None:
    """Populated IOC renders verdict + score + warninglist + linked techniques."""
    # The SDK's ``to_dict()`` serialises the ``type_`` attribute back to the
    # OpenAPI key ``type`` — the renderer must read that key, not ``type_``.
    payload = {
        "value": "1.2.3.4",
        "type": "ip-dst",
        "misp_attributes": [{"value": "1.2.3.4", "type": "ip-dst"}],
        "misp_feed_hits": [{"value": "1.2.3.4"}],
        "sightings_count": 12,
        "threat_assessment": {"verdict": "malicious", "threat_score": 78.0},
        "warninglist": {"is_on_warninglist": True, "warninglists": ["RFC1918", "Public DNS"]},
        "techniques": [{"technique_id": "T1071", "name": "Application Layer Protocol", "tactics": ["c2"]}],
        "cves": [{"cve": {"cve_id": "CVE-2024-0001"}}],
        "errors": [{"source": "misp"}],
    }
    text = _capture(_formatters.render_ioc, payload)
    assert "1.2.3.4" in text
    assert "ip-dst" in text  # the echoed type renders (regression guard for the type_/type key)
    assert "malicious" in text
    assert "78.0" in text
    assert "RFC1918" in text  # warninglist names surfaced
    assert "T1071" in text
    assert "Errors" in text


def test_render_ioc_handles_empty_response() -> None:
    """No MISP attributes / feed hits / techniques → not-found line, no table."""
    text = _capture(_formatters.render_ioc, {"value": "9.9.9.9", "type_": "ip-dst"})
    assert "No data found for 9.9.9.9" in text
    assert "Crimson Crawler" not in text


def test_render_ioc_warninglist_false_renders_no() -> None:
    """A populated warninglist dict with the flag off must read "no" (truthy-dict trap)."""
    assert _formatters._on_warninglist({"warninglist": {"is_on_warninglist": False, "warninglists": ["x"]}}) == "no"
    assert _formatters._on_warninglist({}) == "no"
    assert _formatters._on_warninglist({"warninglist": {"is_on_warninglist": True}}) == "yes"


def test_render_cwe_emits_detail_and_techniques() -> None:
    """Populated CWE renders name + abstraction + CAPEC/technique counts."""
    payload = {
        "weakness": {
            "cwe_id": "CWE-79",
            "name": "Cross-site Scripting",
            "description": "Improper neutralization of input.",
            "abstraction": "Base",
            "status": "Stable",
        },
        "attack_patterns": [{"capec_id": "CAPEC-63"}, {"capec_id": "CAPEC-588"}],
        "techniques": [{"technique_id": "T1059", "name": "Command", "tactics": ["execution"]}],
        "cves": [{"cve": {"cve_id": "CVE-2024-0002"}}],
        "exploitation_frequency": {"exploitation_class": "high_frequency"},
        "errors": [],
    }
    text = _capture(_formatters.render_cwe, payload)
    assert "CWE-79" in text
    assert "Cross-site Scripting" in text
    assert "Base" in text
    assert "high_frequency" in text
    assert "T1059" in text


def test_render_cwe_handles_missing_weakness() -> None:
    """``weakness: null`` emits the not-found line, no table."""
    text = _capture(_formatters.render_cwe, {"weakness": None})
    assert "No data found" in text
    assert "Crimson Crawler" not in text


def test_render_cwe_not_found_echoes_requested_id() -> None:
    """``requested_id`` is echoed verbatim into the not-found message."""
    console = Console(record=True, width=200, color_system=None)
    sentinel = "CWE-99999"
    _formatters.render_cwe(console, {"weakness": None}, requested_id=sentinel)
    text = console.export_text()
    assert f"No data found for {sentinel}" in text


def test_run_async_returns_value() -> None:
    async def _coro() -> int:
        return 7

    assert _formatters.run_async(_coro()) == 7


def test_with_status_skips_spinner_in_json_mode() -> None:
    output.set_json_mode(True)

    async def _coro() -> str:
        return "done"

    with patch.object(_formatters, "run_async", side_effect=lambda c: asyncio.run(c)) as mock_run:
        result = _formatters.with_status("loading", _coro())

    assert result == "done"
    assert mock_run.called


def test_with_status_shows_spinner_in_tty_mode() -> None:
    output.set_json_mode(False)

    async def _coro() -> str:
        return "ok"

    result = _formatters.with_status("loading", _coro())
    assert result == "ok"


def test_with_live_progress_streams_events_and_returns_result() -> None:
    """The live-progress helper drives the bar + streams each NEW event line, and returns the result."""
    output.set_json_mode(False)
    captured: list[dict] = []

    def make_coro(on_progress):
        async def _inner() -> str:
            # simulate the SDK calling back each poll with a growing event feed
            on_progress({"progress": 0.2, "events": [{"ts": "t1", "message": "✓ CVE-1", "progress": 0.2}]})
            on_progress(
                {
                    "progress": 0.6,
                    "events": [
                        {"ts": "t1", "message": "✓ CVE-1", "progress": 0.2},  # already shown — must NOT re-print
                        {"ts": "t2", "message": "✓ CVE-2", "progress": 0.6},  # new
                    ],
                }
            )
            captured.append({"done": True})
            return "report"

        return _inner()

    result = _formatters.with_live_progress("Enriching", make_coro)
    assert result == "report"
    assert captured == [{"done": True}]  # the coroutine ran to completion under the live bar


def test_with_live_progress_no_ui_in_json_mode() -> None:
    """JSON mode suppresses the live UI (no-op callback) so piped output stays clean."""
    output.set_json_mode(True)
    seen: list[object] = []

    def make_coro(on_progress):
        async def _inner() -> str:
            on_progress({"progress": 0.5, "events": [{"ts": "t", "message": "x"}]})  # no-op in json mode
            seen.append(on_progress)
            return "ok"

        return _inner()

    assert _formatters.with_live_progress("Enriching", make_coro) == "ok"
    assert seen  # callback supplied (a no-op), coroutine ran


# -- --expand mode ------------------------------------------------------------- #

_LONG_DESCRIPTION = "X" * 250  # > the 200-char CVE/CWE description cap


def test_expand_disables_description_truncation() -> None:
    """Default truncates a >200-char CVE description with `…`; --expand shows it whole.

    Rich hard-wraps the long cell across lines, so the expand assertion
    collapses whitespace to reconstruct the contiguous run.
    """
    payload = {"cve": {"cve_id": "CVE-2024-3400", "description": _LONG_DESCRIPTION}}

    default_text = _capture(_formatters.render_cve, payload, width=400)
    assert "…" in default_text
    assert _LONG_DESCRIPTION not in default_text  # truncated

    output.set_expand_mode(True)
    expand_text = _capture(_formatters.render_cve, payload, width=400)
    assert _LONG_DESCRIPTION in expand_text  # full text on one line at this width


def test_expand_disables_sub_table_char_trim() -> None:
    """A >50-char linked-technique name truncates by default, renders whole under --expand."""
    long_name = "Exploitation for Privilege Escalation Through a Very Long Technique Name"
    payload = {
        "cve": {"cve_id": "CVE-2024-3400", "description": "short"},
        "techniques": [{"technique_id": "T1068", "name": long_name, "tactics": ["privilege-escalation"]}],
    }

    default_text = _capture(_formatters.render_cve, payload)
    assert long_name not in default_text  # trimmed in the sub-table cell

    output.set_expand_mode(True)
    expand_text = _capture(_formatters.render_cve, payload)
    assert long_name in expand_text


def test_expand_lifts_linked_techniques_row_cap() -> None:
    """>15 linked techniques: default caps at 15, --expand renders every row."""
    techniques = [
        {"technique_id": f"T{1000 + i}", "name": f"Technique {i}", "tactics": ["execution"]} for i in range(20)
    ]
    payload = {"cve": {"cve_id": "CVE-2024-3400", "description": "short"}, "techniques": techniques}

    default_text = _capture(_formatters.render_cve, payload)
    assert "T1015" not in default_text  # the 16th row (index 15) is dropped

    output.set_expand_mode(True)
    expand_text = _capture(_formatters.render_cve, payload)
    assert "T1015" in expand_text
    assert "T1019" in expand_text  # the 20th row too


def test_expand_lifts_product_top_cves_row_cap() -> None:
    """>10 product Top-CVEs: default caps at 10, --expand renders every row."""
    cves = [{"cve": {"cve_id": f"CVE-2024-{i:05d}", "cvss_score": 5.0, "description": "x"}} for i in range(13)]
    payload = {
        "product": "nginx",
        "vendor": "nginx",
        "cpe_matches": [{"cpe": "cpe:2.3:a:nginx"}],
        "cves": cves,
    }

    default_text = _capture(_formatters.render_product, payload)
    assert "CVE-2024-00011" not in default_text  # 12th row dropped at the 10-row cap

    output.set_expand_mode(True)
    expand_text = _capture(_formatters.render_product, payload)
    assert "CVE-2024-00011" in expand_text
    assert "CVE-2024-00012" in expand_text


def test_expand_is_a_no_op_under_json() -> None:
    """With both modes set, render() still emits the JSON blob (renderer untouched)."""
    output.set_json_mode(True)
    output.set_expand_mode(True)
    payload = {"cve": {"cve_id": "CVE-2024-3400", "description": _LONG_DESCRIPTION}}

    captured: list[bool] = []

    def _renderer(_console, _payload) -> None:  # pragma: no cover - must not run
        captured.append(True)

    with patch("sys.stdout") as mock_stdout:
        output.render(payload, _renderer)

    assert captured == []  # renderer never invoked under --json
    written = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
    assert '"CVE-2024-3400"' in written
    assert _LONG_DESCRIPTION in written  # JSON is inherently untruncated
