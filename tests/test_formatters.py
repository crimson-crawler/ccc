"""Unit tests for the Rich-table renderers and async helpers."""

from __future__ import annotations

import asyncio
import re
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
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
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
        "cve": {"cve_id": "CVE-2025-24813", "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL", "poc_count": 0},
        "poc": [{"html_url": "https://github.com/a/b"}, {"html_url": "https://github.com/c/d"}],
    }
    text = _capture(_formatters.render_cve, payload)
    poc_row = next(line for line in text.splitlines() if "PoC count" in line)
    assert "2" in poc_row  # 2 from the list, not 0 from cve.poc_count


def test_render_cve_poc_count_falls_back_to_scalar() -> None:
    """With no top-level ``poc`` list, fall back to ``cve.poc_count``."""
    payload = {"cve": {"cve_id": "CVE-X", "cvss_v3_score": 7.0, "cvss_v3_severity": "HIGH", "poc_count": 5}}
    text = _capture(_formatters.render_cve, payload)
    poc_row = next(line for line in text.splitlines() if "PoC count" in line)
    assert "5" in poc_row


def test_render_cve_handles_legacy_score_epss_key() -> None:
    """Fall back to ``epss.score`` when ``epss.epss`` isn't present (older SDKs)."""
    payload = {
        "cve": {"cve_id": "CVE-X", "cvss_v3_score": 7.0, "cvss_v3_severity": "HIGH"},
        "epss": {"score": 0.5, "percentile": 0.8},
    }
    text = _capture(_formatters.render_cve, payload)
    assert "0.5" in text


def test_render_cve_marks_retracted_osv_advisory_and_withholds_its_fix() -> None:
    """A retracted advisory keeps its row and its id, but must not read as a live finding.

    ``enrich/cve``'s ``osv_advisories`` come off the ``/vulns/{id}`` GET lane, which does return
    records the source withdrew — the same payload an imported/saved enrichment report can carry.
    So the row stays (provenance) and its ``fixed_versions`` do not surface as a recommendation.
    """
    payload = {
        "cve": {"cve_id": "CVE-2024-3400"},
        "osv_advisories": [
            {"id": "GHSA-live-1111", "severity_label": "HIGH", "fixed_versions": ["1.2.3"], "summary": "live"},
            {
                "id": "GHSA-gone-2222",
                "severity_label": "CRITICAL",
                "fixed_versions": ["9.9.9"],
                "summary": "retracted",
                "withdrawn": "2026-03-01T00:00:00Z",
            },
        ],
    }
    text = _capture(_formatters.render_cve, payload)

    # The count a reader acts on excludes the retraction; the retraction is named instead.
    assert "OSV advisories (1 active, 1 retracted)" in text

    live = next(line for line in text.splitlines() if "GHSA-live-1111" in line)
    assert "active" in live
    assert "1.2.3" in live

    gone = next(line for line in text.splitlines() if "GHSA-gone-2222" in line)
    assert "withdrawn 2026-03-01T00:00:00Z" in gone
    assert "9.9.9" not in gone
    assert "9.9.9" not in text  # no actionable fix from a retracted advisory, anywhere


def test_render_cve_keeps_advisories_without_the_flag_unchanged() -> None:
    """No ``withdrawn`` key — the shape before the field existed — renders exactly as before."""
    payload = {
        "cve": {"cve_id": "CVE-2024-3400"},
        "osv_advisories": [{"id": "GHSA-live-1111", "fixed_versions": ["1.2.3"]}],
    }
    text = _capture(_formatters.render_cve, payload)

    assert "OSV advisories (1)" in text
    assert "withdrawn" not in text
    assert "retracted" not in text


def test_render_cve_escapes_markup_in_osv_advisory_fields() -> None:
    """``id`` / ``withdrawn`` / ``summary`` are upstream text and must not be interpreted as markup.

    Each cell appears literally — including a link tag long enough to hit the status-cell trim, which
    must still render as data rather than becoming a link.
    """
    payload = {
        "cve": {"cve_id": "CVE-2024-3400"},
        "osv_advisories": [
            {
                "id": "[red]GHSA-owned[/red]",
                "withdrawn": "[link=https://evil.example]2026-03-01[/link]",
                "summary": "[bold]x[/bold]",
            }
        ],
    }
    text = _capture(_formatters.render_cve, payload)

    assert "[red]GHSA-owned[/red]" in text
    assert "[bold]x[/bold]" in text
    assert "[link=https://evil." in text


def test_render_package_preserves_an_explicit_zero_advisory_count() -> None:
    """``vulnerability_count: 0`` is an answer, not an absent value.

    ``or len(advisories)`` recomputed the count from the list whenever the payload said 0 — exactly
    the case a retracted-advisory reduction produces, so the withdrawn finding came back as a
    headline number.
    """
    payload = {
        "ecosystem": "PyPI",
        "package": "django",
        "version": "1.0.0",
        "vulnerability_count": 0,
        "advisories": [{"id": "GHSA-gone-1111", "withdrawn": "2026-03-01T00:00:00Z", "fixed_versions": ["9.9.9"]}],
        "cves": [],
    }
    text = _capture(_formatters.render_package, payload)

    count_row = next(line for line in text.splitlines() if "Advisories" in line and "Active" not in line)
    assert "0" in count_row.split()
    assert "1" not in count_row.split()  # not the list length a `or len(advisories)` fallback produced
    assert "GHSA-gone-1111" in text  # the record itself is not discarded
    assert "9.9.9" not in text  # …but its fix is not presented
    assert "Active advisories" in text


def test_render_package_marks_retracted_rows_and_counts_only_active() -> None:
    """A mixed payload lists both rows, labels the retracted one, and counts only the live one."""
    payload = {
        "ecosystem": "npm",
        "package": "lodash",
        "version": "1.0.0",
        "vulnerability_count": 2,
        "advisories": [
            {"id": "GHSA-live-1111", "cve_ids": ["CVE-2024-1111"], "fixed_versions": ["2.0.0"], "summary": "live"},
            {
                "id": "GHSA-gone-2222",
                "fixed_versions": ["9.9.9"],
                "summary": "retracted",
                "withdrawn": "2026-03-01T00:00:00Z",
            },
        ],
    }
    text = _capture(_formatters.render_package, payload)

    assert "OSV advisories (1 active, 1 retracted)" in text
    assert "(excludes 1 retracted)" in text

    live = next(line for line in text.splitlines() if "GHSA-live-1111" in line)
    assert "active" in live
    assert "2.0.0" in live

    gone = next(line for line in text.splitlines() if "GHSA-gone-2222" in line)
    assert "withdrawn 2026-03-01T00:00:00Z" in gone
    assert "9.9.9" not in text

    # `--json` prints this same dict, so the renderer must not have consumed anything from it.
    assert payload["advisories"][1]["fixed_versions"] == ["9.9.9"]


def test_render_package_marks_withdrawn_nd_envelope() -> None:
    payload = {
        "ecosystem": "PyPI",
        "package": "example",
        "vulnerability_count": 0,
        "advisories": [
            {
                "id": "CGA-dead",
                "withdrawn": True,
                "withdrawn_at": "2024-03-01T03:04:05Z",
                "source_url": "https://osv.dev/vulnerability/CGA-dead",
            }
        ],
    }
    text = _capture(_formatters.render_package, payload)
    assert "CGA-dead" in text and "withdrawn 2024-03-01T03:04:05Z" in text
    assert "1 retracted" in text and "True" not in text


def test_render_package_escapes_nd_withdrawal_timestamp() -> None:
    payload = {
        "ecosystem": "PyPI",
        "package": "example",
        "advisories": [{"id": "CGA-dead", "withdrawn": True, "withdrawn_at": "[red]2024-03-01[/red]"}],
    }
    text = _capture(_formatters.render_package, payload)
    assert "[red]2024-03-01[/re" in text


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


def test_render_search_kev_states_membership_for_an_unlisted_cve() -> None:
    """A KEV miss is a real row with null catalogue fields, so the table must state membership.

    ``ccc search kev CVE-1999-99999`` answers with one row — ``in_kev: false`` and every
    catalogue field null — and rendering that row with no membership cell leaves a decisive
    "not on the catalog" looking like an entry whose metadata failed to load. Cells are read
    back through the header, so reordering or adding columns doesn't touch this.
    """
    miss = {
        "cve_id": "CVE-1999-99999",
        "in_kev": False,
        "vendor_project": None,
        "product": None,
        "date_added": None,
        "due_date": None,
        "ransomware": False,
        "vulnerability_name": None,
    }
    hit = {
        "cve_id": "CVE-2024-3400",
        "in_kev": True,
        "vendor_project": "Palo Alto Networks",
        "product": "PAN-OS",
        "date_added": "2024-04-12",
        "due_date": "2024-04-19",
        "ransomware": True,
        "vulnerability_name": "PAN-OS Command Injection",
    }
    text = _capture(_formatters.render_search_kev, {"results": [miss, hit]}, width=240)
    header = next(line for line in text.splitlines() if "In KEV" in line)
    names = [cell.strip() for cell in re.split(r"[│┃]", header)[1:-1]]

    def membership(row: dict) -> str:
        line = next(line for line in text.splitlines() if row["cve_id"] in line)
        return [cell.strip() for cell in re.split(r"[│┃]", line)[1:-1]][names.index("In KEV")]

    assert membership(miss) == "no"
    assert membership(hit) == "yes"
    # A row that states nothing is unknown, not a false membership claim.
    assert _formatters._kev_membership({"cve_id": "CVE-2024-3400"}) == "—"


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


def test_count_with_top_escapes_untrusted_names() -> None:
    """The helper escapes, because its nine ``add_row`` callers cannot."""
    assert _formatters._count_with_top([{"name": "[red]x[/red]"}]) == "1 — \\[red]x\\[/red]"
    # Non-str names must not blow up the join either.
    assert _formatters._count_with_top([{"name": 42}]) == "1 — 42"


def test_render_technique_survives_malformed_markup_in_names() -> None:
    """An unbalanced tag in a name would raise MarkupError → exit 1 if interpreted."""
    text = _capture(
        _formatters.render_technique,
        {
            "techniques": [{"technique_id": "T1055"}],
            "groups": [{"name": "[/]"}],
            "software": [{"name": "[link=file:///etc/passwd]innocent[/link]"}],
        },
    )
    assert "[/]" in text
    assert "[link=file:///etc/passwd]innocent[/link]" in text


def test_render_cve_handles_missing_fields() -> None:
    """Empty payload (``cve: null``) emits the not-found line, no table."""
    text = _capture(_formatters.render_cve, {})
    assert "No data found" in text
    assert "Crimson Crawler" not in text


def test_render_cve_keeps_source_only_advisories_and_attribution() -> None:
    for advisory_id, licence in (("GHSA-1", "CC-BY-4.0"), ("CGA-1", "CC-BY-NC-ND-4.0")):
        payload = {
            "cve": None,
            "osv_advisories": [
                {
                    "id": advisory_id,
                    "summary": "Distinctive advisory",
                    "source_url": "https://osv.dev/vulnerability/" + advisory_id,
                    "licence": licence,
                    "licence_url": "https://example.test/licence",
                    "attribution": "Publisher [bold]literal[/bold]; fields selected",
                }
            ],
            "errors": [{"service": "osv", "error": "stale_copy", "detail": "OSV data as of yesterday"}],
        }
        text = _capture(_formatters.render_cve, payload)
        assert "No data found" not in text
        assert advisory_id in text and "Distinctive advisory" in text
        assert "https://osv.dev/vulnerability/" + advisory_id in text
        assert licence in text and "https://example.test/licence" in text
        assert "Publisher [bold]literal[/bold]" in text
        assert "stale_copy" in text and "OSV data as of yesterday" in text


def test_render_cve_keeps_source_only_android_credit() -> None:
    text = _capture(
        _formatters.render_cve,
        {
            "cve": None,
            "android_bulletin": {
                "asb_id": "ASB-A-111893654",
                "severity": "High",
                "source_url": "https://example.test/android",
                "licence": "CC-BY-4.0",
                "attribution": "Android Open Source Project; CC-BY-4.0 https://creativecommons.org/licenses/by/4.0/",
            },
        },
    )
    assert "No data found" not in text
    assert "ASB-A-111893654" in text
    assert "https://example.test/android" in text
    assert "Android Open Source Project" in text
    assert "https://creativecommons.org/licenses/by/4.0/" in text


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
                "cve": {"cve_id": "CVE-2023-44487", "cvss_v3_score": 7.5, "description": "rapid reset"},
                "epss": {"epss": 0.42},  # canonical key
                "kev": {"in_kev": True, "vendor_inventory": "nginx"},
            },
            {
                "cve": {"cve_id": "CVE-2024-00001", "cvss_v3_score": 5.0, "description": "legacy shape"},
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


def test_render_technique_surfaces_ics_asset_and_fraud_techniques() -> None:
    """The ICS-asset lookup's own `asset` and the opt-in `f3_techniques` layer are rendered rather than
    silently dropped by the table."""
    payload = {
        "techniques": [
            {
                "technique_id": "T0852",
                "name": "Screen Capture",
                "tactics": ["collection"],
                "platforms": ["None"],
                "description": "capture",
                "f3_techniques": [
                    {
                        "object_id": "F1031",
                        "name": "Impersonate Account Holder",
                        "url": "https://ctid.mitre.org/fraud/F1031",
                    }
                ],
            }
        ],
        "asset": {"asset_id": "A0002", "name": "Human-Machine Interface (HMI)"},
        "errors": [],
    }
    text = _capture(_formatters.render_technique, payload)

    assert "A0002" in text and "Human-Machine Interface (HMI)" in text
    assert "F3 fraud techniques (1)" in text
    assert "F1031" in text


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


def test_render_ioc_publishes_network_registration_and_list_rows() -> None:
    """#466 IOC network tokens: ASN, RDAP registration and the unified list ledger each get a row."""
    payload = {
        "value": "1.10.16.5",
        "type": "ip-dst",
        "network_context": {
            "ip": "1.10.16.5",
            "version": 4,
            "asn": None,
            "as_name": None,
            "country": None,
            "prefix": "1.10.0.0/17",
            "source": "iptoasn",
        },
        "domain_context": {
            "domain": "example.com",
            "registration_date": "1995-08-14T04:00:00Z",
            "age_days": 10000,
            "registrar": "RESERVED-Internet Assigned Numbers Authority",
            "status": [],
            "source": "rdap",
        },
        "listed_on": [
            {"source": "example.org", "list": "Example list A", "match": "exact"},
            {"source": "Spamhaus DROP", "list": "DROP", "match": "cidr"},
        ],
    }
    text = _capture(_formatters.render_ioc, payload)
    assert "not routed / unknown" in text
    assert "1.10.0.0/17" in text
    assert "1995-08-14T04:00:00Z (10000 days)" in text
    assert "example.org/Example list A (exact)" in text
    assert "Spamhaus DROP/DROP (cidr)" in text


def test_render_ioc_network_only_answer_is_not_reported_as_no_data() -> None:
    payload = {
        "value": "8.8.8.8",
        "type": "ip-dst",
        "network_context": {
            "ip": "8.8.8.8",
            "version": 4,
            "asn": 15169,
            "as_name": "GOOGLE",
            "country": "US",
            "prefix": "8.8.8.0/24",
            "source": "iptoasn",
        },
    }
    text = _capture(_formatters.render_ioc, payload)
    assert "AS15169 GOOGLE; US; 8.8.8.0/24" in text
    assert "No data" not in text and "no data" not in text.lower()


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
    """Populated CWE renders the identity rows plus the hierarchy/categories/detection layers."""
    payload = {
        "weakness": {
            "cwe_id": "CWE-79",
            "name": "Cross-site Scripting",
            "description": "Improper neutralization of input.",
            "likelihood_of_exploit": "High",
            "related_weaknesses": [{"nature": "ChildOf", "cwe_id": "CWE-74"}],
            "categories": [{"grouping_id": "CWE-1396", "name": "Access Control"}],
            "views": [{"grouping_id": "CWE-699", "name": "Software Development View"}],
            "detection_methods": ["Automated Static Analysis"],
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
    assert "high_frequency" in text
    assert "T1059" in text
    # The layers that are the reason to request a CWE bundle: the actual parent edge, the MITRE
    # groupings and the detection guidance — not counts alone.
    assert "CWE-74" in text
    assert "CWE-1396" in text
    assert "Automated Static Analysis" in text
    assert "High" in text


def test_render_cwe_marks_a_generic_weakness() -> None:
    """``is_generic`` replaced the removed ``version`` row; a specific CWE prints neither."""
    weakness = {"cwe_id": "CWE-284", "name": "Improper Access Control", "is_generic": True}
    generic = _capture(_formatters.render_cwe, {"weakness": weakness})
    assert "Generic weakness" in generic
    assert "pillar/class" in generic

    specific = _capture(_formatters.render_cwe, {"weakness": {"cwe_id": "CWE-79", "name": "XSS"}})
    assert "Generic weakness" not in specific
    assert "Version" not in specific  # the row the removed CWEDetail.version fed


def test_render_cwe_search_matches_are_rendered() -> None:
    """``weakness: null`` WITH search results is a ``--search`` hit, not a miss."""
    payload = {
        "weakness": None,
        "search_results": [{"cwe_id": "CWE-79", "name": "Cross-site Scripting", "description": "x"}],
    }
    text = _capture(_formatters.render_cwe, payload)
    assert "CWE-79" in text
    assert "No data found" not in text


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


# -- render_entity (the eleven id-or-search entity payloads) -------------------- #

# Trimmed real responses. F3/CLOAK's ``FrameworkObjectDetail`` names the framework id
# ``object_id`` (the ATLAS/DISARM ``TechniqueDetail`` uses ``technique_id``), F3 hangs its
# ATT&CK hop off ``linked_techniques``, and a CLOAK tool carries no tactics and no url — so
# the row set has to shrink to fit rather than print empty cells.
_F3_PAYLOAD = {
    "technique": {
        "object_id": "F1031",
        "name": "Impersonate Account Holder",
        "description": "Fraud actors may impersonate legitimate account holders.",
        "object_type": "attack-pattern",
        "tactics": ["initial-access", "defense-evasion"],
        "url": "https://ctid.mitre.org/fraud/techniques/F1031",
        "stix_id": "attack-pattern--03361ddb-cd4a-552e-b1ad-aa6b1a07d343",
    },
    "linked_techniques": [
        {"technique_id": "T1593", "name": "Search Open Websites/Domains", "tactics": ["reconnaissance"]}
    ],
    "knowledgebase": [{"title": "kb"}],
    "errors": [],
}

_CLOAK_PAYLOAD = {
    "technique": {
        "object_id": "TTP-496",
        "name": "DNS over TLS (DoT)",
        "description": "Encrypts DNS queries over a dedicated TLS connection.",
        "object_type": "tool",
        "tactics": [],
        "url": "",
        "stix_id": "tool--21f35349-52db-56ac-9d9e-3b9558fec6f6",
    },
    "knowledgebase": [{"title": "kb"}],
    "errors": [],
}


def test_render_entity_renders_framework_object_detail() -> None:
    """F3's detail model names the id ``object_id`` — the ID and Tactics rows must still fill."""
    text = _capture(_formatters.render_entity, _F3_PAYLOAD)

    assert "F1031" in text  # read from object_id, not technique_id
    assert "initial-access, defense-evasion" in text  # tactics row
    assert "attack-pattern" in text  # object_type row
    assert "linked techniques 1 · knowledgebase 1" in text
    assert "T1593" in text  # the linked-techniques sub-table
    assert "https://ctid.mitre.org/fraud/techniques/F1031" in text


def test_render_entity_omits_absent_cloak_rows() -> None:
    """A CLOAK tool has no tactics, no url and no technique hop — those rows must not print."""
    text = _capture(_formatters.render_entity, _CLOAK_PAYLOAD)

    assert "TTP-496" in text
    assert "tool" in text
    assert "knowledgebase 1" in text
    assert "Tactics" not in text
    assert "Reference" not in text
    assert "Linked techniques" not in text
    assert "│ —" not in text  # no cell renders the placeholder


def test_render_entity_search_matches_read_object_id() -> None:
    """``search_results`` rows are the same detail model, so the match table needs object_id."""
    text = _capture(
        _formatters.render_entity,
        {"search_results": [{"object_id": "TTP-2799", "name": "DNSCrypt", "description": "x"}], "errors": []},
    )

    assert "TTP-2799" in text
    assert "DNSCrypt" in text


def test_render_entity_search_match_table_only_shows_aliases_a_model_declares() -> None:
    """Six of the eleven entity details still declare ``aliases``; five dropped it.

    The match table is shared by all eleven entity commands, so an unconditional Aliases
    column printed a blank cell for every ATT&CK/ATLAS/DISARM technique and F3/CLOAK object
    match — a column that could never be filled.
    """
    technique_match = _capture(
        _formatters.render_entity,
        {
            "search_results": [
                {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "description": "x"}
            ],
            "errors": [],
        },
    )
    assert "Aliases" not in technique_match  # TechniqueDetail has no aliases field

    group_match = _capture(
        _formatters.render_entity,
        {
            "search_results": [{"group_id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"], "description": "x"}],
            "errors": [],
        },
    )
    assert "Aliases" in group_match
    assert "Cozy Bear" in group_match


def test_render_entity_renders_the_objects_revision_history() -> None:
    """``include=['versions']`` history hangs off the entity — every entity, not just technique/CWE."""
    payload = {
        **_F3_PAYLOAD,
        "technique": {
            **_F3_PAYLOAD["technique"],
            "revision_history": [
                {"modified": "2026-04-08T17:36:46.311Z", "versions": ["1.0"], "latest": True},
            ],
        },
    }

    text = _capture(_formatters.render_entity, payload)

    assert "Revision history (1)" in text
    assert "2026-04-08T17:36:46.311Z" in text
    assert "1.0" in text


def test_render_entity_without_history_prints_no_history_table() -> None:
    """The opt-out case stays silent — no empty table, no placeholder."""
    text = _capture(_formatters.render_entity, _F3_PAYLOAD)

    assert "Revision history" not in text


def test_render_entity_revision_history_distinguishes_unknown_from_not_current() -> None:
    """``latest`` is tri-state: a row the source never judged must not render the "no" of a False.

    The KB histories (every ATT&CK-family surface) carry no current-status, so the column reads
    "—"; the CVE path's explicit False still reads "no".
    """
    payload = {
        **_F3_PAYLOAD,
        "technique": {
            **_F3_PAYLOAD["technique"],
            "revision_history": [
                {"modified": "2026-09-01T00:00:00Z", "versions": ["9.9.9"], "latest": True},
                {"modified": "2026-05-01T00:00:00Z", "versions": ["9.9.8"], "latest": False},
                {"modified": "2026-01-01T00:00:00Z", "versions": ["9.9.7"]},
            ],
        },
    }

    lines = _capture(_formatters.render_entity, payload).splitlines()

    def current_cell(version: str) -> str:
        line = next(line for line in lines if version in line)
        return [cell.strip() for cell in line.split("│") if cell.strip()][-1]

    assert current_cell("9.9.9") == "yes"
    assert current_cell("9.9.8") == "no"
    assert current_cell("9.9.7") == "—"


def test_render_cwe_reads_the_history_off_the_weakness() -> None:
    """The API attaches it to ``weakness`` (``CWEDetail``); a payload-level read showed nothing."""
    payload = {
        "weakness": {
            "cwe_id": "CWE-284",
            "name": "Improper Access Control",
            "revision_history": [{"modified": "2026-05-01T00:00:00Z", "versions": ["4.19"], "latest": True}],
        },
        "errors": [],
    }

    text = _capture(_formatters.render_cwe, payload)

    assert "Revision history (1)" in text
    assert "4.19" in text


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
    cves = [{"cve": {"cve_id": f"CVE-2024-{i:05d}", "cvss_v3_score": 5.0, "description": "x"}} for i in range(13)]
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
