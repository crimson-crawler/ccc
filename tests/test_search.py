"""End-to-end tests for the ``ccc search`` sub-app.

Covers all nine subcommands: the six that require their query/identifier
(``cti``, ``d3fend``, ``knowledgebase``, ``poc``, ``vendor``, ``techniques``) and
the three pure-filter endpoints whose positional is optional (``cve``, ``kev``,
``misp``). The deprecated top-level ``ccc search-techniques`` alias keeps its own
suite in ``test_search_techniques.py``; here we only pin that the grouped
spelling reaches the same SDK method.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode
from crimson_crawler_client import UnexpectedStatus


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("cve", ["nginx"]),
        ("kev", []),
        ("d3fend", ["network"]),
        ("misp", ["--event-id", "1"]),
    ],
)
def test_search_rejects_conflicting_include_flags_without_credentials(
    runner: CliRunner, clean_env: Path, command, args
) -> None:
    result = runner.invoke(app, ["search", command, *args, "--no-includes", "--include", "details"])
    assert result.exit_code == ExitCode.BAD_INPUT
    assert "--no-includes cannot be combined with --include" in result.output


@pytest.mark.parametrize(
    ("command", "method", "message"),
    [
        ("cve", "search_cve", "No matching CVEs for this query."),
        ("kev", "search_kev", "No matching KEV entries for this query."),
    ],
)
@pytest.mark.parametrize(("matched", "with_stats"), [(False, True), (False, False), (True, True)])
def test_empty_search_result_is_distinct_from_statistics(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
    command,
    method,
    message,
    matched,
    with_stats,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {
        "results": [{"cve_id": "CVE-2024-1234"}] if matched else [],
        "statistics": {"cve_total_count": 10, "kev_by_year": [{"count": 10}]} if with_stats else None,
        "errors": [],
    }
    getattr(mock_sdk, method).return_value = _stub_response(payload)
    result = runner.invoke(app, ["search", command, "CVE-2024-1234"])
    assert result.exit_code == 0, result.output
    assert (message in result.output) is not matched
    if with_stats:
        assert "in this deployment" in result.output
    if matched:
        assert "CVE-2024-1234" in result.output


@pytest.mark.parametrize(
    ("command", "method", "step", "label"),
    [("cve", "search_cve", "get_cve", "CVE"), ("kev", "search_kev", "search_kev", "KEV")],
)
def test_primary_search_failure_is_not_reported_as_no_match(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, command, method, step, label
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {
        "results": [],
        "statistics": {"cve_total_count": 10, "kev_by_year": [{"count": 10}]},
        "errors": [{"step": step, "service": "vulnerability-data", "error": "OSError", "detail": "unavailable"}],
    }
    getattr(mock_sdk, method).return_value = _stub_response(payload)
    result = runner.invoke(app, ["search", command, "CVE-2024-1234"])
    assert result.exit_code == 0, result.output
    assert f"{label} search failed; matching results are unavailable." in result.output
    assert "No matching" not in result.output and "in this deployment" in result.output


@pytest.mark.parametrize(("command", "method"), [("cve", "search_cve"), ("kev", "search_kev")])
def test_unavailable_statistics_do_not_render_null_counts(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, command, method
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    statistics = {
        "cve_total_count": None,
        "latest_cve": None,
        "cve_modified_since": {"d1": None, "d7": None, "d30": None},
        "kev_by_year": [],
        "kev_created_since": None,
    }
    payload = {"results": [{"cve_id": "CVE-2024-1234"}], "statistics": statistics, "errors": []}
    getattr(mock_sdk, method).return_value = _stub_response(payload)
    result = runner.invoke(app, ["search", command, "CVE-2024-1234"])
    assert result.exit_code == 0
    assert "CVE-2024-1234" in result.output
    assert "in this deployment" not in result.output and "d1 None" not in result.output


@pytest.mark.parametrize(("command", "default"), [("kev", "statistics"), ("d3fend", "versions")])
def test_search_help_explains_include_replacement(runner: CliRunner, command: str, default: str) -> None:
    result = runner.invoke(app, ["search", command, "--help"])
    text = " ".join(result.output.replace("│", " ").split())
    assert result.exit_code == 0
    assert f"replaces the default ['{default}']" in text
    assert "--no-includes" in text


# -- ccc search cve ------------------------------------------------------------- #

_CVE_RESULTS = {
    "results": [
        {
            "cve_id": "CVE-2024-3400",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
            "weaponization_score": 88,
            "has_public_exploit": True,
            "cwe_ids": ["CWE-77"],
            "description": "PAN-OS authentication bypass.",
        }
    ],
    "errors": [],
}


def test_search_cve_query_renders_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response(_CVE_RESULTS)

    result = runner.invoke(app, ["search", "cve", "authentication bypass"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CVE-2024-3400" in result.stdout
    assert "CRITICAL" in result.stdout
    args, kwargs = mock_sdk.search_cve.call_args
    assert args == ("authentication bypass",)
    assert kwargs["limit"] == 50 and kwargs["page"] == 1 and kwargs["kev_only"] is False


def test_search_cve_filters_forwarded(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response(_CVE_RESULTS)

    result = runner.invoke(
        app,
        [
            "search",
            "cve",
            "--cwe-id",
            "CWE-79",
            "--attack-id",
            "T1190",
            "--capec-id",
            "CAPEC-66",
            "--cpe",
            "cpe:2.3:a:apache:http_server",
            "--cvss-min",
            "7.5",
            "--epss-min",
            "0.5",
            "--kev-only",
            "--vuln-status",
            "Analyzed",
            "--sort",
            "epss_score_descending",
            "--include",
            "details",
            "--include",
            "kev",
            "--limit",
            "10",
            "--page",
            "3",
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    kwargs = mock_sdk.search_cve.call_args.kwargs
    assert kwargs["cwe_id"] == "CWE-79"
    assert kwargs["attack_id"] == "T1190"
    assert kwargs["capec_id"] == "CAPEC-66"
    assert kwargs["cpe"] == "cpe:2.3:a:apache:http_server"
    assert kwargs["cvss_min"] == 7.5
    assert kwargs["epss_min"] == 0.5
    assert kwargs["kev_only"] is True
    assert kwargs["vuln_status"] == "Analyzed"
    assert kwargs["sort"] == "epss_score_descending"
    assert kwargs["include"] == ["details", "kev"]
    assert kwargs["limit"] == 10 and kwargs["page"] == 3


def test_search_cve_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response(_CVE_RESULTS)

    result = runner.invoke(app, ["--json", "search", "cve", "--kev-only"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _CVE_RESULTS


def test_search_cve_kev_only_alone_is_a_valid_filter(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response(_CVE_RESULTS)

    result = runner.invoke(app, ["search", "cve", "--kev-only"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.search_cve.assert_awaited_once()


def test_search_cve_without_any_filter_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """An unfiltered call would page the whole corpus — refuse before the request."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "cve", "--limit", "5"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_cve.assert_not_awaited()


# -- ccc search kev ------------------------------------------------------------- #


def test_search_kev_bare_lists_catalog(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_kev.return_value = _stub_response(
        {
            "results": [
                {
                    "cve_id": "CVE-2021-44228",
                    "vendor_project": "Apache",
                    "product": "Log4j2",
                    "date_added": "2021-12-10",
                    "due_date": "2021-12-24",
                    "ransomware": True,
                    "vulnerability_name": "Apache Log4j2 RCE",
                }
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "kev"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CVE-2021-44228" in result.stdout
    kwargs = mock_sdk.search_kev.call_args.kwargs
    assert kwargs["cve_id"] is None and kwargs["ransomware_status"] is None
    # No ``--include`` means the server's own default applies; asking for the corpus block is the
    # caller's opt-in.
    assert kwargs["include"] is None


def test_search_kev_normalises_and_filters(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_kev.return_value = _stub_response({"results": [], "errors": []})

    result = runner.invoke(app, ["search", "kev", "cve-2024-3400", "--ransomware-status", "Known"])

    assert result.exit_code == 0, result.stdout + result.stderr
    kwargs = mock_sdk.search_kev.call_args.kwargs
    assert kwargs["cve_id"] == "CVE-2024-3400"
    assert kwargs["ransomware_status"] == "Known"


def test_search_kev_malformed_cve_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "kev", "CVE-24-3400"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_kev.assert_not_awaited()


def test_search_kev_statistics_render_with_no_catalog_matches(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``--include statistics`` is a coverage call: the corpus block renders even when no catalog
    entry matched, and the requested layer reaches the wire."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_kev.return_value = _stub_response(
        {
            "results": [],
            "statistics": {
                "cve_total_count": 450284,
                "latest_cve": "CVE-2026-90461",
                "cve_modified_since": {"d1": 1333, "d7": 7096, "d30": 20947},
                "kev_by_year": [{"year": 2024, "count": 1000}, {"year": 2025, "count": 169}],
                "kev_created_since": {"d1": 3, "d7": 11, "d30": 42, "d365": 900},
            },
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "kev", "--include", "statistics"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "1169 KEV entries in this deployment" in result.stdout
    assert "d365 900" in result.stdout
    assert "No data found" not in result.stdout
    assert mock_sdk.search_kev.call_args.kwargs["include"] == ["statistics"]


def test_search_kev_unavailable_statistics_never_fake_a_zero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """When the KEV half of the stats read failed, the shared CVE-corpus half prints instead — the
    renderer must not report "0 KEV entries", which is a different fact from "unknown"."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_kev.return_value = _stub_response(
        {
            "results": [],
            "statistics": {
                "cve_total_count": 450284,
                "latest_cve": "CVE-2026-90461",
                "cve_modified_since": {"d1": 1333, "d7": 7096, "d30": 20947},
                "kev_by_year": [],
                "kev_created_since": None,
            },
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "kev", "--include", "statistics"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "0 KEV entries" not in result.stdout
    assert "450284 CVEs in this deployment" in result.stdout


# -- ccc search cti ------------------------------------------------------------- #


def test_search_cti_scopes_sources_and_types(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cti.return_value = _stub_response(
        {"results": [{"_source": "attack", "attack_id": "T1003", "name": "OS Credential Dumping"}], "errors": []}
    )

    result = runner.invoke(
        app,
        ["search", "cti", "credential dumping", "--source", "attack", "--source", "capec", "--type", "attack-pattern"],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "T1003" in result.stdout
    args, kwargs = mock_sdk.search_cti.call_args
    assert args == ("credential dumping",)
    assert kwargs["sources"] == ["attack", "capec"]
    assert kwargs["types"] == ["attack-pattern"]


def test_search_cti_accepts_f3_and_cloak_sources(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """F3 and CLOAK are searchable CTI sources, alongside attack/disarm/atlas."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cti.return_value = _stub_response({"results": [], "errors": []})

    result = runner.invoke(app, ["search", "cti", "wire transfer", "--source", "f3", "--source", "cloak"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.search_cti.call_args.kwargs["sources"] == ["f3", "cloak"]


def test_search_cti_defaults_omit_scoping(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """No ``--source``/``--type`` means the server's own defaults apply."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cti.return_value = _stub_response({"results": [], "errors": []})

    result = runner.invoke(app, ["search", "cti", "phishing"])

    assert result.exit_code == 0, result.stdout + result.stderr
    kwargs = mock_sdk.search_cti.call_args.kwargs
    assert kwargs["sources"] is None and kwargs["types"] is None


def test_search_cti_blank_query_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "cti", "   "])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_cti.assert_not_awaited()


def test_search_cti_rejects_unknown_type(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "cti", "phishing", "--type", "not-a-stix-type"])

    assert result.exit_code != 0
    mock_sdk.search_cti.assert_not_awaited()


# -- ccc search d3fend ---------------------------------------------------------- #


def test_search_d3fend_renders_and_forwards_form(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_d3fend.return_value = _stub_response(
        {
            "results": [
                {
                    "d3fend_id": "D3-NTA",
                    "d3fend_form": "mitigation",
                    "name": "Network Traffic Analysis",
                    "linked_techniques": ["T1071"],
                    "description": "Analyzing network traffic.",
                }
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "d3fend", "network traffic", "--form", "mitigation"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "D3-NTA" in result.stdout
    args, kwargs = mock_sdk.search_d3fend.call_args
    assert args == ("network traffic",)
    assert kwargs["d3fend_form"] == "mitigation"


def test_search_d3fend_versions_include_passthrough(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``--include versions`` asks for each returned technique's KB revision history."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_d3fend.return_value = _stub_response({"results": [{"d3fend_id": "D3-NTA"}], "errors": []})

    result = runner.invoke(app, ["search", "d3fend", "network traffic", "--include", "versions"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.search_d3fend.call_args.kwargs["include"] == ["versions"]


def test_search_d3fend_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"results": [{"d3fend_id": "D3-AL"}], "errors": []}
    mock_sdk.search_d3fend.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "search", "d3fend", "logging"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


# -- ccc search knowledgebase --------------------------------------------------- #


def test_search_knowledgebase_forwards_collections_and_alpha(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_knowledgebase.return_value = _stub_response(
        {
            "results": [
                {"collection": "red_team", "score": 0.87, "source": "handbook.md", "content": "Kerberoasting steps…"}
            ],
            "errors": [],
        }
    )

    result = runner.invoke(
        app,
        [
            "search",
            "knowledgebase",
            "kerberoasting",
            "--collection",
            "red_team",
            "--collection",
            "main",
            "--alpha",
            "0.3",
            "--limit",
            "5",
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Kerberoasting" in result.stdout
    args, kwargs = mock_sdk.search_knowledgebase.call_args
    assert args == ("kerberoasting",)
    assert kwargs["collections"] == ["red_team", "main"]
    assert kwargs["alpha"] == 0.3
    assert kwargs["limit"] == 5


def test_search_knowledgebase_alpha_out_of_range_exits_nonzero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "knowledgebase", "x", "--alpha", "1.5"])

    assert result.exit_code != 0
    mock_sdk.search_knowledgebase.assert_not_awaited()


# -- ccc search misp ------------------------------------------------------------ #


def test_search_misp_renders_attributes_and_events(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_misp.return_value = _stub_response(
        {
            "attributes": [
                {
                    "type": "ip-dst",
                    "value": "203.0.113.7",
                    "category": "Network activity",
                    "event_id": "42",
                    "sighting_count": 3,
                    "to_ids": True,
                    "tags": ["tlp:white"],
                }
            ],
            "events": [
                {
                    "id": "42",
                    "date": "2026-01-04",
                    "org": "CIRCL",
                    "threat_level_id": "2",
                    "attribute_count": 17,
                    "info": "Botnet C2 sightings",
                }
            ],
            "misp_events_truncated": True,
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "misp", "203.0.113.7"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "203.0.113.7" in result.stdout
    assert "Botnet C2 sightings" in result.stdout
    assert "misp_events_full" in result.stdout
    assert mock_sdk.search_misp.call_args.kwargs["value"] == "203.0.113.7"
    # Sightings are opt-in: the default call must not ask MISP for the array.
    assert mock_sdk.search_misp.call_args.kwargs["include"] is None


def test_search_misp_filter_only_call(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_misp.return_value = _stub_response({"attributes": [], "events": [], "errors": []})

    result = runner.invoke(
        app,
        [
            "search",
            "misp",
            "--type",
            "domain",
            "--tag",
            "tlp:green",
            "--tag",
            "apt",
            "--date-from",
            "2026-01-01",
            "--no-published",
            "--to-ids",
            "--threat-level",
            "1",
            "--include",
            "sightings",
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    kwargs = mock_sdk.search_misp.call_args.kwargs
    assert kwargs["value"] is None
    assert kwargs["type_attribute"] == "domain"
    assert kwargs["tags"] == ["tlp:green", "apt"]
    assert kwargs["date_from"] == "2026-01-01"
    assert kwargs["published"] is False
    assert kwargs["to_ids"] is True
    assert kwargs["threat_level_id"] == "1"
    assert kwargs["include"] == ["sightings"]


def test_search_misp_include_alone_is_not_a_filter(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``--include`` deepens the response, it does not narrow the search — asking for
    sightings with no filter would still page the whole feed, so it stays refused."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "misp", "--include", "sightings"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_misp.assert_not_awaited()


def test_search_misp_without_any_filter_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "misp"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_misp.assert_not_awaited()


def test_search_misp_empty_both_lists_reports_no_data(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_misp.return_value = _stub_response({"attributes": [], "events": [], "errors": []})

    result = runner.invoke(app, ["search", "misp", "203.0.113.9"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "No data found" in result.stdout


# -- ccc search poc ------------------------------------------------------------- #


def test_search_poc_renders_repositories(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_poc.return_value = _stub_response(
        {
            "cve_id": "CVE-2024-3400",
            "total": 12,
            "results": [
                {
                    "repo_name": "xzbot",
                    "owner": "amlweems",
                    "stargazers_count": 3100,
                    "forks_count": 210,
                    "updated_at": "2026-02-02",
                    "repo_url": "https://github.com/amlweems/xzbot",
                }
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "poc", "cve-2024-3400", "--limit", "5"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "xzbot" in result.stdout
    mock_sdk.search_poc.assert_awaited_once_with("CVE-2024-3400", limit=5)


def test_search_poc_malformed_cve_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "poc", "CVE-BAD"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_poc.assert_not_awaited()


# -- ccc search vendor ---------------------------------------------------------- #


def test_search_cve_renders_statistics_and_cna_directory(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """The opt-in coverage and CNA layers render even with no CVE matches, and the CNA block is
    labelled as the GLOBAL directory (not the CNA that assigned a filtered CVE)."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response(
        {
            "results": [],
            "statistics": {
                "cve_total_count": 450284,
                "latest_cve": "CVE-2026-90461",
                "cve_modified_since": {"d1": 1333, "d7": 7096, "d30": 20947, "d365": 95137},
            },
            "cnas": [
                {
                    "name": "Apache Software Foundation",
                    "contact_information": "security@apache.org",
                    "identity_id": "identity--74a17a7d",
                }
            ],
            "errors": [],
        }
    )

    result = runner.invoke(
        app, ["search", "cve", "--cve-id", "CVE-2021-44228", "--include", "statistics", "--include", "cna"]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "450284" in result.stdout
    assert "Apache Software Foundation" in result.stdout
    assert "CNA directory" in result.stdout


def test_search_vendor_renders_products(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_vendor.return_value = _stub_response(
        {
            "vendor": "apache",
            # `total_products` counts DISTINCT products while `products` holds one row per CPE
            # entry — the header must name both units, never render "2 of 3" as a ratio.
            "total_products": 2,
            "products": [
                {
                    "product": "http_server",
                    "version": "2.4.51",
                    "cpe": "cpe:2.3:a:apache:http_server:2.4.51",
                    "title": "Apache HTTP Server 2.4.51",
                },
                {
                    "product": "http_server",
                    "version": "2.4.50",
                    "cpe": "cpe:2.3:a:apache:http_server:2.4.50",
                    "title": "Apache HTTP Server 2.4.50",
                },
                {
                    "product": "tomcat",
                    "version": "9.0.1",
                    "cpe": "cpe:2.3:a:apache:tomcat:9.0.1",
                    "title": "Apache Tomcat 9.0.1",
                },
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "vendor", "apache"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "http_server" in result.stdout
    assert "2 products · 3 rows" in result.stdout
    mock_sdk.search_vendor.assert_awaited_once_with("apache", q=None, limit=50)


def test_search_vendor_directory_mode_lists_vendors(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Omitting VENDOR browses the vendor directory (`--q` filters it)."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_vendor.return_value = _stub_response(
        {
            "vendor": None,
            "vendors": [{"vendor": "07fly", "products_count": 2, "softwares_count": 20}],
            "total_vendors": 1,
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "vendor", "--q", "micro"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "07fly" in result.stdout
    mock_sdk.search_vendor.assert_awaited_once_with(None, q="micro", limit=50)


def test_search_vendor_blank_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search", "vendor", "  "])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_vendor.assert_not_awaited()


# -- ccc search techniques (grouped spelling of the deprecated alias) ----------- #


def test_search_techniques_grouped_spelling(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_techniques.return_value = _stub_response(
        {"results": [{"_source": "attack", "attack_id": "T1003", "name": "OS Credential Dumping"}], "errors": []}
    )

    result = runner.invoke(app, ["search", "techniques", "credential dumping", "--limit", "7"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "T1003" in result.stdout
    mock_sdk.search_techniques.assert_awaited_once_with("credential dumping", limit=7)


def test_deprecated_alias_still_resolves(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``ccc search-techniques`` shipped in v4.0.0 — it must keep working."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_techniques.return_value = _stub_response({"results": [], "errors": []})

    result = runner.invoke(app, ["search-techniques", "phishing"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.search_techniques.assert_awaited_once_with("phishing", limit=20)


def test_deprecated_alias_help_says_deprecated(runner: CliRunner) -> None:
    result = runner.invoke(app, ["search-techniques", "--help"])

    assert result.exit_code == 0
    assert "deprecated" in result.stdout.lower()
    assert "search techniques" in result.stdout.replace("\n", " ")


# -- shared error paths --------------------------------------------------------- #


def test_search_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["search", "vendor", "apache"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.search_vendor.assert_not_awaited()


def test_search_api_error_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_poc.side_effect = UnexpectedStatus(429, b'{"detail":"rate limited"}', None)

    result = runner.invoke(app, ["--json", "search", "poc", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 429
    assert payload["body"] == {"detail": "rate limited"}


# -- ccc search csaf ------------------------------------------------------------ #

_CSAF_PAYLOAD = {
    "advisories": [
        {
            "tracking_id": "ICSA-26-288-01",
            "publisher_name": "CISA",
            "advisory_kind": "coordinator",
            "affected_models": ["6GK6242-6PA00"],
            "remediations": [{"category": "vendor_fix", "details": "Update to V4.0"}],
            "tlp_label": "CLEAR",
            "cve_ids": ["CVE-2026-97851"],
            "sectors": ["Water and Wastewater"],
            "current_release_date": "2026-10-14T00:00:00",
            "title": "Siemens SIMATIC HMI",
        },
        {
            "tracking_id": "SSA-2026-10",
            "publisher_name": "Siemens",
            "advisory_kind": "vendor",
            "affected_models": [],
            "remediations": [],
            "tlp_label": "WHITE",
            "cve_ids": [],
            "sectors": [],
            "current_release_date": "2026-10-10T00:00:00",
            "title": "CVE-less product note",
        },
    ],
    "total": 2,
    "errors": [],
}


def test_csaf_command(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_csaf.return_value = _stub_response(_CSAF_PAYLOAD)

    result = runner.invoke(app, ["search", "csaf", "--publisher", "Siemens"])

    assert result.exit_code == 0, result.output
    assert "ICSA-26-288-01" in result.output
    assert "SSA-2026-10" in result.output
    assert "2 of 2" in result.output
    assert "coordinator" in result.output and "vendor" in result.output
    mock_sdk.search_csaf.assert_called_once_with(
        cve_id=None,
        advisory_id=None,
        publisher="Siemens",
        sector=None,
        product=None,
        cpe=None,
        tlp=None,
        sort="newest",
        limit=20,
        page=1,
    )


def test_csaf_command_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_csaf.return_value = _stub_response(_CSAF_PAYLOAD)

    result = runner.invoke(app, ["search", "csaf", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["advisories"][1]["tracking_id"] == "SSA-2026-10"


def test_csaf_null_tlp_renders_blank_not_none(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """A document that states no TLP carries a null label (migration 031).

    The table shows a blank cell there, never the text 'None'."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {
        "advisories": [
            {
                "tracking_id": "NOTLP-26-01",
                "publisher_name": "Cisco",
                "advisory_kind": "vendor",
                "affected_models": [],
                "remediations": [],
                "tlp_label": None,
                "cve_ids": [],
                "sectors": [],
                "current_release_date": "2026-10-12T00:00:00",
                "title": "Advisory with no TLP statement",
            }
        ],
        "total": 1,
        "errors": [],
    }
    mock_sdk.search_csaf.return_value = _stub_response(payload)

    result = runner.invoke(app, ["search", "csaf"])

    assert result.exit_code == 0, result.output
    assert "NOTLP-26-01" in result.output
    assert "None" not in result.output
