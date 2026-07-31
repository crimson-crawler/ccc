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
from crimson_crawler_client import UnexpectedStatus
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


# -- ccc search cve ------------------------------------------------------------- #

_CVE_RESULTS = {
    "results": [
        {
            "cve_id": "CVE-2024-3400",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
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
            "search", "cve",
            "--cwe-id", "CWE-79",
            "--attack-id", "T1190",
            "--capec-id", "CAPEC-66",
            "--cpe", "cpe:2.3:a:apache:http_server",
            "--cvss-min", "7.5",
            "--epss-min", "0.5",
            "--kev-only",
            "--vuln-status", "Analyzed",
            "--sort", "epss_score_descending",
            "--include", "details",
            "--include", "kev",
            "--limit", "10",
            "--page", "3",
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


def test_search_cve_empty_results_reports_no_data(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_cve.return_value = _stub_response({"results": [], "errors": []})

    result = runner.invoke(app, ["search", "cve", "nothing matches this"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "No data found" in result.stdout


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
        ["search", "knowledgebase", "kerberoasting", "--collection", "red_team", "--collection", "main",
         "--alpha", "0.3", "--limit", "5"],
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
                {"id": "42", "date": "2026-01-04", "org": "CIRCL", "threat_level_id": "2",
                 "attribute_count": 17, "info": "Botnet C2 sightings"}
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "misp", "203.0.113.7"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "203.0.113.7" in result.stdout
    assert "Botnet C2 sightings" in result.stdout
    assert mock_sdk.search_misp.call_args.kwargs["value"] == "203.0.113.7"


def test_search_misp_filter_only_call(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_misp.return_value = _stub_response({"attributes": [], "events": [], "errors": []})

    result = runner.invoke(
        app,
        ["search", "misp", "--type", "domain", "--tag", "tlp:green", "--tag", "apt",
         "--date-from", "2026-01-01", "--no-published", "--to-ids", "--threat-level", "1"],
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


def test_search_vendor_renders_products(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_vendor.return_value = _stub_response(
        {
            "vendor": "apache",
            "total_products": 240,
            "products": [
                {"product": "http_server", "version": "2.4.51", "cpe": "cpe:2.3:a:apache:http_server:2.4.51",
                 "title": "Apache HTTP Server 2.4.51"}
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["search", "vendor", "apache"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "http_server" in result.stdout
    mock_sdk.search_vendor.assert_awaited_once_with("apache", limit=50)


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
