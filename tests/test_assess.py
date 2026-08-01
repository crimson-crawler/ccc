"""End-to-end tests for the ``ccc assess`` sub-app.

Four commands over the ``/v1/assess/*`` portfolio endpoints. The interesting
surface is the local input handling — indicator type inference, SSVC
``--stakeholder KEY=VALUE`` validation, variadic id checks, and the 50-entry caps
— all of which must exit ``64`` before any billable request.
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


# -- ccc assess group-exposure -------------------------------------------------- #

_GROUP_EXPOSURE = {
    "groups": [{"group_id": "G0016", "name": "APT29"}, {"group_id": "G0007", "name": "APT28"}],
    "techniques": [{"technique_id": "T1566", "name": "Phishing", "tactics": ["initial-access"]}],
    "overlap_analysis": {
        "shared_count": 14,
        "combined_unique": 61,
        "shared_tactics": ["initial-access", "execution"],
    },
    "cves": [{"cve_id": "CVE-2000-0001"}],
    "predictions": [{"technique_id": "T1059", "probability": 0.7, "name": "Command and Scripting"}],
    "errors": [],
}


def test_group_exposure_renders_overlap(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_group_exposure.return_value = _stub_response(_GROUP_EXPOSURE)

    result = runner.invoke(app, ["assess", "group-exposure", "--group-id", "G0016", "--group-id", "G0007"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "APT29" in result.stdout
    assert "T1566" in result.stdout  # the shared linked-techniques sub-table
    kwargs = mock_sdk.assess_group_exposure.call_args.kwargs
    assert kwargs["group_ids"] == ["G0016", "G0007"]
    assert kwargs["search"] is None
    assert kwargs["framework"] == "enterprise"
    assert kwargs["include"] is None


def test_group_exposure_search_and_include(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_group_exposure.return_value = _stub_response(_GROUP_EXPOSURE)

    result = runner.invoke(
        app,
        [
            "assess",
            "group-exposure",
            "--search",
            "APT28",
            "--search",
            "Sandworm",
            "--framework",
            "ics",
            "--include",
            "details",
            "--include",
            "tie",
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    kwargs = mock_sdk.assess_group_exposure.call_args.kwargs
    assert kwargs["group_ids"] is None
    assert kwargs["search"] == ["APT28", "Sandworm"]
    assert kwargs["framework"] == "ics"
    assert kwargs["include"] == ["details", "tie"]


def test_group_exposure_lowercase_ids_normalised(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_group_exposure.return_value = _stub_response(_GROUP_EXPOSURE)

    result = runner.invoke(app, ["assess", "group-exposure", "--group-id", "g0016"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.assess_group_exposure.call_args.kwargs["group_ids"] == ["G0016"]


def test_group_exposure_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_group_exposure.return_value = _stub_response(_GROUP_EXPOSURE)

    result = runner.invoke(app, ["--json", "assess", "group-exposure", "--group-id", "G0016"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _GROUP_EXPOSURE


def test_group_exposure_requires_a_selector_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "group-exposure"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_group_exposure.assert_not_awaited()


def test_group_exposure_malformed_group_id_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "group-exposure", "--group-id", "APT29"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_group_exposure.assert_not_awaited()


def test_group_exposure_empty_response_reports_no_data(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_group_exposure.return_value = _stub_response({"groups": [], "techniques": [], "errors": []})

    result = runner.invoke(app, ["assess", "group-exposure", "--group-id", "G0016"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "No data found" in result.stdout


# -- ccc assess ioc-portfolio --------------------------------------------------- #

_IOC_PORTFOLIO = {
    "indicators_assessed": 3,
    "misp_attributes": [{"type": "ip-dst", "value": "203.0.113.7"}],
    "misp_events": [{"id": "42"}],
    "total_sightings": 9,
    "techniques": [{"technique_id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"]}],
    "groups": [{"group_id": "G0016", "name": "APT29"}],
    "errors": [],
}


def test_ioc_portfolio_infers_types_from_shape(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_ioc_portfolio.return_value = _stub_response(_IOC_PORTFOLIO)

    result = runner.invoke(
        app,
        [
            "assess",
            "ioc-portfolio",
            "--ioc",
            "203.0.113.7",
            "--ioc",
            "evil.example",
            "--ioc",
            "https://evil.example/payload?a=b",
            "--ioc",
            "d41d8cd98f00b204e9800998ecf8427e",
            "--ioc",
            "a" * 40,
            "--ioc",
            "b" * 64,
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    # The rollup renders counts, not raw indicator values — the detail is in --json.
    assert "Indicators assessed" in result.stdout
    assert "T1071" in result.stdout
    indicators = mock_sdk.assess_ioc_portfolio.call_args.args[0]
    assert [item["type"] for item in indicators] == ["ip-dst", "domain", "url", "md5", "sha1", "sha256"]
    # The URL's query-string "=" must not be mistaken for a TYPE= prefix.
    assert indicators[2]["value"] == "https://evil.example/payload?a=b"


def test_ioc_portfolio_explicit_type_prefix(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_ioc_portfolio.return_value = _stub_response(_IOC_PORTFOLIO)

    result = runner.invoke(
        app, ["assess", "ioc-portfolio", "--ioc", "hostname=intranet", "--ioc", "ip-src=203.0.113.9"]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.assess_ioc_portfolio.call_args.args[0] == [
        {"value": "intranet", "type": "hostname"},
        {"value": "203.0.113.9", "type": "ip-src"},
    ]


def test_ioc_portfolio_from_file(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_ioc_portfolio.return_value = _stub_response(_IOC_PORTFOLIO)
    payload = tmp_path / "iocs.json"
    payload.write_text(json.dumps([{"value": "evil.example", "type": "domain"}]), encoding="utf-8")

    result = runner.invoke(app, ["assess", "ioc-portfolio", "--file", str(payload), "--include", "techniques"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.assess_ioc_portfolio.call_args.args[0] == [{"value": "evil.example", "type": "domain"}]
    assert mock_sdk.assess_ioc_portfolio.call_args.kwargs["include"] == ["techniques"]


def test_ioc_portfolio_file_entry_without_type_is_inferred(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_ioc_portfolio.return_value = _stub_response(_IOC_PORTFOLIO)
    payload = tmp_path / "iocs.json"
    payload.write_text(json.dumps([{"value": "203.0.113.7"}]), encoding="utf-8")

    result = runner.invoke(app, ["assess", "ioc-portfolio", "--file", str(payload)])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.assess_ioc_portfolio.call_args.args[0] == [{"value": "203.0.113.7", "type": "ip-dst"}]


def test_ioc_portfolio_uninferable_value_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """A bare token with no recognisable shape must be rejected, not guessed at."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "ioc-portfolio", "--ioc", "intranet"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_ioc_portfolio.assert_not_awaited()


def test_ioc_portfolio_no_indicators_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "ioc-portfolio"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_ioc_portfolio.assert_not_awaited()


def test_ioc_portfolio_over_fifty_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = tmp_path / "iocs.json"
    payload.write_text(json.dumps([{"value": f"10.0.0.{n}", "type": "ip-dst"} for n in range(51)]), encoding="utf-8")

    result = runner.invoke(app, ["assess", "ioc-portfolio", "--file", str(payload)])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_ioc_portfolio.assert_not_awaited()


# -- ccc assess technique-coverage ---------------------------------------------- #

_COVERAGE = {
    "techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing App", "tactics": ["initial-access"]}],
    "coverage_score": {
        "total_techniques": 2,
        "mitigated_count": 1,
        "mitigation_pct": 50.0,
        "detected_count": 2,
        "detection_pct": 100.0,
        "uncovered_techniques": ["T1059.001"],
    },
    "priority_gaps": [
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "gap_score": 0.81,
            "top_tactic": "execution",
            "has_kev_cves": True,
            "reason": "No mitigation mapped.",
        }
    ],
    "errors": [],
}


def test_technique_coverage_renders_score_and_gaps(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_technique_coverage.return_value = _stub_response(_COVERAGE)

    result = runner.invoke(app, ["assess", "technique-coverage", "T1190", "T1059.001"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "PowerShell" in result.stdout
    assert "50.0" in result.stdout
    args, kwargs = mock_sdk.assess_technique_coverage.call_args
    assert args == (["T1190", "T1059.001"],)
    assert kwargs["framework"] == "enterprise"


def test_technique_coverage_normalises_and_forwards_framework(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_technique_coverage.return_value = _stub_response(_COVERAGE)

    result = runner.invoke(app, ["assess", "technique-coverage", "t1190", "--framework", "mobile"])

    assert result.exit_code == 0, result.stdout + result.stderr
    args, kwargs = mock_sdk.assess_technique_coverage.call_args
    assert args == (["T1190"],)
    assert kwargs["framework"] == "mobile"


def test_technique_coverage_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_technique_coverage.return_value = _stub_response(_COVERAGE)

    result = runner.invoke(app, ["--json", "assess", "technique-coverage", "T1190"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _COVERAGE


def test_technique_coverage_malformed_id_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "technique-coverage", "T1190", "NOPE"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_technique_coverage.assert_not_awaited()


def test_technique_coverage_requires_at_least_one_id(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "technique-coverage"])

    assert result.exit_code != 0
    mock_sdk.assess_technique_coverage.assert_not_awaited()


# -- ccc assess vulnerability-exposure ------------------------------------------ #

_EXPOSURE = {
    "cves": [{"cve_id": "CVE-2000-0001", "cvss_score": 9.8}],
    "kev_entries": [{"cve_id": "CVE-2000-0001"}],
    "max_weaponization_score": 91,
    "avg_weaponization_score": 74,
    "likely_tactics": ["initial-access"],
    "techniques": [{"technique_id": "T1190"}],
    "prioritized_remediation": [
        {
            "cve_id": "CVE-2000-0001",
            "priority_rank": 1,
            "adjusted_priority_score": 0.94,
            "effort": "low",
            "reason": "KEV-listed with a public exploit.",
        }
    ],
    "errors": [],
}


def test_vulnerability_exposure_renders_remediation(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_vulnerability_exposure.return_value = _stub_response(_EXPOSURE)

    result = runner.invoke(app, ["assess", "vulnerability-exposure", "CVE-2000-0001", "CVE-2000-0002"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "KEV-listed" in result.stdout
    args, kwargs = mock_sdk.assess_vulnerability_exposure.call_args
    assert args == (["CVE-2000-0001", "CVE-2000-0002"],)
    assert kwargs["stakeholder"] is None


def test_vulnerability_exposure_stakeholder_profile(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_vulnerability_exposure.return_value = _stub_response(_EXPOSURE)

    result = runner.invoke(
        app,
        [
            "assess",
            "vulnerability-exposure",
            "CVE-2000-0001",
            "--stakeholder",
            "exposure=open",
            "--stakeholder",
            "human_impact=very_high",
        ],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.assess_vulnerability_exposure.call_args.kwargs["stakeholder"] == {
        "exposure": "open",
        "human_impact": "very_high",
    }


@pytest.mark.parametrize("pair", ["nonsense=open", "exposure=enormous", "exposure"])
def test_vulnerability_exposure_bad_stakeholder_exits_64(
    pair: str, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "vulnerability-exposure", "CVE-2000-0001", "--stakeholder", pair])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_vulnerability_exposure.assert_not_awaited()


def test_vulnerability_exposure_malformed_cve_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["assess", "vulnerability-exposure", "CVE-2000-0001", "CVE-BAD"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.assess_vulnerability_exposure.assert_not_awaited()


def test_vulnerability_exposure_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_vulnerability_exposure.return_value = _stub_response(_EXPOSURE)

    result = runner.invoke(app, ["--json", "assess", "vulnerability-exposure", "cve-2000-0001"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _EXPOSURE
    assert mock_sdk.assess_vulnerability_exposure.call_args.args == (["CVE-2000-0001"],)


# -- shared error paths --------------------------------------------------------- #


def test_assess_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["assess", "technique-coverage", "T1190"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.assess_technique_coverage.assert_not_awaited()


def test_assess_api_error_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.assess_ioc_portfolio.side_effect = UnexpectedStatus(500, b"upstream exploded", None)

    result = runner.invoke(app, ["--json", "assess", "ioc-portfolio", "--ioc", "203.0.113.7"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 500
    assert payload["body"] == "upstream exploded"
