"""End-to-end tests for ``ccc enrich technique`` (formerly ``ccc attack-paths``)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from crimson_crawler_client import UnexpectedStatus, presets
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub(payload: dict) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


def test_technique_happy_path_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub(
        {
            "techniques": [
                {
                    "technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["initial-access"],
                    "platforms": ["Linux", "Windows"],
                    "description": "Adversaries exploit a weakness in an Internet-facing host or system.",
                }
            ],
            "groups": [{"group_id": "G0007", "name": "APT28"}],
            "predictions": [],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "technique", "T1190"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "T1190" in result.stdout
    mock_sdk.enrich_technique_full.assert_awaited_once_with(
        ["T1190"], framework="enterprise", include=[*presets.TECHNIQUE_FULL, "cves"]
    )


def test_technique_framework_flag(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub({"techniques": []})

    result = runner.invoke(app, ["enrich", "technique", "T0866", "--framework", "ics"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_technique_full.assert_awaited_once_with(
        ["T0866"], framework="ics", include=[*presets.TECHNIQUE_FULL, "cves"]
    )


def test_technique_json(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"techniques": [{"technique_id": "T1190"}], "errors": []}
    mock_sdk.enrich_technique_full.return_value = _stub(payload)

    result = runner.invoke(app, ["--json", "enrich", "technique", "T1190"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_technique_malformed_id_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "technique", "not-a-technique"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_technique_full.assert_not_awaited()


def test_technique_missing_credentials(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["enrich", "technique", "T1190"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.enrich_technique_full.assert_not_awaited()


def test_technique_unauthorized_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.side_effect = UnexpectedStatus(401, b'{"detail":"nope"}', None)

    result = runner.invoke(app, ["--json", "enrich", "technique", "T1190"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 401


def test_technique_invalid_framework_exits_nonzero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "technique", "T1190", "--framework", "bogus"])

    # Typer validates choice options before the handler runs → click usage error exit
    assert result.exit_code != 0
    mock_sdk.enrich_technique_full.assert_not_awaited()


def test_technique_renamed_command_enriches_seeded_technique(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """C6: ``ccc enrich technique`` (renamed from ``attack-paths``) enriches a seeded ATT&CK id."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub(
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "cves": []}
    )

    result = runner.invoke(app, ["enrich", "technique", "T1059"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_technique_full.assert_awaited_once_with(
        ["T1059"], framework="enterprise", include=[*presets.TECHNIQUE_FULL, "cves"]
    )
