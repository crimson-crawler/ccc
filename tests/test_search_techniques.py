"""End-to-end tests for ``ccc search-techniques``.

The command now calls the SDK's :meth:`CrawlerClient.search_techniques`
convenience method (not the raw ``search_cti`` endpoint), so these tests
configure ``mock_sdk.search_techniques`` directly. The wrapper owns the
``sources``/``types`` scoping and the enum-not-string serialisation, so the
old raw-request assertions are gone — they live in the SDK wrapper suite
(`crimson-crawler-client`'s test suite) and the CLI integration suite.
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


def _stub_response(results: list[dict]) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = {"results": results, "errors": []}
    return response


def test_search_techniques_happy_path_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_techniques.return_value = _stub_response(
        [
            {
                "_source": "attack",
                "attack_id": "T1003",
                "name": "OS Credential Dumping",
                "description": "Adversaries dump credentials …",
                "relevance_score": 0.91,
            }
        ]
    )

    result = runner.invoke(app, ["search-techniques", "credential dumping"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "T1003" in result.stdout
    mock_sdk.search_techniques.assert_awaited_once_with("credential dumping", limit=20)


def test_search_techniques_limit_flag(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_techniques.return_value = _stub_response([])

    result = runner.invoke(app, ["search-techniques", "phishing", "--limit", "5"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.search_techniques.assert_awaited_once_with("phishing", limit=5)


def test_search_techniques_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    results = [{"_source": "attack", "attack_id": "T1059", "name": "Command"}]
    mock_sdk.search_techniques.return_value = _stub_response(results)

    result = runner.invoke(app, ["--json", "search-techniques", "command"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"results": results, "errors": []}


def test_search_techniques_empty_keyword_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search-techniques", "   "])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.search_techniques.assert_not_awaited()


def test_search_techniques_missing_credentials(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["search-techniques", "phishing"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.search_techniques.assert_not_awaited()


def test_search_techniques_api_error_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.search_techniques.side_effect = UnexpectedStatus(422, b'{"detail":"missing query"}', None)

    result = runner.invoke(app, ["--json", "search-techniques", "phishing"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 422
    assert payload["body"] == {"detail": "missing query"}


def test_search_techniques_limit_out_of_range_exits_nonzero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["search-techniques", "phishing", "--limit", "101"])

    assert result.exit_code != 0
