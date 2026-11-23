"""Tests for ``ccc event-enrich`` — mocked SDK ``client.enricher.enrich_event``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode

_EVENT = '{"alertId":"abc-123","title":"Suspicious PowerShell","cve":"CVE-2024-3400"}'

_RESULT = {
    "enrichment_id": "abc123",
    "result": {
        "event_id": "ev-1",
        "event": _EVENT,
        "extracted_count": 2,
        "threat_assessment": {
            "verdict": "critical",
            "score": None,
            "indicator_count": 2,
            "counts_by_type": {"cve": 1, "ioc": 1},
            "kev_count": 1,
            "weaponized_count": 1,
            "max_weaponization": 90.0,
        },
        "indicators": [
            {
                "type": "cve",
                "value": "CVE-2024-3400",
                "ioc_type": None,
                "status": "ok",
                "verdict": "critical",
                "score": 90.0,
                "kev": True,
                "weaponized": True,
                "enrichment": {},
                "errors": [],
            },
            {
                "type": "ioc",
                "value": "185.220.101.5",
                "ioc_type": "ip-dst",
                "status": "ok",
                "verdict": "high",
                "score": 0.8,
                "kev": False,
                "enrichment": {},
                "errors": [],
            },
        ],
        "techniques": [{"technique_id": "T1059.001"}],
        "errors": [],
    },
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_event_enrich_text_summary(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich_event.return_value = _RESULT

    result = runner.invoke(app, ["event-enrich", "--event", _EVENT, "--event-id", "ev-1"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "abc123" in result.stdout
    assert "CRITICAL" in result.stdout
    assert "CVE-2024-3400" in result.stdout
    assert "185.220.101.5" in result.stdout
    assert "Metasploit module" in result.stdout
    assert "KEV · Metasploit" in result.stdout
    assert "EV-1" in result.stdout or "ev-1" in result.stdout
    mock_sdk.enricher.enrich_event.assert_awaited_once()
    _, kwargs = mock_sdk.enricher.enrich_event.call_args
    assert kwargs["event"] == _EVENT
    assert kwargs["event_id"] == "ev-1"


def test_event_enrich_event_file(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich_event.return_value = _RESULT
    event_file = tmp_path / "alert.json"
    event_file.write_text(_EVENT, encoding="utf-8")

    result = runner.invoke(app, ["event-enrich", "--event-file", str(event_file)])

    assert result.exit_code == 0, result.stdout + result.stderr
    _, kwargs = mock_sdk.enricher.enrich_event.call_args
    assert kwargs["event"] == _EVENT
    assert kwargs["event_id"] is None


def test_event_enrich_output_json_file(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich_event.return_value = _RESULT
    out = tmp_path / "event.json"

    result = runner.invoke(app, ["event-enrich", "--event", _EVENT, "--output", str(out)])

    assert result.exit_code == 0, result.stdout + result.stderr
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["enrichment_id"] == "abc123"
    assert written["result"]["threat_assessment"]["verdict"] == "critical"


def test_event_enrich_requires_event(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    result = runner.invoke(app, ["event-enrich"])
    assert result.exit_code == ExitCode.BAD_INPUT.value
    mock_sdk.enricher.enrich_event.assert_not_awaited()


def test_event_enrich_refuses_oversized_event_before_billing(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    """An event over the engine's 200k-char cap exits 64 locally — never truncated, never submitted."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    big = tmp_path / "big.log"
    big.write_text("x" * 200_001, encoding="utf-8")

    result = runner.invoke(app, ["event-enrich", "--event-file", str(big)])

    assert result.exit_code == ExitCode.BAD_INPUT.value
    assert "200,000" in result.stderr + result.stdout
    mock_sdk.enricher.enrich_event.assert_not_awaited()


def test_event_enrich_status(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    from unittest.mock import MagicMock

    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    stub = MagicMock()
    stub.to_dict.return_value = {"status": "done", "progress": 1.0, "stages": []}
    mock_sdk.event_enrich_status.return_value = stub

    result = runner.invoke(app, ["event-enrich", "status", "abc123"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "done" in result.stdout
    mock_sdk.event_enrich_status.assert_awaited_once_with("abc123")


def test_event_enrich_status_requires_id(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    result = runner.invoke(app, ["event-enrich", "status"])
    assert result.exit_code != 0  # typer missing-arg usage error
