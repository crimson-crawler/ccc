"""Tests for ``ccc artifact-enrich`` — mocked SDK ``client.enricher.enrich``."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import ANY

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.commands.enrich_artifact import _FAST_INCLUDE
from crimson_crawler_cli.exceptions import ExitCode

_REPORT = {
    "enrichment_id": "abc123",
    "report": {
        "summary": {"grade": "B", "confidence": 0.82, "bluf": "Two exploitable CVEs found."},
        "references": [
            {"recommended_action": "PATCH"},
            {"recommended_action": "patch"},
            {"recommended_action": "WATCH"},
            {"recommended_action": "INFO"},
        ],
        "prioritized_actions": [{"action": "Patch Apache", "detail": "Upgrade to 2.4.59"}],
        "errors": [],
    },
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# -- happy path ----------------------------------------------------------------- #


def test_artifact_enrich_text_summary(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT

    result = runner.invoke(app, ["artifact-enrich", "--text", "Suspicious login from 10.1.1.1"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "abc123" in result.stdout
    assert "BLUF" in result.stdout
    # action breakdown — two PATCH (case-insensitive), one WATCH, one INFO.
    assert "PATCH 2" in result.stdout
    assert "WATCH 1" in result.stdout
    assert "Patch Apache" in result.stdout
    mock_sdk.enricher.enrich.assert_awaited_once_with(
        text="Suspicious login from 10.1.1.1", files=None, include=None, on_progress=ANY, save=False
    )


# -- file staging --------------------------------------------------------------- #


def test_artifact_enrich_file_base64_encoding(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT
    artifact = tmp_path / "evidence.bin"
    raw = b"\x00\x01binary\xff payload"
    artifact.write_bytes(raw)

    result = runner.invoke(app, ["artifact-enrich", "--file", str(artifact)])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enricher.enrich.assert_awaited_once()
    _, kwargs = mock_sdk.enricher.enrich.call_args
    assert kwargs["text"] is None
    assert kwargs["files"] == [{"filename": "evidence.bin", "content_b64": base64.b64encode(raw).decode("ascii")}]


def test_artifact_enrich_text_and_files_combined(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT
    a = tmp_path / "a.txt"
    a.write_text("alpha")
    b = tmp_path / "b.txt"
    b.write_text("bravo")

    result = runner.invoke(app, ["artifact-enrich", "--text", "context", "--file", str(a), "--file", str(b)])

    assert result.exit_code == 0, result.stdout + result.stderr
    _, kwargs = mock_sdk.enricher.enrich.call_args
    assert kwargs["text"] == "context"
    assert [f["filename"] for f in kwargs["files"]] == ["a.txt", "b.txt"]


# -- depth → include wiring ----------------------------------------------------- #


def test_artifact_enrich_full_depth_uses_engine_default(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Default ``full`` depth passes ``include=None`` → the engine default."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT

    result = runner.invoke(app, ["artifact-enrich", "--text", "hi", "--depth", "full"])

    assert result.exit_code == 0, result.stdout + result.stderr
    _, kwargs = mock_sdk.enricher.enrich.call_args
    assert kwargs["include"] is None


def test_artifact_enrich_fast_depth_include_passthrough(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``--depth fast`` sends the minimal include list to the SDK."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT

    result = runner.invoke(app, ["artifact-enrich", "--text", "hi", "--depth", "fast"])

    assert result.exit_code == 0, result.stdout + result.stderr
    _, kwargs = mock_sdk.enricher.enrich.call_args
    assert kwargs["include"] == _FAST_INCLUDE


# -- output modes --------------------------------------------------------------- #


def test_artifact_enrich_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT

    result = runner.invoke(app, ["artifact-enrich", "--text", "hi", "--json"])

    assert result.exit_code == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data == _REPORT


def test_artifact_enrich_output_file_write(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT
    out = tmp_path / "report.json"

    result = runner.invoke(app, ["artifact-enrich", "--text", "hi", "--output", str(out)])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(out.read_text()) == _REPORT
    assert result.stdout == ""  # report went to the file, not stdout
    # Rich soft-wraps long paths in the confirmation line — collapse before asserting.
    assert str(out) in result.stderr.replace("\n", "")


# -- empty input ---------------------------------------------------------------- #


def test_artifact_enrich_empty_input_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Neither --text nor --file → BadInputError (exit 64) before any SDK call."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["artifact-enrich"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enricher.enrich.assert_not_awaited()


def test_artifact_enrich_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["artifact-enrich", "--text", "hi"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    assert "CRIMSON_CRAWLER_API_KEY" in result.stderr
    mock_sdk.enricher.enrich.assert_not_awaited()


def test_artifact_enrich_save_flag_passes_through_and_shows_id(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = {**_REPORT, "saved": {"enrichment_artifact_id": "art-42"}}

    result = runner.invoke(app, ["artifact-enrich", "--text", "x", "--save"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "art-42" in result.stdout  # the "Saved to library" row
    mock_sdk.enricher.enrich.assert_awaited_once_with(text="x", files=None, include=None, on_progress=ANY, save=True)
