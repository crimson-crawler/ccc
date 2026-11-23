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
        text="Suspicious login from 10.1.1.1",
        files=None,
        attached_artifact_ids=None,
        include=None,
        on_progress=ANY,
        save=False,
        tlp=None,
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
    mock_sdk.enricher.enrich.assert_awaited_once_with(
        text="x", files=None, attached_artifact_ids=None, include=None, on_progress=ANY, save=True, tlp=None
    )


def test_artifact_enrich_tlp_flag_canonicalised(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = _REPORT

    result = runner.invoke(app, ["artifact-enrich", "--text", "x", "--tlp", "amber"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.enricher.enrich.call_args.kwargs["tlp"] == "AMBER"


def test_artifact_enrich_invalid_tlp_is_a_usage_error_before_the_submit(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["artifact-enrich", "--text", "x", "--tlp", "WHITE"])

    assert result.exit_code == ExitCode.BAD_INPUT  # usage errors are 64 here, not Click's 2
    # The usage error lists the canonical UPPERCASE spellings, not casefolded ones.
    # Flatten Rich's panel borders/line wrap before matching the list.
    assert "'CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'" in " ".join(result.output.replace("│", " ").split())
    mock_sdk.enricher.enrich.assert_not_awaited()


def test_artifact_enrich_shows_exploit_evidence_and_threat_context(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    # Report schema 2.2: KEV-listed CVEs sort first; Metasploit rank, EPSS percentile, and fix render per CVE;
    # a sector reports its targeting-actor count; the two rollups' forecasts merge, highest probability first.
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = {
        "enrichment_id": "x1",
        "report": {
            "references": [
                {"type": "cve", "value": "CVE-2000-0002", "score": 90, "epss": 0.2},
                {
                    "type": "cve",
                    "value": "CVE-2000-0001",
                    "kev_due_date": "2026-01-01",
                    "epss": 0.97,
                    "epss_percentile": 0.999,
                    "metasploit_modules": [{"rank_label": "Excellent"}],
                    "fixed_versions": ["2.15.0"],
                },
                {
                    "type": "sector",
                    "value": "health",
                    "sector": {"name": "Health"},
                    "threat_actors_targeting": ["APT41", "APT9"],
                },
            ],
            "rollups": {
                "technique_coverage": {"predictions": [{"technique_id": "T1036", "probability": 0.17}]},
                "group_exposure": {"predictions": [{"technique_id": "T1055", "probability": 0.3}]},
            },
        },
    }
    result = runner.invoke(app, ["artifact-enrich", "--text", "x"])
    assert result.exit_code == 0, result.stdout + result.stderr
    out = result.stdout
    assert out.index("CVE-2000-0001") < out.index("CVE-2000-0002")
    assert "Excellent" in out and "99.9%" in out and "2.15.0" in out
    assert "Health (sector): targeted by 2 known actors" in out
    assert "Likely next: T1055 30%, T1036 17%" in out
