"""Tests for ``ccc inventory-enrich`` (submit) and ``ccc inventory-enrich status ID``.

The submit is a pure ``202`` acknowledgement — it maps 1:1 to
``POST /v1/inventory-enrich`` and deliberately does not poll (``ccc ingest``
covers the poll-to-briefing path). Both commands live on a Typer group whose
callback is the submit, so the bare-group and subcommand dispatch are pinned
here too.
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

_SUBMIT = {"enrichment_id": "inv-abc123", "status": "queued"}

_JOB = {
    "enrichment_id": "inv-abc123",
    "status": "running",
    "progress": 42.5,
    "queue_position": 2,
    "created_at": "2026-07-26T10:00:00Z",
    "updated_at": "2026-07-26T10:00:30Z",
    "stages": [
        {"key": "parse", "label": "Parsing assets", "status": "done", "progress": 100},
        {"key": "enrich", "label": "Enriching CVEs", "status": "running", "progress": 30, "detail": "12 of 40"},
    ],
    "result": None,
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


# -- submit --------------------------------------------------------------------- #


def test_inventory_enrich_product_shorthand(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``[vendor/]name[@version]`` — the same shorthand ``ccc enrich product`` takes."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich.return_value = _stub_response(_SUBMIT)

    result = runner.invoke(
        app,
        ["inventory-enrich", "--product", "nginx", "--product", "nginx@1.24.0", "--product", "apache/httpd@2.4.51"],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "inv-abc123" in result.stdout
    assert mock_sdk.inventory_enrich.call_args.args[0] == [
        {"product": "nginx"},
        {"product": "nginx", "version": "1.24.0"},
        {"product": "httpd", "vendor": "apache", "version": "2.4.51"},
    ]


def test_inventory_enrich_prints_the_poll_command(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """The submit doesn't poll, so it must name the command that does."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich.return_value = _stub_response(_SUBMIT)

    result = runner.invoke(app, ["inventory-enrich", "--product", "nginx"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "ccc inventory-enrich status" in result.stdout.replace("\n", "")


def test_inventory_enrich_from_file_with_full_asset_fields(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich.return_value = _stub_response(_SUBMIT)
    asset = {"product": "django", "ecosystem": "PyPI", "version": "4.2", "criticality": "high"}
    items = tmp_path / "assets.json"
    items.write_text(json.dumps({"items": [asset]}), encoding="utf-8")

    result = runner.invoke(
        app, ["inventory-enrich", "--file", str(items), "--include", "kev", "--attachments-text", "ticket context"]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    args, kwargs = mock_sdk.inventory_enrich.call_args
    assert args[0] == [asset]
    assert kwargs["include"] == ["kev"]
    assert kwargs["attachments_text"] == "ticket context"


def test_inventory_enrich_file_and_products_combine(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich.return_value = _stub_response(_SUBMIT)
    items = tmp_path / "assets.json"
    items.write_text(json.dumps([{"product": "django"}]), encoding="utf-8")

    result = runner.invoke(app, ["inventory-enrich", "--file", str(items), "--product", "nginx"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.inventory_enrich.call_args.args[0] == [{"product": "django"}, {"product": "nginx"}]


def test_inventory_enrich_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich.return_value = _stub_response(_SUBMIT)

    result = runner.invoke(app, ["--json", "inventory-enrich", "--product", "nginx"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _SUBMIT


def test_inventory_enrich_no_assets_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["inventory-enrich"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.inventory_enrich.assert_not_awaited()


def test_inventory_enrich_asset_without_product_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    items = tmp_path / "assets.json"
    items.write_text(json.dumps([{"vendor": "apache"}]), encoding="utf-8")

    result = runner.invoke(app, ["inventory-enrich", "--file", str(items)])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.inventory_enrich.assert_not_awaited()


def test_inventory_enrich_invalid_json_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    items = tmp_path / "assets.json"
    items.write_text("{not json", encoding="utf-8")

    result = runner.invoke(app, ["inventory-enrich", "--file", str(items)])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.inventory_enrich.assert_not_awaited()


@pytest.mark.parametrize("token", ["@1.2.3", "apache/", "  "])
def test_inventory_enrich_malformed_product_exits_64(
    token: str, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["inventory-enrich", "--product", token])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.inventory_enrich.assert_not_awaited()


def test_inventory_enrich_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["inventory-enrich", "--product", "nginx"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.inventory_enrich.assert_not_awaited()


# -- status --------------------------------------------------------------------- #


def test_inventory_enrich_status_renders_job(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich_status.return_value = _stub_response(_JOB)

    result = runner.invoke(app, ["inventory-enrich", "status", "inv-abc123"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "42.5%" in result.stdout
    assert "Enriching CVEs" in result.stdout
    assert "pending" in result.stdout  # result not ready yet
    mock_sdk.inventory_enrich_status.assert_awaited_once_with("inv-abc123")
    mock_sdk.inventory_enrich.assert_not_awaited()  # `status` must not re-submit


def test_inventory_enrich_status_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich_status.return_value = _stub_response(_JOB)

    result = runner.invoke(app, ["--json", "inventory-enrich", "status", "inv-abc123"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _JOB


def test_inventory_enrich_status_reports_failure_detail(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich_status.return_value = _stub_response(
        {**_JOB, "status": "failed", "error": {"step": "enrich", "service": "ctibutler", "error": "timeout"}}
    )

    result = runner.invoke(app, ["inventory-enrich", "status", "inv-abc123"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "timeout" in result.stdout


def test_inventory_enrich_status_api_error_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.inventory_enrich_status.side_effect = UnexpectedStatus(404, b'{"detail":"unknown id"}', None)

    result = runner.invoke(app, ["--json", "inventory-enrich", "status", "nope"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert json.loads(result.stderr)["status"] == 404


# -- artifact-enrich status (same job envelope, other engine) -------------------- #


def test_artifact_enrich_status_renders_job(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.artifact_enrich_status.return_value = _stub_response(
        {**_JOB, "enrichment_id": "art-xyz", "status": "done", "progress": 100, "result": {"grade": "B"}}
    )

    result = runner.invoke(app, ["artifact-enrich", "status", "art-xyz"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "art-xyz" in result.stdout
    assert "ready" in result.stdout  # the report is available
    mock_sdk.artifact_enrich_status.assert_awaited_once_with("art-xyz")
    mock_sdk.enricher.enrich.assert_not_awaited()  # `status` must not submit


def test_artifact_enrich_status_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {**_JOB, "enrichment_id": "art-xyz"}
    mock_sdk.artifact_enrich_status.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "artifact-enrich", "status", "art-xyz"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_artifact_enrich_bare_group_still_submits(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Turning ``artifact-enrich`` into a group must not change its bare behaviour."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enricher.enrich.return_value = {"enrichment_id": "art-1", "report": {"summary": {}}}

    result = runner.invoke(app, ["artifact-enrich", "--text", "suspicious login"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "art-1" in result.stdout
    mock_sdk.enricher.enrich.assert_awaited_once()
    mock_sdk.artifact_enrich_status.assert_not_awaited()
