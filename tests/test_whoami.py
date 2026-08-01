"""End-to-end tests for ``ccc whoami`` via Typer's CLI runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode


@pytest.fixture()
def runner() -> CliRunner:
    # Modern Click separates stderr from stdout on the result automatically.
    return CliRunner()


def test_whoami_with_env_var(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-1234567890abcdef")

    result = runner.invoke(app, ["whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "environment variable" in result.stdout
    assert "cdef" in result.stdout  # key tail visible
    assert "env-key-1234567890ab" not in result.stdout  # full key hidden


def test_whoami_with_config_file(runner: CliRunner, secure_config_file: Path) -> None:
    secure_config_file.write_text('api_key = "cfg-key-9999"\n', encoding="utf-8")

    result = runner.invoke(app, ["whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "config file" in result.stdout
    assert "9999" in result.stdout


def test_whoami_json_output(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-zzzzzzzz1234")

    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "api_key_tail": "1234",
        "api_key_masked": "•" * (len("env-key-zzzzzzzz1234") - 4) + "1234",
        "config_file": None,
        "source": "env",
        "source_detail": "CRIMSON_CRAWLER_API_KEY",
    }


def test_whoami_accepts_trailing_expand(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    """`ccc whoami --expand` is accepted (no-op) for flag parity with --json."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-1234567890abcdef")

    result = runner.invoke(app, ["whoami", "--expand"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "environment variable" in result.stdout


def test_whoami_no_credentials_exits_nonzero(runner: CliRunner, clean_env: Path) -> None:
    result = runner.invoke(app, ["whoami"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    assert "CRIMSON_CRAWLER_API_KEY" in result.stderr


def test_whoami_no_credentials_json_mode(runner: CliRunner, clean_env: Path) -> None:
    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    payload = json.loads(result.stderr)
    assert payload["error"] == "MissingCredentialsError"
    assert "CRIMSON_CRAWLER_API_KEY" in payload["message"]
