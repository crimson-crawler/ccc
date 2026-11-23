"""End-to-end tests for ``ccc whoami`` via Typer's CLI runner."""

from __future__ import annotations

import json
import os
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
        "config_file_status": "absent",
        "config_file_detail": None,
        "source": "env",
        "source_detail": "CRIMSON_CRAWLER_API_KEY",
    }


# #252 — the "Config file" row stats the file itself, independent of which source won.
# Before, it echoed the winning source, so every state below rendered as "not present".


def test_whoami_config_present_but_unused_when_env_wins(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, secure_config_file: Path
) -> None:
    secure_config_file.write_text('api_key = "cfg-key-9999"\n', encoding="utf-8")
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-1234567890abcdef")

    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["source"] == "env"  # precedence unchanged — the env var still wins
    assert payload["api_key_tail"] == "cdef"  # and the file's key was never used
    assert payload["config_file"] == str(secure_config_file)
    assert payload["config_file_status"] == "unused"
    assert payload["config_file_detail"] is None

    table = runner.invoke(app, ["whoami"])
    assert "present but unused" in table.stdout
    assert "not present" not in table.stdout


def test_whoami_config_in_use_reports_in_use(runner: CliRunner, secure_config_file: Path) -> None:
    secure_config_file.write_text('api_key = "cfg-key-9999"\n', encoding="utf-8")

    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["source"] == "config"
    assert payload["config_file"] == str(secure_config_file)
    assert payload["config_file_status"] == "in_use"


@pytest.mark.skipif(os.name != "posix", reason="the permission refusal is posix-only")
def test_whoami_reports_a_refused_config_even_when_env_wins(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, secure_config_file: Path
) -> None:
    """The damaging case from #252: the file is broken, the env var masks it, and the
    only diagnostic command used to say "not present" and exit 0. It still exits 0 — the
    key DID resolve — but the row now says why the file was skipped, with the fix."""
    secure_config_file.write_text('api_key = "cfg-key-9999"\n', encoding="utf-8")
    secure_config_file.chmod(0o644)
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-1234567890abcdef")

    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["source"] == "env"
    assert payload["config_file"] == str(secure_config_file)
    assert payload["config_file_status"] == "refused"
    assert "chmod 600" in payload["config_file_detail"]  # the remediation travels with the state

    table = runner.invoke(app, ["whoami"])
    assert table.exit_code == 0
    assert "REFUSED" in table.stdout
    assert "chmod 600" in table.stdout


@pytest.mark.skipif(os.name != "posix", reason="the permission refusal is posix-only")
def test_whoami_refused_config_with_no_env_is_a_typed_exit_64(runner: CliRunner, secure_config_file: Path) -> None:
    """With the env var unset the loader IS consulted and refuses: that must be a typed
    `ConfigPermissionError` at `BAD_INPUT` (64) with a stable `--json` name — never the
    `InternalError` / exit 1 catch-all #252 reported — and exit 2 stays reserved for "no key"."""
    secure_config_file.write_text('api_key = "cfg-key-9999"\n', encoding="utf-8")
    secure_config_file.chmod(0o644)

    result = runner.invoke(app, ["--json", "whoami"])

    assert result.exit_code == int(ExitCode.BAD_INPUT) == 64
    payload = json.loads(result.stderr)
    assert payload["error"] == "ConfigPermissionError"
    assert "chmod 600" in payload["message"]


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
