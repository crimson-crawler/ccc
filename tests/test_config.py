"""Config-file diagnostics for :mod:`crimson_crawler_cli.config`.

The reported failure was ``Error: internal error: Invalid value at line 1
column 25`` — tomllib's parse position escaping through ``handle_errors``'
top-level safety net, naming neither the file, the mistake, nor the fix.
"""

from __future__ import annotations

from pathlib import Path, PosixPath

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import config
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ConfigFileError, ConfigPermissionError, ExitCode

# Deliberately low-entropy AND under 24 characters. Every test below asserts this value
# never reaches the diagnostic, so it only needs to be distinctive - and two export gates
# constrain it from opposite directions: gitleaks' `generic-api-key` fires on entropy, and
# `verify-public-artifacts.py` flags `secret = "<24+ chars>"` regardless of entropy. Do not
# fix a hit here by editing `.gitlab/security/gitleaks-public-clients.toml`: the exporter
# ships that policy into all five client trees, so touching it forces every client to bump.
SECRET = "not-a-real-key"


def test_env_style_config_is_explained(secure_config_file: Path) -> None:
    """The reported bug: a shell/.env line pasted into the TOML config.

    Also pins that the diagnostic quotes the key NAME but never the value —
    the value is the secret, and this message reaches terminals and CI logs.
    """
    secure_config_file.write_text(f"CRIMSON_CRAWLER_API_KEY={SECRET}\n", encoding="utf-8")

    with pytest.raises(ConfigFileError) as exc_info:
        config.load_config_file()

    message = str(exc_info.value)
    assert str(secure_config_file) in message
    assert "shell/.env syntax" in message
    assert config.EXPECTED_SHAPE in message
    assert SECRET not in message


def test_unquoted_value_is_explained(secure_config_file: Path) -> None:
    secure_config_file.write_text(f"api_key = {SECRET}\n", encoding="utf-8")

    with pytest.raises(ConfigFileError) as exc_info:
        config.load_config_file()

    message = str(exc_info.value)
    assert "must be quoted" in message
    assert SECRET not in message


def test_unrecognized_syntax_still_names_the_file_and_fix(secure_config_file: Path) -> None:
    """No shape hint available — the file, the parse detail, and the fix still are.

    Exit ``64``, not ``2``: the key is present and misformatted, so a wrapper
    branching on ``2`` must not prompt for a new one.
    """
    secure_config_file.write_text("[[[not toml at all\n", encoding="utf-8")

    with pytest.raises(ConfigFileError) as exc_info:
        config.load_config_file()

    assert str(secure_config_file) in str(exc_info.value)
    assert config.EXPECTED_SHAPE in str(exc_info.value)
    assert exc_info.value.exit_code == ExitCode.BAD_INPUT


@pytest.mark.skipif(config.os.name != "posix", reason="POSIX ownership and mode checks")
def test_permission_refusal_is_also_a_cli_error(secure_config_file: Path) -> None:
    """Renders as a real CLI error, while staying a ``PermissionError``.

    It printed as ``internal error: Refusing to read …`` for the same reason
    the parse failure did — nothing in the config path raised a ``CLIError``.
    """
    secure_config_file.write_text('api_key = "x"\n', encoding="utf-8")
    secure_config_file.chmod(0o640)

    with pytest.raises(ConfigPermissionError) as exc_info:
        config.load_config_file()

    assert isinstance(exc_info.value, PermissionError)
    assert exc_info.value.exit_code == ExitCode.BAD_INPUT


def test_malformed_config_reaches_the_cli_as_a_clean_error(secure_config_file: Path) -> None:
    """End-to-end through a real command — previously exit 1, "internal error"."""
    secure_config_file.write_text("CRIMSON_CRAWLER_API_KEY=abc123\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["whoami"])

    combined = result.stdout + result.stderr
    assert result.exit_code == ExitCode.BAD_INPUT, combined
    assert "internal error" not in combined


# #252 — `config_file_status()` is the non-raising twin `ccc whoami` uses to stat the file
# independently of `resolve_auth`. It must never raise: `whoami` under a set env var has a
# resolved key and must keep exiting 0 even when the file it did NOT read is broken.


def test_status_absent(clean_env: Path) -> None:
    assert not clean_env.exists()
    assert config.config_file_status() == ("absent", None)


def test_status_present_does_not_parse(secure_config_file: Path) -> None:
    """Presence is a stat, not a parse — a malformed file is still `present`; the loader
    names the mistake at the moment the file is actually used."""
    secure_config_file.write_text("CRIMSON_CRAWLER_API_KEY=abc123\n", encoding="utf-8")
    assert config.config_file_status() == ("present", None)


@pytest.mark.skipif(config.os.name != "posix", reason="POSIX ownership and mode checks")
def test_status_refused_carries_the_loader_remediation(secure_config_file: Path) -> None:
    secure_config_file.write_text('api_key = "x"\n', encoding="utf-8")
    secure_config_file.chmod(0o644)

    status, detail = config.config_file_status()

    assert status == "refused"
    assert detail is not None and "chmod 600" in detail
    # Same text the loader raises — one remediation, two surfaces.
    with pytest.raises(ConfigPermissionError) as exc_info:
        config.load_config_file()
    assert str(exc_info.value) == detail


@pytest.mark.skipif(config.os.name != "posix", reason="PosixPath base")
def test_status_refused_when_the_os_denies_the_open(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    """The open itself fails with a bare `PermissionError` before `_validate_permissions` runs
    (mode 000 for a normal user). Still `refused`, still non-raising. The denial is injected
    rather than produced with `chmod 000` because CI runs the suite as root, which can open
    anything — the branch under test is unreachable there by construction."""

    class _Denied(PosixPath):
        def open(self, *args: object, **kwargs: object) -> object:  # type: ignore[override]
            raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(config, "CONFIG_FILE", _Denied(clean_env))

    status, detail = config.config_file_status()

    assert status == "refused"
    assert detail == f"Cannot read {clean_env}: Permission denied."
