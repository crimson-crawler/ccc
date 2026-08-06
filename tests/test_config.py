"""Config-file diagnostics for :mod:`crimson_crawler_cli.config`.

The reported failure was ``Error: internal error: Invalid value at line 1
column 25`` — tomllib's parse position escaping through ``handle_errors``'
top-level safety net, naming neither the file, the mistake, nor the fix.
"""

from __future__ import annotations

from pathlib import Path

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
    assert "shell/.env syntax" in combined
