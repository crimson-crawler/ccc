"""Smoke tests for the top-level Typer app."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import __version__
from crimson_crawler_cli.cli import app


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_version_flag_prints_version(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_whoami(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "whoami" in result.stdout


def test_no_args_shows_help(runner: CliRunner) -> None:
    """Pins ``no_args_is_help=True`` so bare ``ccc`` doesn't silently exit 0."""
    result = runner.invoke(app, [])

    assert result.exit_code != 0
    assert "whoami" in result.stdout
