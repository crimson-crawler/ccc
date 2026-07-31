"""Exception types, exit codes, and the centralized error-handling decorator.

Callers should catch :class:`CLIError` to handle any CLI-raised problem. The
:func:`handle_errors` decorator renders ``CLIError`` subclasses through
:mod:`crimson_crawler_cli.output` and exits with ``error.exit_code``. Command
modules apply it to their command functions without needing to import from
:mod:`crimson_crawler_cli.cli`, which keeps circular deps off the table as
more commands land.

Mirrors the Python SDK's ``CrawlerClientError`` shape so the CLI and SDK
share a recognizable error hierarchy.
"""

from __future__ import annotations

import functools
import json
from enum import IntEnum
from typing import Any, Callable

import typer
from crimson_crawler_client import UnexpectedStatus

from . import output


class ExitCode(IntEnum):
    """Process exit codes used by the CLI."""

    OK = 0
    GENERIC_ERROR = 1
    MISSING_CREDENTIALS = 2
    API_ERROR = 3
    BAD_INPUT = 64  # sysexits.h EX_USAGE


class CLIError(Exception):
    """Base class for all CLI-raised errors."""

    exit_code: ExitCode = ExitCode.GENERIC_ERROR


class MissingCredentialsError(CLIError):
    """Raised when no API key can be resolved from env or config file."""

    exit_code: ExitCode = ExitCode.MISSING_CREDENTIALS


class BadInputError(CLIError):
    """Raised when CLI input fails local validation (malformed CVE id, etc.)."""

    exit_code: ExitCode = ExitCode.BAD_INPUT


class APIError(CLIError):
    """Raised when the API returns a non-success status.

    Carries the HTTP status and a decoded body (dict if the body parsed as
    JSON, otherwise str). Both surface in the JSON error payload so callers
    piping ``--json`` to ``jq`` get the full server detail.
    """

    exit_code: ExitCode = ExitCode.API_ERROR

    def __init__(self, status: int, body: dict[str, Any] | str | None, message: str | None = None) -> None:
        self.status = status
        self.body = body
        super().__init__(message or f"Crimson Crawler API returned status {status}")


def _decode_unexpected_body(raw: Any) -> dict[str, Any] | str | None:
    """Translate an :class:`UnexpectedStatus` body to a JSON-friendly value.

    The generated client stores the raw ``httpx.Response.content`` (bytes) on
    :attr:`UnexpectedStatus.body`. Decode once at translation time so both the
    Rich and JSON output paths get a readable payload.
    """
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex()
    elif isinstance(raw, str):
        text = raw
    else:
        return raw
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text


def handle_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Render :class:`CLIError` (and unexpected exceptions) through :mod:`output`.

    Apply to every Typer command function so failures route through the
    shared JSON/Rich output dispatcher instead of Click's default traceback.
    Translates :class:`crimson_crawler_client.UnexpectedStatus` into
    :class:`APIError` so SDK transport errors flow through the same path.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except UnexpectedStatus as exc:
            body = _decode_unexpected_body(exc.body)
            api_error = APIError(exc.status, body, f"Crimson Crawler API returned status {exc.status}")
            payload: dict[str, Any] = {
                "error": "APIError",
                "message": str(api_error),
                "status": api_error.status,
                "body": api_error.body,
            }
            output.render_error(payload, str(api_error))
            raise typer.Exit(code=api_error.exit_code) from exc
        except CLIError as exc:
            payload = {"error": type(exc).__name__, "message": str(exc)}
            if isinstance(exc, APIError):
                payload["status"] = exc.status
                payload["body"] = exc.body
            output.render_error(payload, str(exc))
            raise typer.Exit(code=exc.exit_code) from exc
        except typer.Exit:
            raise
        except Exception as exc:  # noqa: BLE001 — top-level safety net
            output.render_error(
                {"error": "InternalError", "message": str(exc)},
                f"internal error: {exc}",
            )
            raise typer.Exit(code=ExitCode.GENERIC_ERROR) from exc

    return wrapper


__all__ = [
    "APIError",
    "BadInputError",
    "CLIError",
    "ExitCode",
    "MissingCredentialsError",
    "handle_errors",
]
