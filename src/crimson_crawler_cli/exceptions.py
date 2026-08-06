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


# Click validates the command line before any command body runs, and its own
# UsageError family (unknown option, missing argument, a value outside a
# `min=`/`max=` range, a non-integer where an int is required) exits 2. That is
# the code this CLI documents as meaning "no API key" — and README sells exit
# codes as stable enough for CI to branch on, so a wrapper doing
# `if code == 2: prompt_for_api_key` fired on a plain typo, and nothing could
# tell the two apart. Point the usage family at BAD_INPUT instead, which is
# where every one of our own local-validation errors already lands (malformed
# CVE id, empty keyword, unknown ingest format).
#
# `exit_code` is declared on UsageError itself and inherited by NoSuchOption,
# BadParameter and MissingParameter, so one assignment covers the family.
# Non-usage ClickException keeps its own 1. Rebinding a dependency's attribute
# would be rude in a library; this is an application entry point, and the
# alternative (running Click with standalone_mode=False) means reimplementing
# its usage reporting and exit handling to change one integer.
#
# Import it from whichever click Typer is actually driving. **typer 0.27 vendors
# click at `typer._click` and no longer depends on the distribution at all**, so
# a plain `import click` raises ModuleNotFoundError there — and our floor is
# `typer>=0.12`, so both shapes are in range and a lockfile can differ from a
# fresh resolve. Declaring `click` explicitly would be worse than this: on 0.27
# it installs a second click that Typer never consults, so the patch would apply
# to the wrong class and silently do nothing.
#
# Both branches failing raises at import, which the `build-client-cli` job trips
# immediately because it runs `ccc` against a clean install of the built wheel.
# That is deliberate: a silent skip would restore the exit-2 collision with
# nothing to notice it. The two `*_exits_64` CLI tests cover the other half —
# they fail if the import succeeds but targets a class Typer does not raise.
try:  # typer >= 0.27
    from typer._click.exceptions import UsageError as _UsageError
except ImportError:  # typer <= 0.26 depends on the real click distribution
    from click import UsageError as _UsageError

_UsageError.exit_code = ExitCode.BAD_INPUT


class CLIError(Exception):
    """Base class for all CLI-raised errors."""

    exit_code: ExitCode = ExitCode.GENERIC_ERROR


class MissingCredentialsError(CLIError):
    """Raised when no API key can be resolved from env or config file."""

    exit_code: ExitCode = ExitCode.MISSING_CREDENTIALS


class BadInputError(CLIError):
    """Raised when CLI input fails local validation (malformed CVE id, etc.)."""

    exit_code: ExitCode = ExitCode.BAD_INPUT


class ConfigFileError(CLIError):
    """Raised when ``~/.crimson-crawler/config.toml`` exists but is unusable.

    Local validation of a file the user wrote, so it lands on
    :attr:`ExitCode.BAD_INPUT` alongside every other bad-input case — not on
    :attr:`ExitCode.MISSING_CREDENTIALS`, which means *only* "no API key
    anywhere" and which CI wrappers branch on to prompt for a key.

    Without this class a malformed config surfaced through ``handle_errors``'
    top-level safety net as ``internal error: Invalid value at line 1 column
    25`` — a tomllib parse position with no mention of the file it came from,
    let alone the one-line fix.
    """

    exit_code: ExitCode = ExitCode.BAD_INPUT


class ConfigPermissionError(ConfigFileError, PermissionError):
    """Raised when the config file's ownership or mode is unsafe to read.

    Also a :class:`PermissionError` because that is what callers (and the
    existing tests) catch for the ownership/``chmod 600`` refusals, which
    predate the :class:`ConfigFileError` family.
    """


def describe_api_status(status: int) -> str:
    """Human-readable one-liner for an API status code.

    ``401``/``403`` get a credential-specific message naming where the key the
    CLI just used came from, because "returned status 401" alone reads like a
    server problem when it is almost always a stale, revoked, or wrong-origin
    key. Every other status keeps the neutral phrasing — the response body,
    which the JSON payload carries in full, is the better detail there.
    """
    if status == 401:
        return (
            "The Crimson Crawler API rejected your API key (HTTP 401)."
            f"{_key_origin_sentence()} Confirm the key is still active at "
            "https://crimsoncrawler.com/dashboard, and that CRIMSON_CRAWLER_BASE_URL "
            "points at the deployment that issued it — a key is only valid on its own origin. "
            "Run `ccc whoami` to see which key the CLI is picking up."
        )
    if status == 403:
        return (
            "The Crimson Crawler API accepted your key but refused this request (HTTP 403)."
            f"{_key_origin_sentence()} The key may lack access to this endpoint, "
            "or your plan may not include it."
        )
    return f"Crimson Crawler API returned status {status}"


def _key_origin_sentence() -> str:
    """`` The key came from …`` — or an empty string when it can't be determined.

    Imported lazily: :mod:`auth` imports this module at load time, so a
    module-level import here would be circular.
    """
    from . import auth  # noqa: PLC0415 — deliberate, see docstring

    origin = auth.credential_origin()
    return f" The key came from {origin}." if origin else ""


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
        super().__init__(message or describe_api_status(status))


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
            api_error = APIError(exc.status, body)
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
    "ConfigFileError",
    "ConfigPermissionError",
    "ExitCode",
    "MissingCredentialsError",
    "describe_api_status",
    "handle_errors",
]
