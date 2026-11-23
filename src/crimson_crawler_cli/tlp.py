"""The ``--tlp`` marking option for every export command (#374).

The five case-sensitive CISA TLP 2.0 markings come from the SDK (:data:`TLP_VALUES`), so the CLI keeps no
second copy. The *input* is matched case-insensitively and handed on in canonical uppercase
(``amber+strict`` → ``AMBER+STRICT``); anything else is a usage error (exit 64, this CLI's bad-input code)
that lists the five values. The canonical value is then handed to the SDK, which re-validates and encodes it.

No ``import click``: typer 0.27 vendors click and ``crimson-crawler-cli`` does not declare it (see the note in
``exceptions.py``), so the option is a plain typer ``str`` option with a callback.
"""

from __future__ import annotations

import typer

from crimson_crawler_client import TLP_VALUES, Tlp, validate_tlp

_CHOICES = ", ".join(repr(value) for value in TLP_VALUES)


def _parse_tlp(value: str | None) -> Tlp | None:
    """Option callback: case-insensitive match, canonical UPPERCASE out, ``None`` (omitted) passes through."""
    if value is None:
        return None
    try:
        return validate_tlp(value.upper())
    except ValueError:
        raise typer.BadParameter(f"{value!r} is not one of {_CHOICES}.") from None


def tlp_option(help_text: str) -> object:
    """The shared ``--tlp`` option; ``help_text`` is the per-command description."""
    return tlp_named_option("--tlp", help_text)


def tlp_named_option(flag: str, help_text: str) -> object:
    """The same option under ANOTHER flag, with the same parsing — for a command that takes TWO markings at
    once (``ccc artifact-manager settings --artifact-tlp … --inventory-tlp …``). Declaring ``tlp_option``
    twice on one command makes click see the parameter name ``--tlp`` twice and warn, then bind both to the
    same slot; the flag has to differ, the parsing must not."""
    return typer.Option(
        flag,
        help=help_text,
        callback=_parse_tlp,
        metavar="[" + "|".join(TLP_VALUES) + "]",
        show_default=False,
    )


def tlp_value(raw: str | None) -> Tlp | None:
    """The SDK-typed value of a parsed ``--tlp`` (already canonical; ``None`` omits the parameter so the
    server applies the context default — all markings on a list filter, ``AMBER`` on create, and the
    artifact's stored TLP on a stored-artifact export)."""
    return validate_tlp(raw)


__all__ = ["tlp_option", "tlp_named_option", "tlp_value"]
