"""Local-host software collector for ``ccc crawl endpoint``.

Enumerates the software installed on the LOCAL host and emits assets in the
shared :mod:`inventory` shape, so ``ccc crawl endpoint`` produces the same
JSON document as ``ccc crawl project`` (just sourced from the OS instead of a
directory).

Sources (v1 — Linux packages + OS only; services deferred — there's no
'service' category and services rarely carry a matchable version):

  * ``dpkg-query`` (Debian/Ubuntu) or ``rpm`` (RHEL/Fedora/SUSE) →
    installed-application assets carrying a ``deb`` / ``rpm`` ecosystem so they
    serialize to ``pkg:deb/<distro>/<name>@<ver>`` / ``pkg:rpm/...`` purls. The
    distro (purl namespace) comes from ``/etc/os-release`` ``ID``.
  * ``/etc/os-release`` → one operating-system component.

Versions are kept verbatim (``3.0.13-0ubuntu3.4``, not the upstream
``3.0.13``): this is collection, not enrichment, and the platform crawler
keeps them verbatim too, so the two stay consistent.

The parsers are PURE (text in, asset dicts out) for offline unit testing;
:func:`collect` is the only impure part — it shells out through an injectable
``run`` callable.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from . import inventory
from .exceptions import BadInputError

OS_RELEASE_PATH = Path("/etc/os-release")

Runner = Callable[[list[str]], str]


def _default_runner(argv: list[str]) -> str:
    # NOT check=True: ``dpkg-query``/``rpm`` can exit nonzero while still
    # printing a usable package listing (e.g. a single unreadable entry). Use
    # whatever stdout we got; only treat a nonzero exit WITH no output as fatal.
    proc = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",  # a stray non-UTF-8 byte must not abort the scan
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise BadInputError(f"{argv[0]} failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


# ============================================================
# Parsers (pure — text in, asset dicts out)
# ============================================================


def parse_dpkg(text: str, distro: str | None = None) -> list[dict]:
    """Parse ``dpkg-query -W -f='${Package}\\t${Version}\\n'`` output.

    Emits ``deb``-ecosystem assets → ``pkg:deb/<distro>/<name>@<ver>`` purls.
    ``distro`` (the purl namespace) is the ``/etc/os-release`` ``ID`` (e.g.
    ``ubuntu``); ``None`` yields a namespace-less ``pkg:deb/<name>`` purl. No
    vendor — a Debian package's Maintainer is not a CPE vendor.
    """
    assets: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        if not name:
            continue
        version = (parts[1].strip() if len(parts) > 1 else "") or "unknown"
        assets.append(
            inventory.asset(
                "installed-application",
                name,
                None,
                [version],
                "installed via dpkg",
                ecosystem="deb",
                namespace=distro,
            )
        )
    return assets


def parse_rpm(text: str, distro: str | None = None) -> list[dict]:
    """Parse ``rpm -qa --qf '%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n'`` output.

    Emits ``rpm``-ecosystem assets → ``pkg:rpm/<distro>/<name>@<ver>`` purls.
    ``%{VENDOR}`` is a real vendor string (surfaced as the component
    ``publisher``); ``(none)`` collapses to ``None``. The packaging
    ``%{RELEASE}`` is intentionally not requested.
    """
    assets: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        if not name:
            continue
        version = parts[1].strip() if len(parts) > 1 else ""
        if version == "(none)":  # rpm's absent-field sentinel — never CPE-matches
            version = ""
        version = version or "unknown"
        vendor = parts[2].strip() if len(parts) > 2 else ""
        vendor_val = vendor if vendor and vendor != "(none)" else None
        assets.append(
            inventory.asset(
                "installed-application",
                name,
                vendor_val,
                [version],
                "installed via rpm",
                ecosystem="rpm",
                namespace=distro,
            )
        )
    return assets


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _os_release_fields(text: str) -> dict[str, str]:
    """Parse ``KEY=value`` lines of ``/etc/os-release`` into a dict (unquoted)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = _unquote(value)
    return fields


def os_distro(text: str) -> str | None:
    """The distro slug (the purl namespace for deb/rpm packages AND the OS
    component's name), lowercased: ``/etc/os-release`` ``ID`` (e.g. 'ubuntu'),
    falling back to the leading token of ``NAME``. ``None`` when neither is set."""
    fields = _os_release_fields(text)
    raw = fields.get("ID") or (fields.get("NAME") or "").split()[:1]
    raw = raw if isinstance(raw, str) else (raw[0] if raw else "")
    return raw.strip().lower() or None


def parse_os_release(text: str, ecosystem: str | None = None) -> list[dict]:
    """Parse ``/etc/os-release`` into one operating-system asset.

    Product + purl namespace are the distro slug (``ID``, lowercased — e.g.
    'ubuntu'), version is ``VERSION_ID`` (e.g. '24.04'), and ``ecosystem``
    ('deb'/'rpm', from the host's package manager) drives the purl type, so the
    OS serializes to ``pkg:deb/ubuntu/ubuntu@24.04`` — same distro grouping the
    packages carry. Returns an empty list when the distro can't be identified.
    """
    fields = _os_release_fields(text)
    distro = os_distro(text)
    if not distro:
        return []
    version = fields.get("VERSION_ID")
    if not version:
        # No clean VERSION_ID — take the leading token of the free-text VERSION
        # ("22.04.3 LTS (Jammy Jellyfish)" → "22.04.3"), never the whole
        # marketing string (which would never CPE-match).
        raw = (fields.get("VERSION") or "").split()
        version = raw[0] if raw else "unknown"
    return [
        inventory.asset(
            "operating-system",
            distro,
            None,
            [version],
            "detected from /etc/os-release",
            ecosystem=ecosystem,
            namespace=distro,
        )
    ]


# ============================================================
# Collection (impure — shells out through `run`)
# ============================================================


def collect(
    *,
    run: Runner | None = None,
    which: Callable[[str], str | None] = shutil.which,
    os_release_path: Path = OS_RELEASE_PATH,
) -> list[dict]:
    """Enumerate installed software on the local host into asset dicts.

    Picks ``dpkg-query`` first (Debian/Ubuntu), else ``rpm``
    (RHEL/Fedora/SUSE). Raises :class:`BadInputError` (exit 64) when NEITHER
    is present rather than emitting an OS-only result. ``run`` / ``which`` /
    ``os_release_path`` are injectable so the suite drives the path offline.
    """
    run = run or _default_runner
    assets: list[dict] = []
    os_text = ""
    distro: str | None = None

    if os_release_path.exists():
        os_text = os_release_path.read_text(encoding="utf-8", errors="replace")
        distro = os_distro(os_text)  # purl namespace for the OS + deb/rpm packages

    # Pick the package manager first: its kind (deb/rpm) fixes the purl type for
    # BOTH the packages below AND the OS component.
    if which("dpkg-query"):
        kind = "deb"
    elif which("rpm"):
        kind = "rpm"
    else:
        raise BadInputError(
            "No supported package manager found (need dpkg-query or rpm). "
            "ccc crawl endpoint supports Debian/RPM-based Linux for now."
        )

    if os_text:
        assets.extend(parse_os_release(os_text, ecosystem=kind))

    if kind == "deb":
        assets.extend(parse_dpkg(run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]), distro))
    else:
        assets.extend(parse_rpm(run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"]), distro))

    return assets


__all__ = ["collect", "os_distro", "parse_dpkg", "parse_os_release", "parse_rpm"]
