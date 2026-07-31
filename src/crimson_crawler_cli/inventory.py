"""Shared asset model + dedup + CycloneDX serialization for ``ccc crawl``.

Both collection sources — :mod:`crawl` (project directory) and :mod:`endpoint`
(local host) — collect into one ergonomic internal asset shape, dedup through
the helpers here, and serialize to a single **CycloneDX 1.6 JSON** document, so
``ccc crawl project`` and ``ccc crawl endpoint`` produce the same SBOM
differing only in content.

CycloneDX is the SBOM industry standard: the output is directly ingestible by
the API's CycloneDX ingestion path, by Dependency-Track
/ Trivy / Grype, and by anything else that speaks the format. Registry packages
are identified by **purl** (``pkg:type/namespace/name@version``) — there is no
vendor field to leave ``null``; the purl namespace carries the grouping (Maven
groupId, npm scope, deb/rpm distro). The full contract lives in
``docs/CYCLONEDX-INVENTORY-SPEC.md``.

Internal asset shape (collection-time, NOT the output)::

    {"category", "vendor", "product", "versions": [...], "notes",
     "ecosystem"?, "namespace"?}

``build_inventory`` is the boundary that turns deduped internal assets into a
CycloneDX document; nothing outside this module sees the internal shape.

Output (CycloneDX 1.6)::

    {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
     "metadata": {"timestamp": ..., "tools": [...]}, "components": [...]}
"""

from __future__ import annotations

import re

from packageurl import PackageURL

NOTES_MAX = 200


# ============================================================
# Package-name canonicalization (ported from the platform matcher)
# ============================================================


def normalize_package(name: str, ecosystem: str | None) -> str:
    """Ecosystem-aware canonical form for exact package-name comparison.

    PyPI follows PEP 503 (lowercase; runs of ``-``/``_``/``.`` collapse to one
    ``-``); every other ecosystem just case-folds. Mirrors the platform
    matcher so a ccc inventory canonicalizes names the same way they'll be
    matched downstream.
    """
    n = name.strip().casefold()
    if ecosystem == "PyPI":
        n = re.sub(r"[-_.]+", "-", n)
    return n


# ============================================================
# Version cleaning
# ============================================================

# A spec is one of:
#   exact pin (==, ===) or bare value (lockfiles) → record the bare version
#   constraint (>=, >, <=, <, !=, ~=, ~>, ^, ~)   → keep VERBATIM (e.g. ">=3.0")
#   wildcard / empty (*, "")                       → 'unknown'
_EXACT_OP_RE = re.compile(r"^\s*={2,3}\s*")
_CONSTRAINT_RE = re.compile(r"^\s*(>=|<=|!=|~=|~>|\^|~|>|<)\s*(.+)$")
_EQ_RE = re.compile(r"^\s*=\s*")

# A concrete version starts with an alphanumeric and carries no constraint
# operator — the only kind that can become a purl version / CycloneDX `version`.
_CONSTRAINT_LEAD = "<>=!~^"


def clean_version(spec: str) -> str:
    """One spec → a bare version (exact/bare), a verbatim constraint
    (``>=3.0``), or ``'unknown'`` (wildcard/empty)."""
    s = spec.strip()
    if not s or s == "*":
        return "unknown"
    if _EXACT_OP_RE.match(s):
        out = _EXACT_OP_RE.sub("", s).strip()
    else:
        m = _CONSTRAINT_RE.match(s)
        if m:
            op, ver = m.group(1), m.group(2).strip()
            out = f"{op}{ver}" if ver and ver != "*" else ""
        else:
            out = _EQ_RE.sub("", s).strip()  # bare pin (lockfiles) / `=`
    # A result with no alphanumeric (a bare operator like ``>=``, stray
    # punctuation) is not a usable version.
    if not out or not any(c.isalnum() for c in out):
        return "unknown"
    return out


def is_concrete_version(version: str) -> bool:
    """True when *version* is a single resolved version (not ``'unknown'``, not
    a constraint like ``>=2.31`` / ``^4.0``) — i.e. eligible to become a purl
    version and a CycloneDX ``component.version``."""
    return bool(version) and version != "unknown" and version[0] not in _CONSTRAINT_LEAD


def _drop_redundant_unknown(versions: list[str]) -> list[str]:
    """Drop the ``'unknown'`` placeholder when a concrete version is present."""
    concrete = [v for v in versions if v != "unknown"]
    return concrete or versions


def split_versions(versions: list[str]) -> list[str]:
    """Split each spec on ``,``, resolve to concrete versions, dedup, and drop
    ``'unknown'`` once any concrete version is known."""
    out: list[str] = []
    for v in versions:
        text = v if isinstance(v, str) else str(v)  # tolerate int/float pins
        for part in text.split(","):
            cleaned = clean_version(part)
            if cleaned and cleaned not in out:
                out.append(cleaned)
    return _drop_redundant_unknown(out) or ["unknown"]


# ============================================================
# Asset construction + dedup (internal collection shape)
# ============================================================


def asset(
    category: str,
    product: str,
    vendor: str | None,
    versions: list[str],
    note: str,
    ecosystem: str | None = None,
    namespace: str | None = None,
) -> dict:
    """Build one internal asset dict.

    ``ecosystem`` (PyPI / npm / Go / crates.io / Maven / RubyGems / deb / rpm)
    selects the purl type at serialization. ``namespace`` is an explicit purl
    namespace (used by ``endpoint`` for the deb/rpm distro); for Maven / npm /
    Go it is derived from ``product`` at serialization instead.
    """
    cleaned = split_versions(versions) if versions else ["unknown"]
    d: dict = {
        "category": category,
        "vendor": vendor,
        "product": product,
        "versions": cleaned,
        "notes": note,
    }
    if ecosystem is not None:
        d["ecosystem"] = ecosystem
    if namespace is not None:
        d["namespace"] = namespace
    return d


def dedup(assets: list[dict]) -> list[dict]:
    """Dedup by (category, ecosystem, vendor, namespace, product); union
    versions; concat notes.

    Ecosystem + namespace are part of the key so PyPI ``requests`` and Go
    ``requests`` never merge, and deb ``curl`` from different distros stay
    separate. Product names are canonicalized (PEP 503 for PyPI, case-fold
    otherwise) so registry variants collapse. Post-pass: a None-vendor entry
    sharing (category, ecosystem, namespace, product) with exactly one
    named-vendor entry is absorbed into it; two different named vendors stay
    separate (a real conflict worth surfacing).
    """
    Key = tuple[str, str | None, str | None, str | None, str]
    by_key: dict[Key, dict] = {}
    notes_by_key: dict[Key, list[str]] = {}
    order: list[Key] = []
    for a in assets:
        eco = a.get("ecosystem")
        ns = a.get("namespace")
        product = normalize_package(a["product"], eco) if eco else a["product"]
        key: Key = (a["category"], eco, a["vendor"], ns, product)
        if key not in by_key:
            entry: dict = {
                "category": a["category"],
                "vendor": a["vendor"],
                "product": product,
                "versions": [],
                "notes": "",
            }
            if eco is not None:
                entry["ecosystem"] = eco
            if ns is not None:
                entry["namespace"] = ns
            by_key[key] = entry
            notes_by_key[key] = []
            order.append(key)
        for v in a["versions"]:
            if v not in by_key[key]["versions"]:
                by_key[key]["versions"].append(v)
        if a["notes"] and a["notes"] not in notes_by_key[key]:
            notes_by_key[key].append(a["notes"])

    by_cep: dict[tuple[str, str | None, str | None, str], list[Key]] = {}
    for key in order:
        cat, eco, _vendor, ns, prod = key
        by_cep.setdefault((cat, eco, ns, prod), []).append(key)

    absorbed: set[Key] = set()
    for keys in by_cep.values():
        none_keys = [k for k in keys if k[2] is None]
        named_keys = [k for k in keys if k[2] is not None]
        if none_keys and len(named_keys) == 1:
            target = named_keys[0]
            for nk in none_keys:
                for v in by_key[nk]["versions"]:
                    if v not in by_key[target]["versions"]:
                        by_key[target]["versions"].append(v)
                for note in notes_by_key[nk]:
                    if note not in notes_by_key[target]:
                        notes_by_key[target].append(note)
                absorbed.add(nk)

    order = [k for k in order if k not in absorbed]

    for key in order:
        notes = notes_by_key[key]
        joined = "; ".join(notes)
        if len(joined) > NOTES_MAX:
            by_key[key]["notes"] = f"detected from {len(notes)} sources"
        else:
            by_key[key]["notes"] = joined
        by_key[key]["versions"] = _drop_redundant_unknown(by_key[key]["versions"])
    return [by_key[k] for k in order]


# ============================================================
# CycloneDX serialization (the output boundary)
# ============================================================

# Internal `category` → CycloneDX component `type`.
_CATEGORY_TO_TYPE = {
    "package": "library",
    "installed-application": "application",
    "operating-system": "operating-system",
}

# Internal `ecosystem` → purl type. Absent ecosystem (OS, bare installed-app) →
# no purl (component carries name + version only — valid CycloneDX).
_ECOSYSTEM_TO_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "RubyGems": "gem",
    "deb": "deb",
    "rpm": "rpm",
}


def _purl_coords(purl_type: str | None, product: str, explicit_namespace: str | None) -> tuple[str | None, str]:
    """Split an internal product string into (namespace, name) for a purl/component.

    An explicit namespace (deb/rpm distro) always wins. Otherwise the namespace
    is derived from the product per ecosystem convention: Maven ``group:artifact``,
    scoped npm ``@scope/name``, Go ``module/path/name``. Everything else has no
    namespace.
    """
    if explicit_namespace is not None:
        return explicit_namespace, product
    if purl_type == "maven" and ":" in product:
        ns, _, name = product.partition(":")
        return (ns or None), name
    if purl_type == "npm" and product.startswith("@") and "/" in product:
        ns, _, name = product[1:].partition("/")
        return "@" + ns, name
    if purl_type == "golang" and "/" in product:
        ns, _, name = product.rpartition("/")
        return (ns or None), name
    return None, product


def _build_purl(purl_type: str, namespace: str | None, name: str, version: str | None) -> str:
    """Canonical purl string via ``packageurl`` (handles ``@scope`` + encoding)."""
    return PackageURL(
        type=purl_type, namespace=namespace or None, name=name, version=version or None
    ).to_string()


def _asset_to_components(a: dict) -> list[dict]:
    """One deduped internal asset → one CycloneDX component per version.

    A constraint (``>=2.31``) or ``'unknown'`` version yields a component with
    no ``version`` field; the raw constraint is preserved in a
    ``crimson:requirement`` property so nothing is lost. Multiple concrete
    versions yield one component each (proper SBOM shape).
    """
    ctype = _CATEGORY_TO_TYPE.get(a["category"], "application")
    eco = a.get("ecosystem")
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(eco) if eco else None
    namespace, name = _purl_coords(purl_type, a["product"], a.get("namespace"))
    vendor = a.get("vendor")
    notes = a.get("notes") or ""

    components: list[dict] = []
    for version in a["versions"]:
        concrete = is_concrete_version(version)
        comp: dict = {"type": ctype, "name": name}
        if namespace:
            comp["group"] = namespace
        if concrete:
            comp["version"] = version
        if vendor:
            comp["publisher"] = vendor
        if purl_type:
            comp["purl"] = _build_purl(purl_type, namespace, name, version if concrete else None)
        properties: list[dict] = []
        if not concrete and version != "unknown":
            properties.append({"name": "crimson:requirement", "value": version})
        if notes:
            properties.append({"name": "crimson:notes", "value": notes})
        if properties:
            comp["properties"] = properties
        components.append(comp)
    return components


def build_inventory(assets: list[dict], timestamp: str, *, tool_version: str = "0") -> dict:
    """Serialize deduped internal assets into a CycloneDX 1.6 document.

    ``timestamp`` is passed in (ISO-8601) rather than read from the clock so the
    caller controls it and the function stays pure/testable. ``tool_version`` is
    the ``ccc`` CLI version, recorded under ``metadata.tools``. An empty scan
    emits ``components: []`` — a valid CycloneDX document with no components.
    """
    components: list[dict] = []
    for a in assets:
        components.extend(_asset_to_components(a))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "ccc crawl", "version": tool_version}],
        },
        "components": components,
    }


__all__ = [
    "asset",
    "build_inventory",
    "clean_version",
    "dedup",
    "is_concrete_version",
    "normalize_package",
    "split_versions",
]
