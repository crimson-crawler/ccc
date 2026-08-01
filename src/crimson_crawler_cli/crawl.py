"""Project-directory dependency crawler for ``ccc crawl project``.

Walks a target directory, detecting tooling and library dependencies from
sentinel files, manifest files, Dockerfiles, and version-pin files, and emits
assets in the shared :mod:`inventory` shape — the same document ``ccc crawl
endpoint`` produces, just sourced from files instead of the OS.

Ported from crimsoncrawler-integration-kit's ``scripts/crawl_project.py``. The
asset/dedup/envelope primitives moved to :mod:`inventory`; XML parsing uses
``defusedxml`` (the CLI already depends on it) rather than the stdlib parser.

Output hygiene: PyPI names are canonicalized (PEP 503) at dedup time so
registry variants collapse; version constraints are kept verbatim (``>=3.0``,
not a bare ``3``); Docker tags resolve to a version or 'unknown'; and
dev/test/docs dependency groups are excluded by default (pass ``include_dev``
to keep them).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path

from defusedxml.ElementTree import ParseError as _XMLParseError
from defusedxml.ElementTree import fromstring as _xml_fromstring

from . import inventory

_asset = inventory.asset


def _as_dict(value) -> dict:
    """A manifest section that should be a table, or ``{}`` if it's the wrong
    type — a hand-edited manifest can put a string/list where a table belongs,
    and a parser shouldn't crash (or lose the rest of the file) over it."""
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    """A manifest section that should be an array, or ``[]`` if it's not."""
    return value if isinstance(value, list) else []


# ============================================================
# Constants
# ============================================================

PRUNE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "bower_components",
        "target",
        "build",
        "dist",
        "out",
        ".gradle",
        ".idea",
        ".vscode",
        "vendor",
        ".terraform",
        ".next",
        ".nuxt",
    }
)

OS_BASE_IMAGES = frozenset(
    {
        "ubuntu",
        "debian",
        "alpine",
        "centos",
        "fedora",
        "rhel",
        "rockylinux",
        "almalinux",
        "archlinux",
        "opensuse",
        "amazonlinux",
    }
)

_TAG_VERSION_SEG_RE = re.compile(r"^v?(\d[\w.]*)$")


def _docker_tag_version(tag: str) -> str:
    """Version part of a Docker image tag, or 'unknown' for a pure variant."""
    for segment in tag.split("-"):
        m = _TAG_VERSION_SEG_RE.match(segment)
        if m:
            return m.group(1)
    return "unknown"


# Dev/test/docs/build dependency groups — tooling, not the deployed runtime
# surface — excluded by default. A dep that is ALSO a runtime dependency is
# still emitted from its runtime source, so this only drops dev-ONLY packages.
_DEV_GROUPS = frozenset(
    {
        "dev",
        "devel",
        "development",
        "dev-dependencies",
        "dev-deps",
        "test",
        "tests",
        "testing",
        "qa",
        "lint",
        "linting",
        "style",
        "format",
        "formatting",
        "typing",
        "type",
        "types",
        "typecheck",
        "mypy",
        "doc",
        "docs",
        "documentation",
        "build",
        "ci",
        "cov",
        "coverage",
        "benchmark",
        "bench",
        "profiling",
    }
)


def _is_dev_group(name: str) -> bool:
    return name.strip().casefold() in _DEV_GROUPS


def _is_dev_requirements(path: Path) -> bool:
    # Classify by the FILE's own name only (``requirements-dev.txt``,
    # ``dev-requirements.txt``, ``requirements/test.txt`` → stem ``test``).
    # The parent directory name is deliberately NOT consulted: a runtime
    # ``requirements.txt`` under a dir that happens to be named ``build``,
    # ``ci``, ``test``, ... is still a runtime manifest, not a dev one.
    tokens = re.split(r"[-_.]", path.stem.casefold())
    return any(t in _DEV_GROUPS for t in tokens)


SENTINELS: dict[str, tuple[str | None, str]] = {
    "Dockerfile": ("Docker", "Docker Engine"),
    "Containerfile": ("Docker", "Docker Engine"),
    "docker-compose.yml": ("Docker", "Docker Compose"),
    "docker-compose.yaml": ("Docker", "Docker Compose"),
    "compose.yml": ("Docker", "Docker Compose"),
    "compose.yaml": ("Docker", "Docker Compose"),
    "uv.lock": ("Astral", "uv"),
    "poetry.lock": (None, "Poetry"),
    "Pipfile.lock": (None, "pipenv"),
    "package-lock.json": (None, "npm"),
    "pnpm-lock.yaml": (None, "pnpm"),
    "yarn.lock": (None, "Yarn"),
    "Cargo.lock": ("Rust Foundation", "Cargo"),
    "Gemfile.lock": (None, "Bundler"),
    "Makefile": ("GNU", "make"),
    "GNUmakefile": ("GNU", "make"),
    "pom.xml": ("Apache", "Maven"),
    "build.gradle": (None, "Gradle"),
    "build.gradle.kts": (None, "Gradle"),
}

ASDF_TOOLS: dict[str, tuple[str | None, str]] = {
    "python": ("Python Software Foundation", "Python"),
    "nodejs": (None, "Node.js"),
    "node": (None, "Node.js"),
    "ruby": (None, "Ruby"),
    "go": (None, "Go"),
    "golang": (None, "Go"),
    "rust": (None, "Rust"),
    "terraform": ("HashiCorp", "Terraform"),
}

# Toggled per-crawl by `crawl(include_dev=...)`. Module-level so the many
# parsers can read it without threading the flag through every signature.
EXCLUDE_DEV = True


# ============================================================
# Relative-path notes (shared state)
# ============================================================

_CURRENT_TARGET: Path | None = None


@contextlib.contextmanager
def _target_scope(target: Path | None):
    global _CURRENT_TARGET
    old = _CURRENT_TARGET
    _CURRENT_TARGET = target
    try:
        yield
    finally:
        _CURRENT_TARGET = old


def _rel(path: Path) -> str:
    if _CURRENT_TARGET is None:
        return path.name
    try:
        return str(path.relative_to(_CURRENT_TARGET))
    except ValueError:
        return path.name


# ============================================================
# File reading
# ============================================================


MAX_MANIFEST_BYTES = 5 * 1024 * 1024


def _read(path: Path) -> str | None:
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            print(
                f"warning: skipped oversized manifest {path} ({size} bytes; limit is {MAX_MANIFEST_BYTES} bytes)",
                file=sys.stderr,
            )
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ============================================================
# Sentinel detection
# ============================================================


def detect_sentinel(filename: str) -> list[dict]:
    if filename in SENTINELS:
        vendor, product = SENTINELS[filename]
        return [
            _asset(
                "installed-application",
                product,
                vendor,
                ["unknown"],
                f"detected from {filename}",
            )
        ]
    if filename.endswith(".Dockerfile") and filename != "Dockerfile":
        return [
            _asset(
                "installed-application",
                "Docker Engine",
                "Docker",
                ["unknown"],
                f"detected from {filename}",
            )
        ]
    return []


# ============================================================
# Requirements line parser (shared)
# ============================================================

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(.*)$")


def _parse_requirements_line(line: str) -> tuple[str, str] | None:
    """Parse a single PEP 508 / pip requirement line → (name, version_spec)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        m = re.search(r"#egg=([A-Za-z0-9_.\-]+)", line)
        if m:
            return (m.group(1), "unknown")
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None
    first_token = line.split()[0] if line.split() else ""
    if first_token in {
        "-r",
        "--requirement",
        "-e",
        "--editable",
        "-c",
        "--constraint",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--no-index",
        "--pre",
    }:
        return None
    if line.startswith("-"):
        return None
    if ";" in line:
        line = line.split(";", 1)[0].strip()
    line = re.sub(r"\[[^\]]*\]", "", line, count=1)
    m = _REQ_NAME_RE.match(line)
    if not m:
        return None
    name = m.group(1).strip()
    spec = m.group(2).strip()
    return (name, spec if spec else "unknown")


# ============================================================
# Python: pyproject.toml
# ============================================================


def parse_pyproject_toml(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rel = _rel(path)
    assets: list[dict] = []
    project = _as_dict(data.get("project"))

    rp = project.get("requires-python")
    if isinstance(rp, str) and rp:
        assets.append(
            _asset(
                "installed-application",
                "Python",
                "Python Software Foundation",
                [rp],
                f"detected from {rel} [project.requires-python]",
            )
        )

    for dep_line in _as_list(project.get("dependencies")):
        if not isinstance(dep_line, str):
            continue
        parsed = _parse_requirements_line(dep_line)
        if parsed:
            name, ver = parsed
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [project.dependencies]",
                    ecosystem="PyPI",
                )
            )

    optional = _as_dict(project.get("optional-dependencies"))
    for group, deps in optional.items():
        if EXCLUDE_DEV and _is_dev_group(group):
            continue
        for dep_line in _as_list(deps):
            if not isinstance(dep_line, str):
                continue
            parsed = _parse_requirements_line(dep_line)
            if parsed:
                name, ver = parsed
                assets.append(
                    _asset(
                        "package",
                        name,
                        None,
                        [ver],
                        f"detected from {rel} [project.optional-dependencies.{group}]",
                        ecosystem="PyPI",
                    )
                )

    dep_groups = _as_dict(data.get("dependency-groups"))
    for group, deps in dep_groups.items():
        if EXCLUDE_DEV and _is_dev_group(group):
            continue
        for dep_line in _as_list(deps):
            if not isinstance(dep_line, str):
                continue
            parsed = _parse_requirements_line(dep_line)
            if parsed:
                name, ver = parsed
                assets.append(
                    _asset(
                        "package",
                        name,
                        None,
                        [ver],
                        f"detected from {rel} [dependency-groups.{group}]",
                        ecosystem="PyPI",
                    )
                )

    build_system = _as_dict(data.get("build-system"))
    for dep_line in _as_list(build_system.get("requires")):
        if not isinstance(dep_line, str):
            continue
        parsed = _parse_requirements_line(dep_line)
        if parsed:
            name, ver = parsed
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [build-system.requires]",
                    ecosystem="PyPI",
                )
            )

    poetry = _as_dict(_as_dict(data.get("tool")).get("poetry"))
    for name, spec in _as_dict(poetry.get("dependencies")).items():
        ver = _poetry_version(spec)
        if name == "python":
            assets.append(
                _asset(
                    "installed-application",
                    "Python",
                    "Python Software Foundation",
                    [ver],
                    f"detected from {rel} [tool.poetry.dependencies.python]",
                )
            )
            continue
        assets.append(
            _asset(
                "package",
                name,
                None,
                [ver],
                f"detected from {rel} [tool.poetry.dependencies]",
                ecosystem="PyPI",
            )
        )
    for group_name, group_data in _as_dict(poetry.get("group")).items():
        if EXCLUDE_DEV and _is_dev_group(group_name):
            continue
        deps = _as_dict(_as_dict(group_data).get("dependencies"))
        for name, spec in deps.items():
            ver = _poetry_version(spec)
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [tool.poetry.group.{group_name}.dependencies]",
                    ecosystem="PyPI",
                )
            )
    return assets


def _poetry_version(spec) -> str:
    if isinstance(spec, str):
        return spec if spec != "*" else "unknown"
    if isinstance(spec, dict):
        v = spec.get("version", "*")
        return v if v not in ("*", "") else "unknown"
    if isinstance(spec, list):
        for s in spec:
            if isinstance(s, dict) and "version" in s:
                return s["version"]
        return "unknown"
    return "unknown"


# ============================================================
# Python: requirements*.txt / requirements*.in
# ============================================================


def parse_requirements_txt(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []
    for line in text.splitlines():
        parsed = _parse_requirements_line(line)
        if parsed:
            name, ver = parsed
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel}",
                    ecosystem="PyPI",
                )
            )
    return assets


# ============================================================
# Python: Pipfile
# ============================================================


def parse_pipfile(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rel = _rel(path)
    assets: list[dict] = []
    for section_key in ("packages", "dev-packages"):
        for name, spec in _as_dict(data.get(section_key)).items():
            if isinstance(spec, str):
                ver = spec if spec != "*" else "unknown"
            elif isinstance(spec, dict):
                v = spec.get("version", "*")
                ver = v if v not in ("*", "") else "unknown"
            else:
                ver = "unknown"
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [{section_key}]",
                    ecosystem="PyPI",
                )
            )
    return assets


# ============================================================
# Node: package.json
# ============================================================


def parse_package_json(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rel = _rel(path)
    assets: list[dict] = []
    sections = ["dependencies", "peerDependencies", "optionalDependencies"]
    if not EXCLUDE_DEV:
        sections.append("devDependencies")
    for section in sections:
        for name, ver in _as_dict(data.get(section)).items():
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [str(ver) if ver else "unknown"],
                    f"detected from {rel} [{section}]",
                    ecosystem="npm",
                )
            )
    engines = _as_dict(data.get("engines"))
    if "node" in engines:
        assets.append(
            _asset(
                "installed-application",
                "Node.js",
                None,
                [str(engines["node"])],
                f"detected from {rel} [engines.node]",
            )
        )
    if "npm" in engines:
        assets.append(
            _asset(
                "installed-application",
                "npm",
                None,
                [str(engines["npm"])],
                f"detected from {rel} [engines.npm]",
            )
        )
    return assets


# ============================================================
# Rust: Cargo.toml
# ============================================================


def parse_cargo_toml(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rel = _rel(path)
    assets: list[dict] = []

    pkg = _as_dict(data.get("package"))
    rv = pkg.get("rust-version")
    if isinstance(rv, str) and rv:
        assets.append(
            _asset(
                "installed-application",
                "Rust",
                "Rust Foundation",
                [rv],
                f"detected from {rel} [package.rust-version]",
            )
        )

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in _as_dict(data.get(section)).items():
            if isinstance(spec, str):
                ver = spec
            elif isinstance(spec, dict):
                ver = spec.get("version", "unknown")
            else:
                ver = "unknown"
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [{section}]",
                    ecosystem="crates.io",
                )
            )
    return assets


# ============================================================
# Go: go.mod
# ============================================================

_GO_BLOCK_RE = re.compile(r"require\s*\(\s*([^)]*)\)", re.DOTALL)
_GO_BLOCK_LINE_RE = re.compile(r"^\s*([\w./\-]+)\s+(\S+)")
_GO_SINGLE_LINE_RE = re.compile(r"^\s*require\s+([\w./\-]+)\s+(\S+)", re.MULTILINE)
_GO_DIRECTIVE_RE = re.compile(r"^\s*go\s+([\d.]+)\b", re.MULTILINE)


def parse_go_mod(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []

    m = _GO_DIRECTIVE_RE.search(text)
    if m:
        assets.append(
            _asset(
                "installed-application",
                "Go",
                None,
                [m.group(1)],
                f"detected from {rel} [go directive]",
            )
        )

    for block_match in _GO_BLOCK_RE.finditer(text):
        block = block_match.group(1)
        for line in block.splitlines():
            line = re.sub(r"//.*$", "", line).strip()
            if not line:
                continue
            line_m = _GO_BLOCK_LINE_RE.match(line)
            if line_m:
                assets.append(
                    _asset(
                        "package",
                        line_m.group(1),
                        None,
                        [line_m.group(2)],
                        f"detected from {rel} [require]",
                        ecosystem="Go",
                    )
                )

    for single_m in _GO_SINGLE_LINE_RE.finditer(text):
        assets.append(
            _asset(
                "package",
                single_m.group(1),
                None,
                [single_m.group(2)],
                f"detected from {rel} [require]",
                ecosystem="Go",
            )
        )
    return assets


# ============================================================
# Ruby: Gemfile
# ============================================================

_GEM_LINE_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?")
_RUBY_LINE_RE = re.compile(r"^\s*ruby\s+['\"]([^'\"]+)['\"]")


def parse_gemfile(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []
    for raw_line in text.splitlines():
        line = re.sub(r"#.*$", "", raw_line)
        rm = _RUBY_LINE_RE.match(line)
        if rm:
            assets.append(
                _asset(
                    "installed-application",
                    "Ruby",
                    None,
                    [rm.group(1)],
                    f"detected from {rel} [ruby directive]",
                )
            )
            continue
        gm = _GEM_LINE_RE.match(line)
        if gm:
            name = gm.group(1)
            ver = gm.group(2) or "unknown"
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"detected from {rel} [gem]",
                    ecosystem="RubyGems",
                )
            )
    return assets


# ============================================================
# Java: pom.xml
# ============================================================


def parse_pom_xml(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    cleaned = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
    try:
        root = _xml_fromstring(cleaned)
    except (_XMLParseError, ValueError):
        return []
    # Maven ``<properties>`` hold version values referenced as ``${name}``.
    props = _pom_properties(root)
    assets: list[dict] = []
    for dep in _pom_dependency_elements(root):
        scope = (dep.findtext("scope") or "").strip().casefold()
        if EXCLUDE_DEV and scope == "test":
            continue  # test-scoped dep — tooling, like Gradle's testImplementation
        gid = (dep.findtext("groupId") or "").strip()
        aid = (dep.findtext("artifactId") or "").strip()
        ver = _resolve_pom_version((dep.findtext("version") or "").strip(), props)
        if not aid:
            continue
        product = f"{gid}:{aid}" if gid else aid
        assets.append(
            _asset(
                "package",
                product,
                None,
                [ver],
                f"detected from {rel} [dependencies]",
                ecosystem="Maven",
            )
        )
    return assets


def _pom_properties(root) -> dict[str, str]:
    """Project-level and per-profile ``<properties>`` — the tables that hold
    the ``${name}`` values referenced by dependency versions. Deliberately NOT
    a global ``root.iter('properties')``: a ``<properties>`` block nested in a
    plugin ``<configuration>`` is legal Maven and would otherwise pollute (or
    shadow a real key in) the resolution map."""
    props: dict[str, str] = {}

    def absorb(parent):
        container = parent.find("properties")
        if container is not None:
            for child in container:
                props[child.tag] = (child.text or "").strip()

    absorb(root)
    profiles = root.find("profiles")
    if profiles is not None:
        for prof in profiles.findall("profile"):
            absorb(prof)
    return props


def _pom_dependency_elements(root):
    """Yield ``<dependency>`` elements from the blocks that declare the
    project's own dependencies — top-level ``<dependencies>``,
    ``<dependencyManagement>``, and the per-profile equivalents. Deliberately
    NOT ``<build>``/``<plugin>`` dependencies: those are build-time tooling,
    not the deployed dependency surface this inventory is about. (The old
    ``root.find('dependencies')`` missed dependencyManagement and profiles.)"""

    def containers(parent):
        direct = parent.find("dependencies")
        if direct is not None:
            yield direct
        mgmt = parent.find("dependencyManagement")
        if mgmt is not None:
            md = mgmt.find("dependencies")
            if md is not None:
                yield md

    scopes = [root]
    profiles = root.find("profiles")
    if profiles is not None:
        scopes.extend(profiles.findall("profile"))
    for scope in scopes:
        for container in containers(scope):
            yield from container.findall("dependency")


def _resolve_pom_version(ver: str, props: dict[str, str]) -> str:
    """Resolve a ``${name}`` property reference against ``<properties>``;
    fall back to 'unknown' for an unresolved reference (never emit the literal
    ``${...}`` as a version)."""
    if ver.startswith("${") and ver.endswith("}"):
        return props.get(ver[2:-1], "") or "unknown"
    return ver or "unknown"


# ============================================================
# Java: build.gradle / build.gradle.kts
# ============================================================

_GRADLE_DEP_RE = re.compile(
    r"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|annotationProcessor)\s*[(\s]\s*"
    r"['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]"
)


def parse_build_gradle(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []
    for line in text.splitlines():
        m = _GRADLE_DEP_RE.search(line)
        if m:
            scope, gid, aid, ver = m.group(1), m.group(2), m.group(3), m.group(4)
            if EXCLUDE_DEV and scope.casefold().startswith("test"):
                continue  # testImplementation/testRuntimeOnly — dev tooling
            if ver.startswith("$"):
                ver = "unknown"  # `$var` / `${var}` Gradle variable, not a version
            product = f"{gid}:{aid}"
            assets.append(
                _asset(
                    "package",
                    product,
                    None,
                    [ver],
                    f"detected from {rel} [{scope}]",
                    ecosystem="Maven",
                )
            )
    return assets


# ============================================================
# Version-pin files
# ============================================================


def parse_python_version(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    raw = text.strip()
    ver = raw.splitlines()[0].strip() if raw else "unknown"
    return [
        _asset(
            "installed-application",
            "Python",
            "Python Software Foundation",
            [ver or "unknown"],
            f"detected from {_rel(path)}",
        )
    ]


def parse_nvmrc(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    ver = text.strip().lstrip("v")
    return [
        _asset(
            "installed-application",
            "Node.js",
            None,
            [ver or "unknown"],
            f"detected from {_rel(path)}",
        )
    ]


def parse_ruby_version(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    ver = text.strip()
    return [
        _asset(
            "installed-application",
            "Ruby",
            None,
            [ver or "unknown"],
            f"detected from {_rel(path)}",
        )
    ]


def parse_tool_versions(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        tool, ver = parts[0], parts[1]
        if tool in ASDF_TOOLS:
            vendor, product = ASDF_TOOLS[tool]
        else:
            vendor, product = None, tool
        assets.append(
            _asset(
                "installed-application",
                product,
                vendor,
                [ver],
                f"detected from {rel}",
            )
        )
    return assets


# ============================================================
# Docker: Dockerfile / Containerfile
# ============================================================

_DOCKER_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?",
    re.IGNORECASE | re.MULTILINE,
)
_DOCKER_RUN_RE = re.compile(r"^\s*RUN\s+(.+)$", re.IGNORECASE | re.MULTILINE)


def _split_image_ref(image: str) -> tuple[str, str]:
    """Split a Docker image reference into ``(name, tag)``.

    Handles the cases a naive ``rsplit(':', 1)`` gets wrong:
      * ``registry:5000/img`` — the ``:`` is a registry port, NOT a tag.
      * ``img@sha256:...`` — a digest is not a version; drop it, no tag.
      * ``registry:5000/img:1.2@sha256:...`` — port + tag + digest together.

    A tag exists only as a ``:`` in the LAST path segment (after the final
    ``/``). Returns ``tag=""`` when the image carries no tag.
    """
    ref = image.split("@", 1)[0]  # strip any @sha256:... digest
    slash = ref.rfind("/")
    last_seg = ref[slash + 1 :]
    if ":" in last_seg:
        name_tail, tag = last_seg.rsplit(":", 1)
        return ref[: slash + 1] + name_tail, tag
    return ref, ""


def parse_dockerfile(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    rel = _rel(path)
    assets: list[dict] = []

    joined = re.sub(r"\\\s*\n\s*", " ", text)

    for m in _DOCKER_FROM_RE.finditer(joined):
        image = m.group(1).strip()
        if "${" in image or "$(" in image:
            continue
        if image.lower() == "scratch":
            continue
        img, tag = _split_image_ref(image)
        img_base = img.rsplit("/", 1)[-1].lower()
        category = "operating-system" if img_base in OS_BASE_IMAGES else "installed-application"
        assets.append(
            _asset(
                category,
                img_base,
                None,
                [_docker_tag_version(tag)],
                f"detected from {rel} [FROM]",
            )
        )

    for m in _DOCKER_RUN_RE.finditer(joined):
        body = m.group(1).strip()
        for cmd in re.split(r"&&|;|\|", body):
            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd.startswith("sudo "):
                cmd = cmd[5:].strip()
            assets.extend(_parse_run_command(cmd, rel))
    return assets


def _parse_run_command(cmd: str, rel: str) -> list[dict]:
    tokens = cmd.split()
    if not tokens:
        return []

    if (
        len(tokens) >= 4
        and tokens[0] in ("python", "python3")
        and tokens[1] == "-m"
        and tokens[2] == "pip"
        and tokens[3] == "install"
    ):
        return _parse_pip_packages(tokens[4:], rel, "python -m pip install")

    verb_lookup: list[tuple[tuple[str, ...], Callable[..., list[dict]], str, str | None]] = [
        (("apt-get", "install"), _parse_apt_packages, "apt-get install", None),
        (("apt", "install"), _parse_apt_packages, "apt install", None),
        (("apk", "add"), _parse_apk_packages, "apk add", None),
        (("yum", "install"), _parse_apt_packages, "yum install", None),
        (("dnf", "install"), _parse_apt_packages, "dnf install", None),
        (("pip", "install"), _parse_pip_packages, "pip install", None),
        (("pip3", "install"), _parse_pip_packages, "pip3 install", None),
        (("npm", "install"), _parse_npm_packages, "npm install", None),
        (("npm", "i"), _parse_npm_packages, "npm install", None),
        (("yarn", "add"), _parse_npm_packages, "yarn add", None),
        (("pnpm", "add"), _parse_npm_packages, "pnpm add", None),
        (("pnpm", "install"), _parse_npm_packages, "pnpm install", None),
        (("gem", "install"), _parse_simple_packages, "gem install", "RubyGems"),
        (("cargo", "install"), _parse_simple_packages, "cargo install", "crates.io"),
        (("go", "install"), _parse_simple_packages, "go install", "Go"),
    ]
    for verb_tokens, fn, label, ecosystem in verb_lookup:
        if len(tokens) >= len(verb_tokens) and tuple(tokens[: len(verb_tokens)]) == verb_tokens:
            if fn is _parse_simple_packages:
                return fn(tokens[len(verb_tokens) :], rel, label, ecosystem)
            return fn(tokens[len(verb_tokens) :], rel, label)
    return []


def _strip_install_flags(tokens: list[str]) -> list[str]:
    pkgs: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--virtual":
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        pkgs.append(t)
        i += 1
    return pkgs


def _parse_apt_packages(tokens: list[str], rel: str, label: str) -> list[dict]:
    assets: list[dict] = []
    for pkg in _strip_install_flags(tokens):
        if "=" in pkg:
            name, ver = pkg.split("=", 1)
        else:
            name, ver = pkg, "unknown"
        assets.append(
            _asset(
                "installed-application",
                name,
                None,
                [ver],
                f"installed via {label} in {rel}",
            )
        )
    return assets


def _parse_apk_packages(tokens: list[str], rel: str, label: str) -> list[dict]:
    assets: list[dict] = []
    for pkg in _strip_install_flags(tokens):
        if "=" in pkg:
            name, ver = pkg.split("=", 1)
        else:
            name, ver = pkg, "unknown"
        assets.append(
            _asset(
                "installed-application",
                name,
                None,
                [ver],
                f"installed via {label} in {rel}",
            )
        )
    return assets


def _parse_pip_packages(tokens: list[str], rel: str, label: str) -> list[dict]:
    assets: list[dict] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable"):
            i += 2
            continue
        if t == ".":
            i += 1
            continue
        if t.startswith("-"):
            i += 1
            continue
        parsed = _parse_requirements_line(t)
        if parsed:
            name, ver = parsed
            assets.append(
                _asset(
                    "package",
                    name,
                    None,
                    [ver],
                    f"installed via {label} in {rel}",
                    ecosystem="PyPI",
                )
            )
        i += 1
    return assets


def _parse_npm_packages(tokens: list[str], rel: str, label: str) -> list[dict]:
    pkgs = [t for t in tokens if not t.startswith("-")]
    assets: list[dict] = []
    for pkg in pkgs:
        if pkg.startswith("@"):
            rest = pkg[1:]
            if "@" in rest:
                slash_pkg, ver = rest.rsplit("@", 1)
                name = "@" + slash_pkg
            else:
                name, ver = pkg, "unknown"
        elif "@" in pkg:
            name, ver = pkg.rsplit("@", 1)
        else:
            name, ver = pkg, "unknown"
        assets.append(
            _asset(
                "package",
                name,
                None,
                [ver],
                f"installed via {label} in {rel}",
                ecosystem="npm",
            )
        )
    return assets


def _parse_simple_packages(tokens: list[str], rel: str, label: str, ecosystem: str) -> list[dict]:
    pkgs = [t for t in tokens if not t.startswith("-")]
    return [
        _asset(
            "package",
            pkg,
            None,
            ["unknown"],
            f"installed via {label} in {rel}",
            ecosystem=ecosystem,
        )
        for pkg in pkgs
    ]


# ============================================================
# Walker and dispatcher
# ============================================================


def _walk(target: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        for fname in filenames:
            yield Path(dirpath) / fname


_REQ_FILE_RE = re.compile(r"^requirements.*\.(txt|in)$")


def _is_requirements_file(path: Path) -> bool:
    name = path.name
    if _REQ_FILE_RE.match(name):
        return True
    if path.parent.name == "requirements" and (name.endswith(".txt") or name.endswith(".in")):
        return True
    return False


def _dispatch(path: Path) -> list[dict]:
    name = path.name
    assets: list[dict] = []
    assets.extend(detect_sentinel(name))
    if name == "pyproject.toml":
        assets.extend(parse_pyproject_toml(path))
    elif name == "Pipfile":
        assets.extend(parse_pipfile(path))
    elif name == "package.json":
        assets.extend(parse_package_json(path))
    elif name == "Cargo.toml":
        assets.extend(parse_cargo_toml(path))
    elif name == "go.mod":
        assets.extend(parse_go_mod(path))
    elif name == "Gemfile":
        assets.extend(parse_gemfile(path))
    elif name == "pom.xml":
        assets.extend(parse_pom_xml(path))
    elif name in ("build.gradle", "build.gradle.kts"):
        assets.extend(parse_build_gradle(path))
    elif name in ("Dockerfile", "Containerfile") or name.endswith(".Dockerfile"):
        assets.extend(parse_dockerfile(path))
    elif name == ".python-version":
        assets.extend(parse_python_version(path))
    elif name == ".nvmrc":
        assets.extend(parse_nvmrc(path))
    elif name == ".ruby-version":
        assets.extend(parse_ruby_version(path))
    elif name == ".tool-versions":
        assets.extend(parse_tool_versions(path))
    elif _is_requirements_file(path):
        if not (EXCLUDE_DEV and _is_dev_requirements(path)):
            assets.extend(parse_requirements_txt(path))
    return assets


def crawl(target: Path | str, *, include_dev: bool = False) -> tuple[list[dict], int]:
    """Crawl a project directory. Return (deduped assets, n_files_scanned).

    ``include_dev`` keeps dev/test/docs dependency groups (excluded by default
    — they're tooling, not the deployed runtime surface).
    """
    global EXCLUDE_DEV
    old_exclude_dev = EXCLUDE_DEV
    EXCLUDE_DEV = not include_dev
    target = Path(target).resolve()
    assets: list[dict] = []
    n_files = 0
    skipped = 0
    try:
        with _target_scope(target):
            for path in _walk(target):
                n_files += 1
                # A parser raising on one file is caught so the rest of the tree
                # is still inventoried — but the skip is NOT silent (logged here
                # + tallied below) so a latent parser bug surfaces as a warning
                # rather than as missing assets under a success exit.
                try:
                    assets.extend(_dispatch(path))
                except Exception as e:  # noqa: BLE001 — isolate per-file failures
                    skipped += 1
                    print(f"warning: skipped {path}: {e}", file=sys.stderr)
    finally:
        EXCLUDE_DEV = old_exclude_dev
    if skipped:
        print(
            f"warning: {skipped} file(s) skipped due to unexpected errors — "
            "inventory may be INCOMPLETE (see warnings above)",
            file=sys.stderr,
        )
    return inventory.dedup(assets), n_files


__all__ = ["crawl"]
