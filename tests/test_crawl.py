"""Tests for ``ccc crawl`` — project + endpoint inventory collection.

Pure modules (:mod:`inventory`, :mod:`crawl`, :mod:`endpoint`) are tested
directly; commands go through Typer's CliRunner. No SDK, no network, no API —
collection does not enrich. Output is CycloneDX 1.6; the internal collection
shape (``{category, product, vendor, versions[], ecosystem?, namespace?}``) is
an implementation detail tested only where it drives serialization.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import crawl, endpoint, inventory
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import BadInputError, ExitCode


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _by_name(components: list[dict]) -> dict[str, dict]:
    return {c["name"]: c for c in components}


# ============================================================
# inventory primitives
# ============================================================


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("==1.2.3", "1.2.3"),
        ("1.24.0", "1.24.0"),
        (">=3", ">=3"),
        (">= 3.0", ">=3.0"),
        ("*", "unknown"),
        ("", "unknown"),
    ],
)
def test_clean_version(spec, expected):
    assert inventory.clean_version(spec) == expected


@pytest.mark.parametrize(
    ("version", "concrete"),
    [
        ("1.2.3", True),
        ("3.0.13-0ubuntu3.4", True),
        ("v1.10.0", True),
        (">=2.31", False),
        ("^4.19.0", False),
        ("~1.0", False),
        ("unknown", False),
    ],
)
def test_is_concrete_version(version, concrete):
    assert inventory.is_concrete_version(version) is concrete


def test_normalize_package_pep503():
    assert inventory.normalize_package("SQLAlchemy", "PyPI") == "sqlalchemy"
    assert inventory.normalize_package("dogesec_commons", "PyPI") == "dogesec-commons"
    # Non-PyPI just case-folds.
    assert inventory.normalize_package("Lodash", "npm") == "lodash"


# ============================================================
# CycloneDX serialization (the output boundary)
# ============================================================


def test_build_inventory_cyclonedx_envelope():
    a = inventory.asset("package", "fastapi", None, ["0.110.0"], "from requirements.txt", ecosystem="PyPI")
    assert "criticality" not in a  # never present in the internal shape either
    doc = inventory.build_inventory([a], "2026-06-26T00:00:00Z", tool_version="0.5.0")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    assert doc["metadata"]["timestamp"] == "2026-06-26T00:00:00Z"
    assert doc["metadata"]["tools"][0] == {"name": "ccc crawl", "version": "0.5.0"}
    comp = doc["components"][0]
    assert comp == {
        "type": "library",
        "name": "fastapi",
        "version": "0.110.0",
        "purl": "pkg:pypi/fastapi@0.110.0",
        "properties": [{"name": "crimson:notes", "value": "from requirements.txt"}],
    }


def test_build_inventory_empty_emits_no_components():
    doc = inventory.build_inventory([], "2026-06-26T00:00:00Z")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"] == []  # valid CycloneDX, no PLACEHOLDER


def test_build_inventory_constraint_version_becomes_requirement_property():
    a = inventory.asset("package", "requests", None, [">=2.31"], "from requirements.txt", ecosystem="PyPI")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert "version" not in comp                      # a constraint is not a concrete version
    assert comp["purl"] == "pkg:pypi/requests"        # no version segment
    assert {"name": "crimson:requirement", "value": ">=2.31"} in comp["properties"]


def test_build_inventory_unknown_version_has_no_version_no_requirement():
    a = inventory.asset("package", "httpx", None, ["unknown"], "x", ecosystem="PyPI")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert "version" not in comp
    assert comp["purl"] == "pkg:pypi/httpx"
    # 'unknown' is not a requirement — only notes property
    assert all(p["name"] != "crimson:requirement" for p in comp.get("properties", []))


def test_build_inventory_multiple_versions_emit_one_component_each():
    a = inventory.asset("package", "drupal", None, ["7.0", "7.55"], "x", ecosystem="PyPI")
    comps = inventory.build_inventory([a], "t")["components"]
    assert {c["version"] for c in comps} == {"7.0", "7.55"}
    assert {c["purl"] for c in comps} == {"pkg:pypi/drupal@7.0", "pkg:pypi/drupal@7.55"}


def test_build_inventory_maven_namespace_to_group_and_purl():
    a = inventory.asset("package", "org.apache.commons:commons-lang3", None, ["3.14.0"], "x", ecosystem="Maven")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["name"] == "commons-lang3"
    assert comp["group"] == "org.apache.commons"
    assert comp["purl"] == "pkg:maven/org.apache.commons/commons-lang3@3.14.0"


def test_build_inventory_scoped_npm_purl():
    a = inventory.asset("package", "@angular/core", None, ["17.0.0"], "x", ecosystem="npm")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["name"] == "core"
    assert comp["group"] == "@angular"
    # packageurl percent-encodes the @ in the scope
    assert comp["purl"] == "pkg:npm/%40angular/core@17.0.0"


def test_build_inventory_go_module_path_namespace():
    a = inventory.asset("package", "github.com/gin-gonic/gin", None, ["v1.10.0"], "x", ecosystem="Go")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["name"] == "gin"
    assert comp["group"] == "github.com/gin-gonic"
    assert comp["purl"].startswith("pkg:golang/github.com/gin-gonic/gin@v1.10.0")


def test_build_inventory_deb_namespace_purl_and_no_vendor():
    a = inventory.asset(
        "installed-application", "openssl", None, ["3.0.13-0ubuntu3.4"], "installed via dpkg",
        ecosystem="deb", namespace="ubuntu",
    )
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["type"] == "application"
    assert "publisher" not in comp  # no null vendor — the namespace carries grouping
    assert comp["group"] == "ubuntu"
    assert comp["purl"] == "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4"


def test_build_inventory_rpm_vendor_becomes_publisher():
    a = inventory.asset(
        "installed-application", "openssl", "Red Hat, Inc.", ["3.0.7"], "installed via rpm",
        ecosystem="rpm", namespace="rhel",
    )
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["publisher"] == "Red Hat, Inc."
    assert comp["purl"] == "pkg:rpm/rhel/openssl@3.0.7"


def test_build_inventory_operating_system_has_no_purl():
    a = inventory.asset("operating-system", "Ubuntu", None, ["24.04"], "detected from /etc/os-release")
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["type"] == "operating-system"
    assert comp["name"] == "Ubuntu"
    assert comp["version"] == "24.04"
    assert "purl" not in comp  # no reliable CPE/purl for an OS from a crawl


def test_dedup_unions_versions_and_absorbs_none_vendor():
    assets = [
        inventory.asset("package", "requests", None, ["2.0"], "a", ecosystem="PyPI"),
        inventory.asset("package", "requests", None, [">=2.31"], "b", ecosystem="PyPI"),
    ]
    out = inventory.dedup(assets)
    assert len(out) == 1
    assert set(out[0]["versions"]) == {"2.0", ">=2.31"}


def test_dedup_keeps_distinct_namespaces_separate():
    assets = [
        inventory.asset("installed-application", "curl", None, ["8.5.0"], "x", ecosystem="deb", namespace="ubuntu"),
        inventory.asset("installed-application", "curl", None, ["8.6.0"], "x", ecosystem="deb", namespace="debian"),
    ]
    out = inventory.dedup(assets)
    assert len(out) == 2  # different distros don't merge


# ============================================================
# project crawl (internal collection shape — unchanged)
# ============================================================


def test_crawl_project_detects_python_deps(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\nrequests>=2.31\n")
    assets, n_files = crawl.crawl(tmp_path)
    by = {a["product"]: a for a in assets if a.get("ecosystem") == "PyPI"}
    assert by["fastapi"]["versions"] == ["0.110.0"]
    assert by["requests"]["versions"] == [">=2.31"]  # constraint kept verbatim
    assert n_files == 1


def test_crawl_project_excludes_dev_by_default(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0\n")
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    products = {a["product"] for a in crawl.crawl(tmp_path)[0]}
    assert "flask" in products
    assert "pytest" not in products  # dev requirements skipped
    products_dev = {a["product"] for a in crawl.crawl(tmp_path, include_dev=True)[0]}
    assert "pytest" in products_dev


def test_crawl_project_pom_xml_uses_defusedxml(tmp_path):
    (tmp_path / "pom.xml").write_text(
        '<project><dependencies><dependency>'
        "<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>"
        "<version>3.12.0</version></dependency></dependencies></project>"
    )
    assets = crawl.crawl(tmp_path)[0]
    maven = [a for a in assets if a.get("ecosystem") == "Maven"]
    assert maven[0]["product"] == "org.apache.commons:commons-lang3"
    assert maven[0]["versions"] == ["3.12.0"]


# ============================================================
# endpoint collect
# ============================================================


def test_endpoint_parse_dpkg_keeps_version_verbatim():
    assets = endpoint.parse_dpkg("openssl\t3.0.13-0ubuntu3.4\nbash\t5.2.21-2ubuntu4\n", "ubuntu")
    by = {a["product"]: a for a in assets}
    assert by["openssl"]["versions"] == ["3.0.13-0ubuntu3.4"]  # verbatim, not upstream
    assert by["openssl"]["vendor"] is None
    assert by["openssl"]["category"] == "installed-application"
    assert by["openssl"]["ecosystem"] == "deb"        # → pkg:deb/... purl
    assert by["openssl"]["namespace"] == "ubuntu"     # distro is the purl namespace


def test_endpoint_parse_rpm_vendor_and_none():
    by = {a["product"]: a for a in endpoint.parse_rpm(
        "openssl\t3.0.7\tRed Hat, Inc.\nlocal\t1.0\t(none)\n", "rhel"
    )}
    assert by["openssl"]["vendor"] == "Red Hat, Inc."
    assert by["openssl"]["ecosystem"] == "rpm"
    assert by["local"]["vendor"] is None


def test_endpoint_parse_os_release():
    # Product + purl namespace are the distro slug (ID); ecosystem drives the
    # purl type → OS serializes to pkg:deb/ubuntu/ubuntu@24.04 (spec shape).
    assets = endpoint.parse_os_release('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n', ecosystem="deb")
    assert assets[0]["category"] == "operating-system"
    assert assets[0]["product"] == "ubuntu"
    assert assets[0]["namespace"] == "ubuntu"
    assert assets[0]["ecosystem"] == "deb"
    assert assets[0]["versions"] == ["24.04"]


def test_endpoint_os_distro_reads_id_lowercased():
    assert endpoint.os_distro('ID=ubuntu\nNAME="Ubuntu"\n') == "ubuntu"
    assert endpoint.os_distro('ID="Fedora Linux"\n') == "fedora linux"
    assert endpoint.os_distro('NAME="X"\n') == "x"        # no ID → NAME's leading token
    assert endpoint.os_distro("VERSION_ID=99\n") is None  # neither ID nor NAME


def test_endpoint_collect_threads_distro_into_purls(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nNAME="Ubuntu"\nVERSION_ID="24.04"\n')
    assets = endpoint.collect(
        run=lambda argv: "curl\t8.5.0\n",
        which=lambda b: "/x" if b == "dpkg-query" else None,
        os_release_path=os_release,
    )
    curl = next(a for a in assets if a["product"] == "curl")
    assert curl["ecosystem"] == "deb"
    assert curl["namespace"] == "ubuntu"  # distro pulled from os-release ID
    # The OS rides the same distro grouping: pkg:deb/ubuntu/ubuntu@24.04.
    os_asset = next(a for a in assets if a["category"] == "operating-system")
    assert os_asset["product"] == "ubuntu"
    assert os_asset["ecosystem"] == "deb"
    assert os_asset["namespace"] == "ubuntu"


def test_endpoint_collect_raises_without_package_manager(tmp_path):
    with pytest.raises(BadInputError):
        endpoint.collect(
            run=lambda argv: "", which=lambda b: None, os_release_path=tmp_path / "absent",
        )


# ============================================================
# commands — same CycloneDX shape from both sources
# ============================================================

_EXPECTED_KEYS = {"bomFormat", "specVersion", "version", "metadata", "components"}


def test_crawl_project_command_emits_cyclonedx(runner, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    result = runner.invoke(app, ["crawl", "project", str(tmp_path)])
    assert result.exit_code == 0, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert set(doc) == _EXPECTED_KEYS
    assert doc["bomFormat"] == "CycloneDX"
    flask = _by_name(doc["components"])["flask"]
    assert flask["purl"] == "pkg:pypi/flask@3.0"
    assert all("criticality" not in c for c in doc["components"])


def test_crawl_endpoint_command_matches_project_shape(runner, monkeypatch):
    monkeypatch.setattr("crimson_crawler_cli.commands.crawl.platform.system", lambda: "Linux")
    monkeypatch.setattr(endpoint, "collect", lambda: [
        inventory.asset("operating-system", "ubuntu", None, ["24.04"], "os",
                        ecosystem="deb", namespace="ubuntu"),
        inventory.asset("installed-application", "openssl", None, ["3.0.13"], "dpkg",
                        ecosystem="deb", namespace="ubuntu"),
    ])
    result = runner.invoke(app, ["crawl", "endpoint"])
    assert result.exit_code == 0, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert set(doc) == _EXPECTED_KEYS  # identical envelope to `crawl project`
    by = _by_name(doc["components"])
    assert by["openssl"]["purl"] == "pkg:deb/ubuntu/openssl@3.0.13"
    assert by["ubuntu"]["type"] == "operating-system"
    assert by["ubuntu"]["purl"] == "pkg:deb/ubuntu/ubuntu@24.04"  # OS carries the distro purl


def test_crawl_endpoint_command_output_file(runner, monkeypatch, tmp_path):
    monkeypatch.setattr("crimson_crawler_cli.commands.crawl.platform.system", lambda: "Linux")
    monkeypatch.setattr(endpoint, "collect", lambda: [
        inventory.asset("installed-application", "openssl", None, ["3.0.13"], "dpkg",
                        ecosystem="deb", namespace="ubuntu"),
    ])
    out = tmp_path / "inv.json"
    result = runner.invoke(app, ["crawl", "endpoint", "--output", str(out)])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert result.stdout == ""  # document went to the file
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"][0]["name"] == "openssl"


def test_crawl_endpoint_non_linux_guard(runner, monkeypatch):
    monkeypatch.setattr("crimson_crawler_cli.commands.crawl.platform.system", lambda: "Windows")
    result = runner.invoke(app, ["crawl", "endpoint"])
    assert result.exit_code == int(ExitCode.BAD_INPUT)
    assert "Linux only" in result.stderr


# ============================================================
# robustness — malformed manifests must not abort the crawl
# ============================================================


def test_clean_version_bare_operator_is_unknown():
    # A bare operator with no version is not a usable version.
    assert inventory.clean_version(">=") == "unknown"
    assert inventory.clean_version("~=") == "unknown"
    assert inventory.clean_version("===") == "unknown"


def test_split_versions_tolerates_non_string_pins():
    # A TOML int/float version (e.g. `serde = {version = 1}`) must not crash.
    assert inventory.split_versions([1]) == ["1"]
    assert inventory.split_versions([1.5, "2.0"]) == ["1.5", "2.0"]


def test_crawl_survives_malformed_manifests(tmp_path):
    """A directory full of wrong-typed/garbage manifests must not abort the
    crawl — the one valid manifest is still inventoried."""
    (tmp_path / "package.json").write_text("[1, 2, 3]")  # top-level non-object
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "package.json").write_text('{"dependencies": ["x", "y"]}')  # list section
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = {version = 1}\n')  # int version
    (tmp_path / "pyproject.toml").write_text('project = "oops"\n')  # str where table expected
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "pyproject.toml").write_text('[tool.poetry]\ndependencies = "nope"\n')
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")  # the one good file

    assets, _ = crawl.crawl(tmp_path)  # must not raise
    products = {a["product"] for a in assets}
    assert "flask" in products


def test_crawl_requirements_in_nondev_dir_not_dropped(tmp_path):
    """A runtime requirements.txt under a dir named like a dev token (build/,
    ci/, test/) is still a runtime manifest — not dropped."""
    # (build/dist/etc. are pruned as build output — use non-pruned dev-token dirs.)
    for parent in ("ci", "test", "docs"):
        d = tmp_path / parent
        d.mkdir()
        (d / "requirements.txt").write_text(f"pkg-{parent}==1.0\n")
    products = {a["product"] for a in crawl.crawl(tmp_path)[0]}
    assert {"pkg-ci", "pkg-test", "pkg-docs"} <= products


def test_crawl_gradle_test_scopes_excluded_by_default(tmp_path):
    (tmp_path / "build.gradle").write_text(
        'dependencies {\n'
        '    implementation "com.google.guava:guava:33.0.0-jre"\n'
        '    testImplementation "junit:junit:4.13.2"\n'
        '}\n'
    )
    products = {a["product"] for a in crawl.crawl(tmp_path)[0]}
    assert "com.google.guava:guava" in products
    assert "junit:junit" not in products  # test scope excluded
    products_dev = {a["product"] for a in crawl.crawl(tmp_path, include_dev=True)[0]}
    assert "junit:junit" in products_dev


def test_crawl_gradle_variable_version_is_unknown(tmp_path):
    (tmp_path / "build.gradle").write_text(
        'dependencies {\n    implementation "org.foo:bar:$fooVersion"\n}\n'
    )
    bar = next(a for a in crawl.crawl(tmp_path)[0] if a["product"] == "org.foo:bar")
    assert bar["versions"] == ["unknown"]  # $fooVersion is not a version


def test_parse_dockerfile_digest_and_registry_port(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM myregistry:5000/myapp:1.2.3\n"
        "FROM registry.local:443/tools\n"
        "FROM python@sha256:deadbeefcafe\n"
        "FROM ubuntu:22.04\n"
    )
    assets = crawl.parse_dockerfile(tmp_path / "Dockerfile")
    by = {a["product"]: a for a in assets}
    assert by["myapp"]["versions"] == ["1.2.3"]           # registry port not a tag
    assert by["tools"]["versions"] == ["unknown"]          # port, no tag
    assert by["python"]["versions"] == ["unknown"]         # digest is not a version
    assert by["ubuntu"]["versions"] == ["22.04"]
    assert by["ubuntu"]["category"] == "operating-system"


def test_parse_pom_xml_dependency_management_and_property(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project>"
        "<properties><commons.version>3.12.0</commons.version></properties>"
        "<dependencyManagement><dependencies>"
        "<dependency><groupId>org.apache.commons</groupId>"
        "<artifactId>commons-lang3</artifactId>"
        "<version>${commons.version}</version></dependency>"
        "<dependency><groupId>org.foo</groupId><artifactId>bar</artifactId>"
        "<version>${unresolved.prop}</version></dependency>"
        "</dependencies></dependencyManagement>"
        "</project>"
    )
    by = {a["product"]: a for a in crawl.parse_pom_xml(tmp_path / "pom.xml")}
    assert by["org.apache.commons:commons-lang3"]["versions"] == ["3.12.0"]  # resolved
    assert by["org.foo:bar"]["versions"] == ["unknown"]  # unresolved ${...} → unknown


def test_parse_pom_xml_excludes_plugin_and_test_deps(tmp_path):
    """Project deps are collected; build-plugin deps and test-scoped deps are
    not (the latter only when EXCLUDE_DEV — same as Gradle's test scopes)."""
    (tmp_path / "pom.xml").write_text(
        "<project>"
        "<dependencies>"
        "<dependency><groupId>g</groupId><artifactId>runtime-dep</artifactId>"
        "<version>1.0</version></dependency>"
        "<dependency><groupId>g</groupId><artifactId>junit</artifactId>"
        "<version>5.0</version><scope>test</scope></dependency>"
        "</dependencies>"
        "<build><plugins><plugin><groupId>g</groupId><artifactId>some-plugin</artifactId>"
        "<dependencies><dependency><groupId>g</groupId><artifactId>plugin-dep</artifactId>"
        "<version>9.9</version></dependency></dependencies>"
        "</plugin></plugins></build>"
        "</project>"
    )
    products = {a["product"] for a in crawl.crawl(tmp_path)[0]}
    assert "g:runtime-dep" in products
    assert "g:junit" not in products       # test scope excluded by default
    assert "g:plugin-dep" not in products  # build-plugin dep is not project surface
    products_dev = {a["product"] for a in crawl.crawl(tmp_path, include_dev=True)[0]}
    assert "g:junit" in products_dev       # --include-dev keeps test scope


def test_endpoint_runner_tolerates_nonzero_exit_with_output():
    # dpkg/rpm can exit nonzero while still printing a usable listing.
    assert endpoint._default_runner(["sh", "-c", "printf 'curl\t8.5.0\n'; exit 1"]) \
        == "curl\t8.5.0\n"


def test_endpoint_runner_raises_on_nonzero_exit_without_output():
    with pytest.raises(BadInputError):
        endpoint._default_runner(["sh", "-c", "echo boom >&2; exit 2"])


def test_endpoint_runner_replaces_undecodable_bytes():
    # A non-UTF-8 byte in package output must not abort the scan.
    out = endpoint._default_runner(["sh", "-c", r"printf 'a\377b'"])
    assert out.startswith("a") and out.endswith("b")  # decoded, didn't raise


def test_endpoint_parse_rpm_none_version_is_unknown():
    # rpm's "(none)" sentinel for VERSION must not leak as a literal version.
    by = {a["product"]: a for a in endpoint.parse_rpm("pkg\t(none)\tAcme\n")}
    assert by["pkg"]["versions"] == ["unknown"]


def test_endpoint_os_release_version_fallback_takes_leading_token():
    # No VERSION_ID → leading token of VERSION, not the whole marketing string.
    a = endpoint.parse_os_release('NAME="X"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n')[0]
    assert a["versions"] == ["22.04.3"]


def test_pom_plugin_config_properties_do_not_resolve_deps(tmp_path):
    """A <properties> block nested in a plugin <configuration> must NOT feed
    the ${name} resolution map used for dependency versions."""
    (tmp_path / "pom.xml").write_text(
        "<project>"
        "<build><plugins><plugin><configuration><properties>"
        "<dep.version>9.9.9-EVIL</dep.version>"
        "</properties></configuration></plugin></plugins></build>"
        "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>"
        "<version>${dep.version}</version></dependency></dependencies>"
        "</project>"
    )
    by = {a["product"]: a for a in crawl.parse_pom_xml(tmp_path / "pom.xml")}
    assert by["g:a"]["versions"] == ["unknown"]  # plugin-config prop must not resolve it


def test_crawl_skipped_files_are_surfaced(tmp_path, capsys, monkeypatch):
    """A parser that raises is isolated, but the skip is counted and surfaced —
    not silently swallowed under a success exit."""
    (tmp_path / "pom.xml").write_text("<project/>")
    monkeypatch.setattr(crawl, "parse_pom_xml",
                        lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    crawl.crawl(tmp_path)
    err = capsys.readouterr().err
    assert "boom" in err                 # the per-file warning naming the error
    assert "1 file(s) skipped" in err    # the tally
    assert "INCOMPLETE" in err


def test_crawl_skips_oversized_manifest_with_warning(tmp_path, capsys):
    manifest = tmp_path / "package.json"
    manifest.write_bytes(b'{"dependencies":{}}')
    with manifest.open("r+b") as file:
        file.truncate(crawl.MAX_MANIFEST_BYTES + 1)

    assets, scanned = crawl.crawl(tmp_path)

    assert assets == []
    assert scanned == 1
    warning = capsys.readouterr().err
    assert "skipped oversized manifest" in warning
    assert str(manifest) in warning
