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
    assert "version" not in comp  # a constraint is not a concrete version
    assert comp["purl"] == "pkg:pypi/requests"  # no version segment
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
        "installed-application",
        "openssl",
        None,
        ["3.0.13-0ubuntu3.4"],
        "installed via dpkg",
        ecosystem="deb",
        namespace="ubuntu",
    )
    comp = inventory.build_inventory([a], "t")["components"][0]
    assert comp["type"] == "application"
    assert "publisher" not in comp  # no null vendor — the namespace carries grouping
    assert comp["group"] == "ubuntu"
    assert comp["purl"] == "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4"


def test_build_inventory_rpm_vendor_becomes_publisher():
    a = inventory.asset(
        "installed-application",
        "openssl",
        "Red Hat, Inc.",
        ["3.0.7"],
        "installed via rpm",
        ecosystem="rpm",
        namespace="rhel",
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
        "<project><dependencies><dependency>"
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
    assert by["openssl"]["ecosystem"] == "deb"  # → pkg:deb/... purl
    assert by["openssl"]["namespace"] == "ubuntu"  # distro is the purl namespace


def test_endpoint_parse_rpm_vendor_and_none():
    by = {a["product"]: a for a in endpoint.parse_rpm("openssl\t3.0.7\tRed Hat, Inc.\nlocal\t1.0\t(none)\n", "rhel")}
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
    assert endpoint.os_distro('NAME="X"\n') == "x"  # no ID → NAME's leading token
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
            run=lambda argv: "",
            which=lambda b: None,
            os_release_path=tmp_path / "absent",
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
    monkeypatch.setattr(
        endpoint,
        "collect",
        lambda: [
            inventory.asset("operating-system", "ubuntu", None, ["24.04"], "os", ecosystem="deb", namespace="ubuntu"),
            inventory.asset(
                "installed-application", "openssl", None, ["3.0.13"], "dpkg", ecosystem="deb", namespace="ubuntu"
            ),
        ],
    )
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
    monkeypatch.setattr(
        endpoint,
        "collect",
        lambda: [
            inventory.asset(
                "installed-application", "openssl", None, ["3.0.13"], "dpkg", ecosystem="deb", namespace="ubuntu"
            ),
        ],
    )
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
    (tmp_path / "Cargo.toml").write_text("[dependencies]\nserde = {version = 1}\n")  # int version
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
        "dependencies {\n"
        '    implementation "com.google.guava:guava:33.0.0-jre"\n'
        '    testImplementation "junit:junit:4.13.2"\n'
        "}\n"
    )
    products = {a["product"] for a in crawl.crawl(tmp_path)[0]}
    assert "com.google.guava:guava" in products
    assert "junit:junit" not in products  # test scope excluded
    products_dev = {a["product"] for a in crawl.crawl(tmp_path, include_dev=True)[0]}
    assert "junit:junit" in products_dev


def test_crawl_gradle_variable_version_is_unknown(tmp_path):
    (tmp_path / "build.gradle").write_text('dependencies {\n    implementation "org.foo:bar:$fooVersion"\n}\n')
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
    assert by["myapp"]["versions"] == ["1.2.3"]  # registry port not a tag
    assert by["tools"]["versions"] == ["unknown"]  # port, no tag
    assert by["python"]["versions"] == ["unknown"]  # digest is not a version
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
    assert "g:junit" not in products  # test scope excluded by default
    assert "g:plugin-dep" not in products  # build-plugin dep is not project surface
    products_dev = {a["product"] for a in crawl.crawl(tmp_path, include_dev=True)[0]}
    assert "g:junit" in products_dev  # --include-dev keeps test scope


def test_endpoint_runner_tolerates_nonzero_exit_with_output():
    # dpkg/rpm can exit nonzero while still printing a usable listing.
    assert endpoint._default_runner(["sh", "-c", "printf 'curl\t8.5.0\n'; exit 1"]) == "curl\t8.5.0\n"


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
    monkeypatch.setattr(crawl, "parse_pom_xml", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    crawl.crawl(tmp_path)
    err = capsys.readouterr().err
    assert "boom" in err  # the per-file warning naming the error
    assert "1 file(s) skipped" in err  # the tally
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


# ============================================================
# #241 — parser coverage for the manifest formats and the
# Dockerfile RUN extractors that the original suite never reached.
# ============================================================


def _by_product(assets):
    return {a["product"]: a for a in assets}


# ---------- Pipfile ----------


def test_parse_pipfile_string_dict_and_star_specs(tmp_path):
    (tmp_path / "Pipfile").write_text(
        '[packages]\nrequests = "==2.31.0"\nflask = "*"\ndjango = { version = ">=4.0" }\nlocal = { path = "." }\n'
    )
    by = _by_product(crawl.parse_pipfile(tmp_path / "Pipfile"))
    assert by["requests"]["versions"] == ["2.31.0"]  # `==` pin cleans to concrete
    assert by["flask"]["versions"] == ["unknown"]  # "*" is not a version
    assert by["django"]["versions"] == [">=4.0"]
    assert by["local"]["versions"] == ["unknown"]  # dict with no version key
    assert by["requests"]["ecosystem"] == "PyPI"


def test_parse_pipfile_malformed_toml_returns_empty(tmp_path):
    (tmp_path / "Pipfile").write_text("[packages\nbroken")
    assert crawl.parse_pipfile(tmp_path / "Pipfile") == []


def test_parse_pipfile_non_table_section_is_ignored(tmp_path):
    (tmp_path / "Pipfile").write_text('packages = "not-a-table"\n')
    assert crawl.parse_pipfile(tmp_path / "Pipfile") == []


# ---------- package.json ----------


def test_parse_package_json_sections_and_engines(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"react": "^19.0.0"},
                "peerDependencies": {"vue": "3.4.0"},
                "optionalDependencies": {"fsevents": "*"},
                "devDependencies": {"vitest": "^2.0.0"},
                "engines": {"node": ">=22", "npm": ">=10"},
            }
        )
    )
    by = _by_product(crawl.parse_package_json(tmp_path / "package.json"))
    assert by["react"]["versions"] == ["^19.0.0"]
    assert by["vue"]["ecosystem"] == "npm"
    assert "fsevents" in by
    assert "vitest" not in by  # dev excluded by default
    assert by["Node.js"]["versions"] == [">=22"]
    assert by["npm"]["versions"] == [">=10"]


def test_parse_package_json_includes_dev_when_flag_off(tmp_path, monkeypatch):
    monkeypatch.setattr(crawl, "EXCLUDE_DEV", False)
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"vitest": "^2.0.0"}}))
    assert "vitest" in _by_product(crawl.parse_package_json(tmp_path / "package.json"))


def test_parse_package_json_malformed_and_non_object(tmp_path):
    (tmp_path / "package.json").write_text("{not json")
    assert crawl.parse_package_json(tmp_path / "package.json") == []
    (tmp_path / "package.json").write_text('["a", "list"]')
    assert crawl.parse_package_json(tmp_path / "package.json") == []


def test_parse_package_json_falsy_version_becomes_unknown(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": ""}}))
    by = _by_product(crawl.parse_package_json(tmp_path / "package.json"))
    assert by["a"]["versions"] == ["unknown"]


# ---------- Cargo.toml ----------


def test_parse_cargo_toml_rust_version_and_dep_forms(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nrust-version = "1.78"\n\n'
        '[dependencies]\nserde = "1.0"\ntokio = { version = "1.38", features = ["full"] }\n'
        'weird = 3\n\n[dev-dependencies]\ncriterion = "0.5"\n'
    )
    by = _by_product(crawl.parse_cargo_toml(tmp_path / "Cargo.toml"))
    assert by["Rust"]["versions"] == ["1.78"]
    assert by["Rust"]["vendor"] == "Rust Foundation"
    assert by["serde"]["versions"] == ["1.0"]
    assert by["tokio"]["versions"] == ["1.38"]
    assert by["weird"]["versions"] == ["unknown"]  # non-str/dict spec
    assert by["serde"]["ecosystem"] == "crates.io"


def test_parse_cargo_toml_malformed_returns_empty(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package\n")
    assert crawl.parse_cargo_toml(tmp_path / "Cargo.toml") == []


# ---------- go.mod ----------


def test_parse_go_mod_block_single_and_go_directive(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/m\n\n"
        "go 1.22\n\n"
        "require (\n"
        "\tgithub.com/pkg/errors v0.9.1\n"
        "\tgithub.com/spf13/cobra v1.8.0 // indirect\n"
        "\n"
        ")\n\n"
        "require github.com/stretchr/testify v1.9.0\n"
    )
    by = _by_product(crawl.parse_go_mod(tmp_path / "go.mod"))
    assert by["Go"]["versions"] == ["1.22"]
    assert by["github.com/pkg/errors"]["versions"] == ["v0.9.1"]
    assert by["github.com/spf13/cobra"]["versions"] == ["v1.8.0"]  # // comment stripped
    assert by["github.com/stretchr/testify"]["versions"] == ["v1.9.0"]
    assert by["github.com/pkg/errors"]["ecosystem"] == "Go"


# ---------- Gemfile ----------


def test_parse_gemfile_ruby_directive_gems_and_comments(tmp_path):
    (tmp_path / "Gemfile").write_text(
        "source 'https://rubygems.org'\nruby '3.3.0'\ngem 'rails', '7.1.0'\ngem 'puma'\n# gem 'commented-out', '1.0'\n"
    )
    by = _by_product(crawl.parse_gemfile(tmp_path / "Gemfile"))
    assert by["Ruby"]["versions"] == ["3.3.0"]
    assert by["rails"]["versions"] == ["7.1.0"]
    assert by["puma"]["versions"] == ["unknown"]
    assert "commented-out" not in by
    assert by["rails"]["ecosystem"] == "RubyGems"


# ---------- version-pin files ----------


def test_parse_python_version_takes_first_line(tmp_path):
    (tmp_path / ".python-version").write_text("3.12.4\n3.11.9\n")
    a = crawl.parse_python_version(tmp_path / ".python-version")[0]
    assert a["product"] == "Python"
    assert a["vendor"] == "Python Software Foundation"
    assert a["versions"] == ["3.12.4"]


def test_parse_python_version_empty_is_unknown(tmp_path):
    (tmp_path / ".python-version").write_text("   \n")
    assert crawl.parse_python_version(tmp_path / ".python-version")[0]["versions"] == ["unknown"]


def test_parse_nvmrc_strips_v_prefix(tmp_path):
    (tmp_path / ".nvmrc").write_text("v22.11.0\n")
    a = crawl.parse_nvmrc(tmp_path / ".nvmrc")[0]
    assert a["product"] == "Node.js"
    assert a["versions"] == ["22.11.0"]


def test_parse_nvmrc_empty_is_unknown(tmp_path):
    (tmp_path / ".nvmrc").write_text("\n")
    assert crawl.parse_nvmrc(tmp_path / ".nvmrc")[0]["versions"] == ["unknown"]


def test_parse_ruby_version(tmp_path):
    (tmp_path / ".ruby-version").write_text("3.3.0\n")
    assert crawl.parse_ruby_version(tmp_path / ".ruby-version")[0]["versions"] == ["3.3.0"]


def test_parse_ruby_version_empty_is_unknown(tmp_path):
    (tmp_path / ".ruby-version").write_text("")
    assert crawl.parse_ruby_version(tmp_path / ".ruby-version")[0]["versions"] == ["unknown"]


def test_parse_tool_versions_known_and_unknown_tools(tmp_path):
    (tmp_path / ".tool-versions").write_text(
        "# a comment\n\npython 3.12.4\nnodejs 22.11.0\nterraform 1.9.0\nsomethingelse 1.2.3\nmalformed\n"
    )
    by = _by_product(crawl.parse_tool_versions(tmp_path / ".tool-versions"))
    assert by["Python"]["vendor"] == "Python Software Foundation"
    assert by["Node.js"]["versions"] == ["22.11.0"]
    assert by["Terraform"]["vendor"] == "HashiCorp"
    assert by["somethingelse"]["vendor"] is None  # unmapped tool keeps its name
    assert "malformed" not in by  # <2 fields is skipped


# ---------- Dockerfile RUN extraction ----------


def test_parse_dockerfile_apt_get_install_with_flags_and_pins(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:12\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "    curl git=1:2.39.5-0+deb12u1\n"
    )
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert by["debian"]["category"] == "operating-system"
    assert by["curl"]["versions"] == ["unknown"]
    assert by["git"]["versions"] == ["1:2.39.5-0+deb12u1"]


def test_parse_dockerfile_apk_add_virtual_flag_consumes_its_argument(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.20\nRUN apk add --no-cache --virtual .build-deps gcc musl-dev=1.2.5-r0\n"
    )
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert ".build-deps" not in by  # --virtual's argument is not a package
    assert by["gcc"]["versions"] == ["unknown"]
    assert by["musl-dev"]["versions"] == ["1.2.5-r0"]


def test_parse_dockerfile_pip_install_forms(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN pip install --no-cache-dir requests==2.31.0 flask\n"
        "RUN pip install -r requirements.txt\n"
        "RUN pip install .\n"
        "RUN python -m pip install httpx>=0.27\n"
    )
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert by["requests"]["versions"] == ["2.31.0"]  # `==` pin cleans to concrete
    assert by["flask"]["versions"] == ["unknown"]
    assert by["httpx"]["versions"] == [">=0.27"]  # a constraint stays verbatim
    assert "requirements.txt" not in by  # -r consumes its argument
    assert "." not in by  # a bare "." is the local project


def test_parse_dockerfile_npm_and_yarn_scoped_packages(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM node:22-alpine\n"
        "RUN npm install -g typescript@5.5.4 @scope/pkg@1.2.3 @scope/bare lodash\n"
        "RUN yarn add vite@5.0.0\n"
    )
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert by["typescript"]["versions"] == ["5.5.4"]
    assert by["@scope/pkg"]["versions"] == ["1.2.3"]
    assert by["@scope/bare"]["versions"] == ["unknown"]
    assert by["lodash"]["versions"] == ["unknown"]
    assert by["vite"]["versions"] == ["5.0.0"]
    assert by["typescript"]["ecosystem"] == "npm"


def test_parse_dockerfile_simple_package_managers(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:24.04\nRUN gem install bundler && cargo install ripgrep && go install golang.org/x/tools/gopls\n"
    )
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert by["bundler"]["ecosystem"] == "RubyGems"
    assert by["ripgrep"]["ecosystem"] == "crates.io"
    assert by["golang.org/x/tools/gopls"]["ecosystem"] == "Go"


def test_parse_dockerfile_sudo_prefix_and_yum_dnf(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM fedora:40\nRUN sudo dnf install -y jq\nRUN yum install -y wget\n")
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert "jq" in by  # `sudo ` prefix stripped before verb matching
    assert "wget" in by


def test_parse_dockerfile_skips_scratch_and_variable_images(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\nFROM ${BASE_IMAGE}\nFROM $(echo img)\nFROM alpine:3.20\n")
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert set(by) == {"alpine"}


def test_parse_dockerfile_unrecognised_run_command_yields_nothing(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nRUN echo hello world\n")
    by = _by_product(crawl.parse_dockerfile(tmp_path / "Dockerfile"))
    assert set(by) == {"alpine"}


# ---------- sentinels / dispatch / walker ----------


@pytest.mark.parametrize(
    "filename,product",
    [
        ("uv.lock", "uv"),
        ("poetry.lock", "Poetry"),
        ("package-lock.json", "npm"),
        ("Cargo.lock", "Cargo"),
        ("Makefile", "make"),
        ("docker-compose.yml", "Docker Compose"),
    ],
)
def test_detect_sentinel_known_files(filename, product):
    assert crawl.detect_sentinel(filename)[0]["product"] == product


def test_detect_sentinel_suffixed_dockerfile_and_unknown():
    assert crawl.detect_sentinel("api.Dockerfile")[0]["product"] == "Docker Engine"
    assert crawl.detect_sentinel("random.txt") == []


@pytest.mark.parametrize(
    "name,expected",
    [
        ("requirements.txt", True),
        ("requirements-dev.in", True),
        ("notrequirements.txt", False),
        ("setup.py", False),
    ],
)
def test_is_requirements_file_by_name(tmp_path, name, expected):
    assert crawl._is_requirements_file(tmp_path / name) is expected


def test_is_requirements_file_inside_requirements_dir(tmp_path):
    d = tmp_path / "requirements"
    d.mkdir()
    assert crawl._is_requirements_file(d / "base.txt") is True
    assert crawl._is_requirements_file(d / "base.md") is False


def test_walk_prunes_noise_directories(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("")
    for pruned in list(crawl.PRUNE_DIRS)[:3]:
        d = tmp_path / pruned
        d.mkdir()
        (d / "should_not_appear.py").write_text("")
    names = {p.name for p in crawl._walk(tmp_path)}
    assert "a.py" in names
    assert "should_not_appear.py" not in names


def test_crawl_counts_files_and_restores_exclude_dev_flag(tmp_path):
    (tmp_path / ".nvmrc").write_text("v22\n")
    (tmp_path / "README.md").write_text("hi")
    before = crawl.EXCLUDE_DEV
    assets, n_files = crawl.crawl(tmp_path)
    assert n_files == 2  # every file is counted, not just parsed ones
    assert crawl.EXCLUDE_DEV is before  # global flag restored after the crawl
    assert "Node.js" in _by_product(assets)


def test_crawl_include_dev_keeps_dev_requirements(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\n")
    assert _by_product(crawl.crawl(tmp_path)[0]) == {}
    assert "pytest" in _by_product(crawl.crawl(tmp_path, include_dev=True)[0])


def test_rel_falls_back_to_name_outside_target(tmp_path):
    with crawl._target_scope(tmp_path / "elsewhere"):
        assert crawl._rel(tmp_path / "a" / "b.txt") == "b.txt"


def test_read_returns_none_on_unreadable_path(tmp_path):
    assert crawl._read(tmp_path / "definitely-missing.txt") is None


# ---------- pyproject.toml (PEP 621 + dependency-groups + Poetry) ----------


def test_parse_pyproject_pep621_sections(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'requires-python = ">=3.12"\n'
        'dependencies = ["httpx>=0.27", "typer", 42]\n'
        "\n[project.optional-dependencies]\n"
        'cli = ["rich>=13"]\n'
        'dev = ["pytest>=8"]\n'
        "\n[build-system]\n"
        'requires = ["hatchling"]\n'
    )
    by = _by_product(crawl.parse_pyproject_toml(tmp_path / "pyproject.toml"))
    assert by["Python"]["versions"] == [">=3.12"]
    assert by["httpx"]["versions"] == [">=0.27"]
    assert by["typer"]["versions"] == ["unknown"]
    assert by["rich"]["versions"] == [">=13"]
    assert by["hatchling"]["versions"] == ["unknown"]
    assert "pytest" not in by  # `dev` optional group excluded by default


def test_parse_pyproject_dependency_groups_dev_excluded(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[dependency-groups]\nruntime = ["orjson>=3"]\ntest = ["pytest>=8"]\n')
    by = _by_product(crawl.parse_pyproject_toml(tmp_path / "pyproject.toml"))
    assert by["orjson"]["versions"] == [">=3"]
    assert "pytest" not in by


def test_parse_pyproject_dependency_groups_included_with_dev(tmp_path, monkeypatch):
    monkeypatch.setattr(crawl, "EXCLUDE_DEV", False)
    (tmp_path / "pyproject.toml").write_text('[dependency-groups]\ntest = ["pytest>=8"]\n')
    assert "pytest" in _by_product(crawl.parse_pyproject_toml(tmp_path / "pyproject.toml"))


def test_parse_pyproject_poetry_dependencies_and_groups(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'requests = "^2.31"\n'
        'pandas = { version = "2.2.0", extras = ["all"] }\n'
        'anything = "*"\n'
        "\n[tool.poetry.group.dev.dependencies]\n"
        'pytest = "^8.0"\n'
        "\n[tool.poetry.group.docs.dependencies]\n"
        'sphinx = "^7.0"\n'
    )
    by = _by_product(crawl.parse_pyproject_toml(tmp_path / "pyproject.toml"))
    assert by["Python"]["vendor"] == "Python Software Foundation"
    assert by["Python"]["versions"] == ["^3.12"]
    assert by["requests"]["versions"] == ["^2.31"]
    assert by["pandas"]["versions"] == ["2.2.0"]
    assert by["anything"]["versions"] == ["unknown"]
    assert "pytest" not in by  # poetry `dev` group excluded
    assert "sphinx" not in by  # `docs` is a dev group too


def test_parse_pyproject_poetry_group_kept_when_not_dev(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry.group.runtime.dependencies]\nujson = "^5.0"\n')
    assert "ujson" in _by_product(crawl.parse_pyproject_toml(tmp_path / "pyproject.toml"))


def test_parse_pyproject_malformed_and_non_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\n")
    assert crawl.parse_pyproject_toml(tmp_path / "pyproject.toml") == []


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("^2.31", "^2.31"),
        ("*", "unknown"),
        ({"version": "1.2.3"}, "1.2.3"),
        ({"version": "*"}, "unknown"),
        ({"version": ""}, "unknown"),
        ({"git": "https://example.com/x.git"}, "unknown"),
        ([{"version": "3.0"}, {"version": "4.0"}], "3.0"),
        ([{"platform": "linux"}], "unknown"),
        (7, "unknown"),
    ],
)
def test_poetry_version_spec_forms(spec, expected):
    assert crawl._poetry_version(spec) == expected
