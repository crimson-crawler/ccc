"""Shared pytest fixtures for the CLI test suite."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from crimson_crawler_cli import config


def _generated_tree_present() -> bool:
    spec = importlib.util.find_spec("crimson_crawler_client._generated")
    return spec is not None


@pytest.fixture(autouse=True, scope="session")
def _require_generated_sdk() -> None:
    """Skip the suite with a clear message when the SDK's ``_generated`` tree is missing.

    A public source checkout gets the generated layer for free: ``uv sync``
    installs the pinned ``crimson-crawler-client`` release, which ships it.
    An editable Python SDK checkout may not have generated the layer yet, so
    ``from crimson_crawler_client import …`` would raise an
    opaque :class:`ImportError`. Skip once with a diagnostic message instead of
    letting every test fail with the same wall of import errors.
    """
    if not _generated_tree_present():
        pytest.skip(
            "crimson_crawler_client._generated is missing. Install the co-released "
            "`crimson-crawler-client` package, then run `uv sync` and retry. "
            "For an editable Python SDK checkout, run its codegen script first.",
            allow_module_level=True,
        )


@pytest.fixture(autouse=True)
def _reset_output_modes():
    """Reset the ``output`` mode singletons around every test.

    ``output._json_mode`` / ``output._expand_mode`` are module-level globals that
    persist for the process lifetime. In the test runner (one process, many CLI
    invocations) a command — or a test that pokes the globals directly — would
    otherwise leak its mode into the next test. Reset on both sides so the suite
    is order-independent regardless of how any single test sets the flags.
    """
    from crimson_crawler_cli import output

    output.set_json_mode(False)
    output.set_expand_mode(False)
    yield
    output.set_json_mode(False)
    output.set_expand_mode(False)


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Isolate auth resolution: clear the env var and redirect the config path.

    Returns the path where ``config.CONFIG_FILE`` is now pointed. The file does
    not exist by default — tests that need config-file auth should write to it.
    Tests that want env-var auth can call ``monkeypatch.setenv`` after the
    fixture runs.
    """
    monkeypatch.delenv("CRIMSON_CRAWLER_API_KEY", raising=False)
    monkeypatch.delenv("CRIMSON_CRAWLER_BASE_URL", raising=False)
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(config, "CONFIG_FILE", config_path)
    return config_path


@pytest.fixture()
def secure_config_file(clean_env: Path) -> Path:
    """Create the isolated config file with owner-only permissions."""
    clean_env.touch(mode=0o600)
    return clean_env


class _MockClient:
    """Stand-in for :class:`CrawlerClient` used in CLI command tests.

    Carries every convenience method the CLI calls — the 33 ``/v1`` operations
    plus the four Platform namespaces — each an :class:`AsyncMock`. A test sets
    the return value on the one method its command uses; the factory hands back
    this same instance, so the command's ``async with build_client(...) as
    client`` block sees exactly what the test configured.
    """

    def __init__(self) -> None:
        # The 33 /v1 convenience methods, mirroring PARITY-CONTRACT.local.md.
        for method in (
            "enrich_atlas_full",
            "enrich_batch",
            "enrich_campaign_full",
            "enrich_capec_full",
            "enrich_cve_full",
            "enrich_cwe_full",
            "enrich_defend_full",
            "enrich_disarm_full",
            "enrich_group_full",
            "enrich_ioc_full",
            "enrich_location_full",
            "enrich_package_full",
            "enrich_poc_source",
            "enrich_product_full",
            "enrich_sector_full",
            "enrich_software_full",
            "enrich_technique_full",
            "search_cti",
            "search_cve",
            "search_d3fend",
            "search_kev",
            "search_knowledgebase",
            "search_misp",
            "search_poc",
            "search_techniques",
            "search_vendor",
            "assess_group_exposure",
            "assess_ioc_portfolio",
            "assess_technique_coverage",
            "assess_vulnerability_exposure",
            "artifact_enrich",
            "artifact_enrich_status",
            "inventory_enrich",
            "inventory_enrich_status",
        ):
            setattr(self, method, AsyncMock())
        # client.enricher namespace — the async Artifact Enricher engine (submit→poll).
        self.enricher = MagicMock()
        self.enricher.enrich = AsyncMock()
        # client.artifact_manager namespace (library only) — each method an AsyncMock, mirroring ArtifactManagerAPI.
        self.artifact_manager = MagicMock()
        for method in (
            "discovery",
            "list_artifacts",
            "upload_artifacts",
            "get_artifact",
            "get_artifact_raw",
            "update_artifact",
            "delete_artifact",
            "copy_artifact",
            "bulk_delete",
            "move_to_folder",
            "bulk_set_favorite",
            "download_bundle",
            "get_rating",
            "set_rating",
            "list_exports",
            "get_export",
            "download_all_exports",
            "compare_enrichments",
            "save_enrichment",
            "list_folders",
            "create_folder",
            "rename_folder",
            "delete_folder",
            "download_folder",
        ):
            setattr(self.artifact_manager, method, AsyncMock())
        # client.inventory_manager namespace — mirroring InventoryManagerAPI (its own section).
        self.inventory_manager = MagicMock()
        for method in (
            "list_inventories",
            "get_inventory",
            "get_inventory_context",
            "list_enrichments",
            "compare_enrichments",
            "create_inventory",
            "update_inventory",
            "delete_inventory",
            "attach_to_inventory",
            "detach_from_inventory",
            "set_monitoring",
            "set_favorite",
            "get_automation",
            "set_automation",
            "enrich_inventory",
            "save_enrichment",
            "parse_scan",
            "parse_multi",
            "enrich_items",
            "ingest_scan",
            "import_inventory",
            "import_multi",
            "export_inventory",
            "list_export_formats",
            "replace_assets",
            "add_assets",
            "apply_asset_fix",
            "set_attachments",
            "add_attachments",
        ):
            setattr(self.inventory_manager, method, AsyncMock())
        # client.ai_reports namespace — mirroring AiReportsAPI (the Report Generator section).
        self.ai_reports = MagicMock()
        for method in (
            "discovery",
            "list_templates",
            "list_reports",
            "get_report",
            "get_report_raw",
            "create_draft",
            "fill_section",
            "section",
            "rename_report",
            "delete_report",
            "export_report",
            "generate_report",
        ):
            setattr(self.ai_reports, method, AsyncMock())
        self.api = MagicMock()
        self.aclose = AsyncMock()

    async def __aenter__(self) -> "_MockClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


@pytest.fixture()
def mock_sdk(monkeypatch: pytest.MonkeyPatch) -> _MockClient:
    """Patch the ``build_client`` reference in every command module.

    Returning the same instance every call lets a single test configure return
    values once. Combine with ``monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", ...)``
    (or via the ``clean_env`` fixture + a config-file write) so auth resolves
    before the command reaches the SDK call.
    """
    instance = _MockClient()

    def _factory(_resolved: object) -> _MockClient:
        return instance

    from crimson_crawler_cli import client_factory
    from crimson_crawler_cli.commands import (
        artifact_manager,
        assess,
        enrich,
        enrich_artifact,
        enrich_inventory,
        ingest,
        inventory_manager,
        reports,
        search,
        search_techniques,
    )

    monkeypatch.setattr(client_factory, "build_client", _factory)
    for module in (
        enrich,
        search,
        assess,
        enrich_artifact,
        enrich_inventory,
        search_techniques,
        artifact_manager,
        inventory_manager,
        reports,
        ingest,
    ):
        monkeypatch.setattr(module, "build_client", _factory)
    return instance
