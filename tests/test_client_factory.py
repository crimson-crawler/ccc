"""Unit test for :func:`crimson_crawler_cli.client_factory.build_client`."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from crimson_crawler_cli import client_factory
from crimson_crawler_cli.auth import ResolvedAuth


def test_build_client_passes_resolved_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """``build_client`` constructs a ``CrawlerClient`` with the resolved API key.

    Every command test patches ``build_client`` itself, so the real factory body
    is otherwise never exercised. Patch ``CrawlerClient`` at the factory's import
    path and assert the key is forwarded.
    """
    constructed = MagicMock()
    monkeypatch.setattr(client_factory, "CrawlerClient", constructed)

    resolved = ResolvedAuth(source="env", key="k-1234", source_detail="CRIMSON_CRAWLER_API_KEY")
    client_factory.build_client(resolved)

    constructed.assert_called_once_with(api_key="k-1234")
