"""Factory for the :class:`crimson_crawler_client.CrawlerClient`.

Keeping construction in one place lets the test suite mock ``CrawlerClient``
at a single import path (``crimson_crawler_cli.client_factory.CrawlerClient``)
regardless of which command imports it.
"""

from __future__ import annotations

from crimson_crawler_client import CrawlerClient

from .auth import ResolvedAuth


def build_client(resolved: ResolvedAuth) -> CrawlerClient:
    """Return a :class:`CrawlerClient` configured with the resolved API key.

    Honors the SDK's own ``CRIMSON_CRAWLER_BASE_URL`` env-var override —
    the CLI does not expose a separate flag, which keeps the configuration
    surface aligned with the SDK's.

    ``CRIMSON_CRAWLER_VERIFY_SSL`` is also resolved by the SDK itself
    (constructor default ``None`` → env-var fallback) so self-signed-cert
    preview deployments don't need a per-CLI flag either.
    """
    return CrawlerClient(api_key=resolved.key)


__all__ = ["CrawlerClient", "build_client"]
