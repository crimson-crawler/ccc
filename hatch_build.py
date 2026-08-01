"""Custom Hatch metadata hook — absolute brand URLs in the packaged README.

The CLI ships no generated tree, so unlike the Python SDK there is no build-time guard here. This
module exists only to fix up the README that PyPI renders.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.metadata.plugin.interface import MetadataHookInterface


class PackagedReadmeUrls(MetadataHookInterface):
    """Point the packaged README's brand images at absolute URLs.

    The README in the repository references the art the tree ships (`assets/...`), so a repository
    renders its own header with nothing deployed. PyPI renders that same README standalone, with no
    repository for a relative path to resolve against, and it does not rewrite them. So the packaged
    metadata gets absolute URLs while the file on disk stays relative. Nothing is mutated; each
    surface gets the form that works there.

    `readme` is declared `dynamic` in pyproject.toml because PEP 621 only lets a hook supply a field
    that is not already static.
    """

    PLUGIN_NAME = "packaged-readme-urls"

    #: relative path in the repository -> absolute URL for the packaged copy
    BRAND_URLS = {
        'src="assets/spider.png"': 'src="https://crimsoncrawler.com/logo-icon.png"',
        'src="assets/crimson-crawler-logo.svg"': ('src="https://crimsoncrawler.com/crimson-crawler-logo-cli.svg"'),
    }

    @classmethod
    def rewrite(cls, text: str) -> str:
        for relative, absolute in cls.BRAND_URLS.items():
            text = text.replace(relative, absolute)
        return text

    def update(self, metadata: dict) -> None:
        readme = Path(self.root) / "README.md"
        if not readme.exists():
            return
        metadata["readme"] = {
            "content-type": "text/markdown",
            "text": self.rewrite(readme.read_text(encoding="utf-8")),
        }
