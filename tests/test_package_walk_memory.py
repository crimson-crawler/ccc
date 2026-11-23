"""Exercise the real SDK and CLI against large, lazily generated local pages."""

from __future__ import annotations

import asyncio
import json
import threading
import tracemalloc
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_client import CrawlerClient


def test_package_sdk_streams_and_cli_refuses_over_256_mib(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    record_property: Callable[[str, object], None],
) -> None:
    """The iterator stays small; the CLI fails rather than emitting a partial walk."""
    page_bytes = 1024 * 1024
    page_count = 260
    calls: list[int] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            offset = request.get("offset", 0)
            calls.append(offset)
            payload = {
                "ecosystem": "npm",
                "package": "sample",
                "snapshot_id": "a" * 32,
                "next_offset": offset + 1 if offset + 1 < page_count else None,
                "advisories": [{"id": f"GHSA-{offset}", "summary": "x" * page_bytes}],
                "cves": [],
                "errors": [],
            }
            encoded = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", origin)
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "synthetic-test-key")

    async def walk_sdk() -> int:
        async with CrawlerClient(api_key="synthetic-test-key", base_url=origin) as client:
            seen = 0
            async for page in client.iter_package_advisories("npm", "sample"):
                assert page.advisories[0].id == f"GHSA-{seen}"
                seen += 1
            return seen

    try:
        tracemalloc.start()
        assert asyncio.run(walk_sdk()) == page_count
        _, sdk_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        record_property("sdk_tracemalloc_peak", sdk_peak)
        assert sdk_peak < 64 * 1024 * 1024
        assert len(calls) == page_count
        calls.clear()

        tracemalloc.start()
        result = CliRunner().invoke(app, ["--json", "enrich", "package", "npm", "sample"])
        _, cli_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        record_property("cli_tracemalloc_peak", cli_peak)
        record_property("cli_page_count", len(calls))
        assert result.exit_code != 0
        assert "package_walk_too_large" in result.stderr
        assert result.stdout == ""
        assert len(calls) >= 256
        assert cli_peak < 512 * 1024 * 1024
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.mark.parametrize("status", [200, 401])
def test_package_cli_walk_and_auth_error(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    status: int,
) -> None:
    calls: list[int] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            offset = request.get("offset", 0)
            calls.append(offset)
            payload = (
                {"detail": "bad key"}
                if status == 401
                else {
                    "ecosystem": "npm",
                    "package": "sample",
                    "identifier_resolved": True,
                    "snapshot_id": "a" * 32,
                    "next_offset": 1 if offset == 0 else None,
                    "advisories": [
                        {
                            "id": f"GHSA-{offset}",
                            **(
                                {
                                    "licence": "CC-BY-NC-ND-4.0",
                                    "withdrawn": True,
                                    "withdrawn_at": "2024-03-01T03:04:05Z",
                                }
                                if offset
                                else {}
                            ),
                        }
                    ],
                    "cves": [],
                    "errors": [],
                }
            )
            encoded = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "synthetic-test-key")
    try:
        result = CliRunner().invoke(app, ["--json", "enrich", "package", "npm", "sample"])
        if status == 401:
            assert result.exit_code == 3
            assert "401" in result.stderr or "401" in result.stdout
            assert calls == [0]
        else:
            assert result.exit_code == 0, result.stdout + result.stderr
            advisories = json.loads(result.stdout)["advisories"]
            assert [row["id"] for row in advisories] == ["GHSA-0", "GHSA-1"]
            assert advisories[1]["withdrawn"] is True
            assert advisories[1]["withdrawn_at"] == "2024-03-01T03:04:05Z"
            assert calls == [0, 1]
            limited = CliRunner().invoke(app, ["--json", "enrich", "package", "npm", "sample", "--max-bytes", "100"])
            assert limited.exit_code != 0 and limited.stdout == ""
            assert "package_walk_too_large" in limited.stderr
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()
