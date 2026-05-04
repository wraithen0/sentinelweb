from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.recon import endpoints as recon_endpoints
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_discover_extracts_links_forms_params(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            text="""
                <html><body>
                  <a href="/about">About</a>
                  <a href="https://other.test/x">offsite</a>
                  <form action="/login">
                    <input name="username" />
                    <input name="password" type="password" />
                  </form>
                  <script>fetch('/api/v1/users');</script>
                </body></html>
            """,
        )
    )
    async with make_client(rate_per_sec=100) as client:
        results = await recon_endpoints.discover(
            "https://example.test/", policy, client
        )
    assert "https://example.test/about" in results["urls"]
    assert "https://other.test/x" not in results["urls"]
    assert any(u.endswith("/login") for u in results["forms"])
    assert "username" in results["params"]
    assert "password" in results["params"]
