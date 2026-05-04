from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import cors as cors_scanner
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_reflected_origin_with_credentials(policy: ScopePolicy) -> None:
    def handler(request):
        origin = request.headers.get("Origin", "")
        return Response(
            200,
            headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
            text="ok",
        )

    respx.get("https://example.test/api").mock(side_effect=handler)
    async with make_client(rate_per_sec=100) as client:
        findings = await cors_scanner.scan("https://example.test/api", policy, client)
    assert any(f.id == "CORS-REFLECTED-ORIGIN" for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_safe_cors_no_findings(policy: ScopePolicy) -> None:
    respx.get("https://example.test/api").mock(
        return_value=Response(
            200,
            headers={"access-control-allow-origin": "https://trusted.example.test"},
            text="ok",
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await cors_scanner.scan("https://example.test/api", policy, client)
    assert not findings
