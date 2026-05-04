from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import redirect as redirect_scanner
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_open_redirect_detected(policy: ScopePolicy) -> None:
    route = respx.get("https://example.test/login").mock(
        return_value=Response(302, headers={"Location": "https://example.test/sentinelweb-redirect-probe"})
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await redirect_scanner.scan("https://example.test/login", policy, client)
    assert route.called
    assert findings, "expected at least one finding"
    assert any(f.id.startswith("REDIRECT-OPEN-") for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_no_redirect_no_finding(policy: ScopePolicy) -> None:
    respx.get("https://example.test/login").mock(return_value=Response(200, text="ok"))
    async with make_client(rate_per_sec=100) as client:
        findings = await redirect_scanner.scan("https://example.test/login", policy, client)
    assert not findings
