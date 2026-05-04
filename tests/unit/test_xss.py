from __future__ import annotations

import html

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import xss as xss_scanner
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_unencoded_reflection_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/search").mock(
        return_value=Response(200, text=f"<div>results for {xss_scanner.CANARY}</div>")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await xss_scanner.scan(
            "https://example.test/search?q=foo", policy, client
        )
    assert findings


@pytest.mark.asyncio
@respx.mock
async def test_encoded_reflection_suppressed(policy: ScopePolicy) -> None:
    encoded = html.escape(xss_scanner.CANARY, quote=True)
    body = f"<div>results for {encoded}</div>"
    respx.get("https://example.test/search").mock(
        return_value=Response(200, text=body)
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await xss_scanner.scan(
            "https://example.test/search?q=foo", policy, client
        )
    assert not findings


@pytest.mark.asyncio
@respx.mock
async def test_dangerous_context_higher_severity(policy: ScopePolicy) -> None:
    body = f"<script>var q={xss_scanner.CANARY};</script>"
    respx.get("https://example.test/search").mock(
        return_value=Response(200, text=body)
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await xss_scanner.scan(
            "https://example.test/search?q=foo", policy, client
        )
    assert findings
    assert findings[0].severity.value == "high"
