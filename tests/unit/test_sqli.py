from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import sqli as sqli_scanner
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_mysql_error_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/products").mock(
        side_effect=[
            Response(200, text="<html>ok</html>"),  # baseline
            Response(
                500,
                text="You have an error in your SQL syntax; check the manual",
            ),
        ]
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await sqli_scanner.scan(
            "https://example.test/products?id=1", policy, client
        )
    assert findings
    assert findings[0].id.startswith("SQLI-")


@pytest.mark.asyncio
@respx.mock
async def test_error_in_baseline_suppressed(policy: ScopePolicy) -> None:
    respx.get("https://example.test/products").mock(
        return_value=Response(
            500, text="You have an error in your SQL syntax; check the manual"
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await sqli_scanner.scan(
            "https://example.test/products?id=1", policy, client
        )
    assert not findings
