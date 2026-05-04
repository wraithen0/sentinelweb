from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import headers as headers_scanner
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_missing_headers_flagged(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(200, headers={"server": "nginx"}, text="hi")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await headers_scanner.scan("https://example.test/", policy, client)
    ids = {f.id for f in findings}
    assert "HDR-MISSING-STRICT-TRANSPORT-SECURITY" in ids
    assert "HDR-MISSING-CONTENT-SECURITY-POLICY" in ids


@pytest.mark.asyncio
@respx.mock
async def test_weak_hsts_flagged(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            headers={
                "strict-transport-security": "max-age=60",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
            },
            text="hi",
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await headers_scanner.scan("https://example.test/", policy, client)
    weak_ids = {f.id for f in findings}
    assert "HDR-WEAK-STRICT-TRANSPORT-SECURITY" in weak_ids


@pytest.mark.asyncio
@respx.mock
async def test_all_headers_present_no_critical(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
            text="hi",
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await headers_scanner.scan("https://example.test/", policy, client)
    # No required header missing.
    missing = [f for f in findings if f.id.startswith("HDR-MISSING-")]
    required = {"strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy"}
    for m in missing:
        assert all(r.upper() not in m.id for r in required)
