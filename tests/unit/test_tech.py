from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.recon import tech as recon_tech
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_detects_basic_stack(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            headers={
                "server": "nginx/1.25.0",
                "x-powered-by": "Express",
                "set-cookie": "connect.sid=abc; Path=/",
            },
            text='<html><script src="/static/runtime/main.js"></script></html>',
        )
    )
    async with make_client(rate_per_sec=100) as client:
        techs = await recon_tech.fingerprint("https://example.test/", policy, client)
    names = {t.name for t in techs}
    assert "nginx" in names
    assert "Express.js" in names
    assert "webpack" in names
