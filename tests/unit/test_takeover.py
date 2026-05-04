"""Tests for :mod:`sentinelweb.scanners.takeover`.

DNS resolution is monkeypatched (no network), and the HTTP probe is
mocked through respx. Each test exercises a specific branch of the
fingerprint logic.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
import respx
from httpx import Response

from sentinelweb.scanners import takeover
from sentinelweb.scope.policy import ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.fixture(autouse=True)
def _stub_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[list[str]], None]:
    """Replace the CNAME resolver with a deterministic stub.

    Returns a setter so each test can declare the chain it wants to
    exercise without touching real DNS.
    """
    chain: list[str] = []

    async def _fake_resolve_cname_chain(host: str) -> list[str]:
        # ``host`` is unused for the stub; tests configure ``chain``.
        _ = host
        return list(chain)

    monkeypatch.setattr(
        takeover, "_resolve_cname_chain", _fake_resolve_cname_chain
    )

    def set_chain(new: list[str]) -> None:
        chain.clear()
        chain.extend(new)

    return set_chain


@pytest.mark.asyncio
@respx.mock
async def test_no_cname_no_findings(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    _stub_dns([])
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_cname_match_with_unclaimed_marker_emits_firm_finding(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    _stub_dns(["my-app.github.io"])
    respx.get("https://orphan.example.test/").mock(
        return_value=Response(404, text="There isn't a GitHub Pages site here.")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TAKEOVER-GITHUB-PAGES"
    assert f.severity.value == "high"
    assert f.confidence.value == "firm"
    assert f.target == "orphan.example.test"
    assert "GitHub Pages" in f.title


@pytest.mark.asyncio
@respx.mock
async def test_cname_match_without_marker_emits_advisory(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    _stub_dns(["my-app.github.io"])
    respx.get("https://orphan.example.test/").mock(
        return_value=Response(200, text="<html>Real site</html>")
    )
    respx.get("http://orphan.example.test/").mock(
        return_value=Response(200, text="<html>Real site</html>")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TAKEOVER-GITHUB-PAGES-CNAME-ADVISORY"
    assert f.severity.value == "low"
    assert f.confidence.value == "tentative"


@pytest.mark.asyncio
@respx.mock
async def test_cname_unrelated_provider_no_findings(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    """A CNAME to an unknown SaaS shouldn't emit anything."""
    _stub_dns(["internal.corp.example.test"])
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_takeover_refuses_out_of_scope(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    _stub_dns(["my-app.github.io"])
    async with make_client(rate_per_sec=100) as client:
        with pytest.raises(Exception, match="not allowed by scope"):
            await takeover.scan("attacker.test", policy, client)


@pytest.mark.asyncio
@respx.mock
async def test_aws_s3_fingerprint(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    _stub_dns(["my-bucket.s3.amazonaws.com"])
    respx.get("https://orphan.example.test/").mock(
        return_value=Response(
            404,
            text="<Error><Code>NoSuchBucket</Code></Error>",
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert len(findings) == 1
    assert findings[0].id == "TAKEOVER-AWS-S3"


@pytest.mark.asyncio
@respx.mock
async def test_chain_terminating_in_known_provider(
    policy: ScopePolicy,
    _stub_dns: Callable[[list[str]], None],
) -> None:
    """CNAME chain example.test -> intermediate -> heroku is detected."""
    _stub_dns(["intermediate.corp.test", "myapp.herokuapp.com"])
    respx.get("https://orphan.example.test/").mock(
        return_value=Response(404, text="No such app")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await takeover.scan("orphan.example.test", policy, client)
    assert findings and findings[0].id == "TAKEOVER-HEROKU"


def test_match_fingerprint_helper_is_pure() -> None:
    """Direct unit test of the pattern matcher (no network, no async)."""
    fp = takeover._match_fingerprint("user.github.io")
    assert fp is not None and fp.service == "GitHub Pages"
    assert takeover._match_fingerprint("nope.example.com") is None
