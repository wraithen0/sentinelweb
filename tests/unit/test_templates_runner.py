"""Tests for :mod:`sentinelweb.templates.runner`.

HTTP traffic is mocked through ``respx`` so these tests don't touch
the network. Each case isolates a single matcher branch so a regression
will fail loudly.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.scope.policy import OutOfScopeError, ScopePolicy
from sentinelweb.templates import (
    Template,
    run_templates_against,
)
from sentinelweb.templates.runner import _build_target_url
from sentinelweb.utils.http import make_client


def _template(**overrides: object) -> Template:
    """Build a minimal template, with hooks for overrides."""
    body: dict = {
        "id": overrides.get("id", "test-template"),
        "info": {
            "name": "Test",
            "severity": "medium",
            "category": "test",
            "description": "test",
        },
        "requests": [
            overrides.get(
                "request",
                {
                    "method": "GET",
                    "path": ["/probe"],
                    "matchers": [{"type": "status", "status": [200]}],
                },
            )
        ],
    }
    return Template.model_validate(body)


@pytest.mark.asyncio
@respx.mock
async def test_status_matcher_fires(policy: ScopePolicy) -> None:
    tpl = _template()
    respx.get("http://api.example.test/probe").mock(
        return_value=Response(200, text="ok")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TEMPLATE-TEST-TEMPLATE"
    assert f.severity.value == "medium"
    assert f.target == "http://api.example.test/probe"
    assert "200" in (f.evidence[0].response_excerpt or "")


@pytest.mark.asyncio
@respx.mock
async def test_status_mismatch_no_finding(policy: ScopePolicy) -> None:
    tpl = _template()
    respx.get("http://api.example.test/probe").mock(
        return_value=Response(404, text="missing")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_word_matcher_in_body(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            "matchers": [
                {"type": "word", "words": ["DEBUG"], "case-insensitive": True}
            ],
        }
    )
    respx.get("http://api.example.test/x").mock(
        return_value=Response(200, text="this is debug output")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_regex_matcher_in_body(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            "matchers": [{"type": "regex", "regex": [r"^DB_PASSWORD=.+$"]}],
        }
    )
    respx.get("http://api.example.test/x").mock(
        return_value=Response(200, text="DB_PASSWORD=hunter2\nDEBUG=1\n")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_word_matcher_on_header(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            # Headers are case-insensitive per HTTP spec, and httpx normalizes
            # the keys to lowercase. Templates that look at the header part
            # should set ``case-insensitive: true`` to match what the wire
            # actually carries.
            "matchers": [
                {
                    "type": "word",
                    "part": "header",
                    "words": ["X-Powered-By"],
                    "case-insensitive": True,
                }
            ],
        }
    )
    respx.get("http://api.example.test/x").mock(
        return_value=Response(
            200, text="ok", headers={"X-Powered-By": "Flask/2.0"}
        )
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_negative_matcher(policy: ScopePolicy) -> None:
    """``negative: true`` flips the matcher: fires when the word is absent."""
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            "matchers": [
                {"type": "word", "words": ["secure-banner"], "negative": True}
            ],
        }
    )
    respx.get("http://api.example.test/x").mock(
        return_value=Response(200, text="welcome")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_matchers_condition_and_requires_all(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "words": ["KEYWORD"]},
            ],
        }
    )
    # Status matches but word does NOT — AND should keep this from firing.
    respx.get("http://api.example.test/x").mock(
        return_value=Response(200, text="other text")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_matchers_condition_or_requires_one(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/x"],
            "matchers": [
                {"type": "status", "status": [999]},  # won't match
                {"type": "word", "words": ["KEYWORD"]},  # will match
            ],
        }
    )
    respx.get("http://api.example.test/x").mock(
        return_value=Response(200, text="contains KEYWORD here")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_runner_refuses_out_of_scope(policy: ScopePolicy) -> None:
    tpl = _template()
    async with make_client(rate_per_sec=1000) as client:
        with pytest.raises(OutOfScopeError):
            await run_templates_against(
                [tpl], ["http://attacker.test/"], policy, client
            )


@pytest.mark.asyncio
@respx.mock
async def test_multiple_paths_each_probed(policy: ScopePolicy) -> None:
    tpl = _template(
        request={
            "method": "GET",
            "path": ["/a", "/b", "/c"],
            "matchers": [{"type": "status", "status": [200]}],
        }
    )
    respx.get("http://api.example.test/a").mock(return_value=Response(200, text=""))
    respx.get("http://api.example.test/b").mock(return_value=Response(404, text=""))
    respx.get("http://api.example.test/c").mock(return_value=Response(200, text=""))
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    targets = sorted(f.target for f in findings)
    assert targets == [
        "http://api.example.test/a",
        "http://api.example.test/c",
    ]


def test_build_target_url_refuses_host_changing_path() -> None:
    """A path that changes the host must be refused."""
    with pytest.raises(ValueError, match="different host"):
        _build_target_url("http://api.example.test/", "//attacker.test/x")


def test_build_target_url_normal_join() -> None:
    assert _build_target_url("http://api.example.test", "/foo") == (
        "http://api.example.test/foo"
    )
    assert _build_target_url("http://api.example.test/", "/bar/baz") == (
        "http://api.example.test/bar/baz"
    )


@pytest.mark.asyncio
@respx.mock
async def test_runner_swallows_network_errors(policy: ScopePolicy) -> None:
    """A network error on one path should not abort the run."""
    import httpx

    tpl = _template(
        request={
            "method": "GET",
            "path": ["/dead", "/alive"],
            "matchers": [{"type": "status", "status": [200]}],
        }
    )
    respx.get("http://api.example.test/dead").mock(
        side_effect=httpx.ConnectError("boom")
    )
    respx.get("http://api.example.test/alive").mock(
        return_value=Response(200, text="ok")
    )
    async with make_client(rate_per_sec=1000) as client:
        findings = await run_templates_against(
            [tpl], ["http://api.example.test/"], policy, client
        )
    assert [f.target for f in findings] == ["http://api.example.test/alive"]
