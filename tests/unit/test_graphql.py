"""Tests for the GraphQL information-disclosure scanner.

Each test exercises a specific behavior we want to be regression-safe:

* The introspection probe MUST trigger only when the response actually
  carries a typed schema (defends against false-positives on noisy
  endpoints that happen to return ``{"data": null}`` or surface errors).
* The developer-UI probe MUST be precise enough that unrelated pages
  containing the substring ``GraphQL`` (e.g. blog posts) do not
  generate a finding — we use canonical brand-string markers.
* The scope gate MUST refuse out-of-scope URLs *before* any HTTP
  traffic is sent.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from sentinelweb.scanners import graphql as graphql_scanner
from sentinelweb.scope.policy import OutOfScopeError, ScopePolicy
from sentinelweb.utils.http import make_client


@pytest.mark.asyncio
@respx.mock
async def test_introspection_exposed_emits_high_certain(policy: ScopePolicy) -> None:
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"__schema": {"queryType": {"name": "Query"}}}},
        )
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(200, text="{}", headers={"content-type": "application/json"})
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    intro = [f for f in findings if f.id == "GRAPHQL-INTROSPECTION-EXPOSED"]
    assert len(intro) == 1
    f = intro[0]
    assert f.severity.value == "high"
    assert f.confidence.value == "certain"
    assert f.cwe == "200"
    assert f.detected_by == "scanners.graphql"
    # Evidence references the discovered queryType name verbatim
    assert any("Query" in (e.response_excerpt or "") for e in f.evidence)


@pytest.mark.asyncio
@respx.mock
async def test_introspection_blocked_returns_no_finding(policy: ScopePolicy) -> None:
    """A server that disables introspection typically responds with errors
    and no ``data.__schema``. Make sure we do NOT alarm in that case."""
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"errors": [{"message": "GraphQL introspection has been disabled"}]},
        )
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(200, text="{}")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert not [f for f in findings if f.id == "GRAPHQL-INTROSPECTION-EXPOSED"]


@pytest.mark.asyncio
@respx.mock
async def test_introspection_data_present_but_not_schema(policy: ScopePolicy) -> None:
    """An endpoint returning ``data`` but without ``__schema.queryType.name``
    must NOT trigger the finding (defends against shape-confusion)."""
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200, json={"data": {"hello": "world"}}
        )
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(200, text="{}")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert not [f for f in findings if f.id == "GRAPHQL-INTROSPECTION-EXPOSED"]


@pytest.mark.asyncio
@respx.mock
async def test_introspection_non_json_body_swallowed(policy: ScopePolicy) -> None:
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(200, text="<html>not json</html>")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_graphiql_ui_detected(policy: ScopePolicy) -> None:
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(404, text="not found")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<!doctype html><html><head><title>GraphiQL</title></head>"
                "<body><div id=\"graphiql\">Loading...</div></body></html>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    ui = [f for f in findings if f.id == "GRAPHQL-GRAPHIQL-EXPOSED"]
    assert len(ui) == 1
    assert ui[0].severity.value == "medium"
    assert ui[0].confidence.value == "firm"


@pytest.mark.asyncio
@respx.mock
async def test_playground_ui_detected(policy: ScopePolicy) -> None:
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(404, text="")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<!doctype html><html><head><title>GraphQL Playground"
                "</title></head><body></body></html>"
            ),
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert any(f.id == "GRAPHQL-PLAYGROUND-EXPOSED" for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_apollo_sandbox_requires_graphql_signal(policy: ScopePolicy) -> None:
    """``Apollo Sandbox`` is a marketing-friendly string. Require a
    second signal (``graphql`` somewhere in the body) to keep
    false-positive rate low."""
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(404, text="")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            # Mentions Apollo Sandbox in copy but is not the actual UI
            text="<html><body>Read about Apollo Sandbox on our blog</body></html>",
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert not [f for f in findings if f.id == "GRAPHQL-APOLLO-SANDBOX-EXPOSED"]


@pytest.mark.asyncio
@respx.mock
async def test_apollo_sandbox_with_graphql_signal_detected(policy: ScopePolicy) -> None:
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(404, text="")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<html><body><div>Apollo Sandbox</div>"
                "<script>window.__APOLLO_GRAPHQL_ENDPOINT = '/graphql';</script>"
                "</body></html>"
            ),
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert any(f.id == "GRAPHQL-APOLLO-SANDBOX-EXPOSED" for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_unrelated_html_no_ui_finding(policy: ScopePolicy) -> None:
    """A page that talks about graphql but has no canonical UI marker
    must not trigger a UI finding."""
    respx.post("https://example.test/graphql").mock(
        return_value=httpx.Response(404, text="")
    )
    respx.get("https://example.test/graphql").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<html><body><h1>Our GraphQL API</h1>"
                "<p>Please use our SDK to query graphql.</p></body></html>"
            ),
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await graphql_scanner.scan(
            "https://example.test/graphql", policy, client
        )
    assert findings == []


@pytest.mark.asyncio
async def test_out_of_scope_refused_before_any_request(policy: ScopePolicy) -> None:
    """The scope gate must fire BEFORE we send the introspection POST.
    A respx mock with no expectations would be a free pass; instead we
    assert OutOfScopeError is raised synchronously and no requests
    happen (respx will reject any unmocked call)."""
    with respx.mock(assert_all_called=True):
        async with make_client(rate_per_sec=100) as client:
            with pytest.raises(OutOfScopeError):
                await graphql_scanner.scan(
                    "https://attacker.test/graphql", policy, client
                )
