"""Tests for the CSP analyzer scanner.

Each test exercises one detection rule (or one false-positive guard).
The tests run against a respx mock — no real network — so they're fast
and deterministic.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from sentinelweb.scanners import csp as csp_scanner
from sentinelweb.scope.policy import OutOfScopeError, ScopePolicy
from sentinelweb.utils.http import make_client


def _ids(findings: list) -> set[str]:
    return {f.id for f in findings}


@pytest.mark.asyncio
@respx.mock
async def test_no_csp_header_emits_nothing(policy: ScopePolicy) -> None:
    """The CSP scanner must not duplicate the headers scanner's
    ``HDR-MISSING-CONTENT-SECURITY-POLICY`` finding."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(200, text="")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_unsafe_inline_script_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                    "object-src 'none'; frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    ids = _ids(findings)
    assert "CSP-UNSAFE-INLINE-SCRIPT" in ids
    target_finding = next(f for f in findings if f.id == "CSP-UNSAFE-INLINE-SCRIPT")
    assert target_finding.severity.value == "high"
    assert target_finding.confidence.value == "certain"
    assert target_finding.cwe == "79"
    # Other "missing" findings must NOT fire because the policy sets them
    assert "CSP-MISSING-OBJECT-SRC" not in ids
    assert "CSP-MISSING-FRAME-ANCESTORS" not in ids
    assert "CSP-MISSING-BASE-URI" not in ids


@pytest.mark.asyncio
@respx.mock
async def test_strict_dynamic_suppresses_unsafe_inline(policy: ScopePolicy) -> None:
    """Modern browsers ignore 'unsafe-inline' in the presence of
    'strict-dynamic'. The scanner must mirror that semantic to avoid
    a false positive on policies that opt into the modern model."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "script-src 'strict-dynamic' 'unsafe-inline' 'nonce-abc123'; "
                    "object-src 'none'; frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    ids = _ids(findings)
    assert "CSP-UNSAFE-INLINE-SCRIPT" not in ids
    # And by extension wildcard suppression still applies under strict-dynamic
    assert "CSP-WILDCARD-SCRIPT-SRC" not in ids


@pytest.mark.asyncio
@respx.mock
async def test_unsafe_eval_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "script-src 'self' 'unsafe-eval'; object-src 'none'; "
                    "frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    f = next(f for f in findings if f.id == "CSP-UNSAFE-EVAL")
    assert f.severity.value == "medium"
    assert f.confidence.value == "certain"


@pytest.mark.asyncio
@respx.mock
async def test_wildcard_script_src_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "script-src *; object-src 'none'; frame-ancestors 'self'; "
                    "base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-WILDCARD-SCRIPT-SRC" in _ids(findings)


@pytest.mark.asyncio
@respx.mock
async def test_data_url_script_src_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "script-src 'self' data:; object-src 'none'; "
                    "frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-DATA-URL-SCRIPT-SRC" in _ids(findings)


@pytest.mark.asyncio
@respx.mock
async def test_default_src_none_satisfies_object_src(policy: ScopePolicy) -> None:
    """``default-src 'none'`` removes the ``CSP-MISSING-OBJECT-SRC``
    finding even without an explicit ``object-src``."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; "
                    "frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-MISSING-OBJECT-SRC" not in _ids(findings)


@pytest.mark.asyncio
@respx.mock
async def test_missing_object_src_with_lax_default_detected(
    policy: ScopePolicy,
) -> None:
    """When ``default-src`` is something other than ``'none'``, the
    object-src guard must still fire because objects fall back to the
    lax default."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; "
                    "frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-MISSING-OBJECT-SRC" in _ids(findings)


@pytest.mark.asyncio
@respx.mock
async def test_missing_frame_ancestors_and_base_uri(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    ids = _ids(findings)
    assert "CSP-MISSING-FRAME-ANCESTORS" in ids
    assert "CSP-MISSING-BASE-URI" in ids
    fa = next(f for f in findings if f.id == "CSP-MISSING-FRAME-ANCESTORS")
    assert fa.severity.value == "low"
    assert fa.cwe == "1021"


@pytest.mark.asyncio
@respx.mock
async def test_strict_policy_emits_nothing(policy: ScopePolicy) -> None:
    """A widely-recommended strict policy must produce zero findings."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; "
                    "object-src 'none'; frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_report_only_mode_detected(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy-Report-Only": (
                    "default-src 'none'; script-src 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    ids = _ids(findings)
    assert "CSP-REPORT-ONLY-MODE" in ids
    f = next(f for f in findings if f.id == "CSP-REPORT-ONLY-MODE")
    assert f.severity.value == "info"
    # Directive-level findings must NOT fire on report-only — those are
    # the headers scanner's job (HDR-MISSING-CONTENT-SECURITY-POLICY).
    assert "CSP-MISSING-FRAME-ANCESTORS" not in ids
    assert "CSP-MISSING-BASE-URI" not in ids


@pytest.mark.asyncio
@respx.mock
async def test_enforced_csp_suppresses_report_only_finding(
    policy: ScopePolicy,
) -> None:
    """If both an enforced and a report-only header are present, the
    enforced one is what matters; the ``CSP-REPORT-ONLY-MODE`` finding
    must NOT fire."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                (
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'self'; object-src 'none'; "
                    "frame-ancestors 'self'; base-uri 'self'",
                ),
                (
                    "Content-Security-Policy-Report-Only",
                    "default-src 'none'; script-src 'self' 'unsafe-eval'",
                ),
            ],
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-REPORT-ONLY-MODE" not in _ids(findings)


@pytest.mark.asyncio
async def test_out_of_scope_refused_before_request(policy: ScopePolicy) -> None:
    """Scope gate must fire BEFORE the GET. respx mocks aren't
    registered, so a successful HTTP call would also fail loudly via
    ``UnboundLocalError`` / ``ConnectError`` — but the cleaner signal
    is the ``OutOfScopeError`` itself."""
    async with make_client(rate_per_sec=100) as client:
        with pytest.raises(OutOfScopeError):
            await csp_scanner.scan(
                "https://attacker.test/", policy, client
            )


@pytest.mark.asyncio
@respx.mock
async def test_script_src_falls_back_to_default_src(policy: ScopePolicy) -> None:
    """When ``script-src`` is absent, weaknesses in ``default-src``
    should still trigger the script-src findings."""
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self' 'unsafe-eval'; object-src 'none'; "
                    "frame-ancestors 'self'; base-uri 'self'"
                )
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await csp_scanner.scan(
            "https://example.test/", policy, client
        )
    assert "CSP-UNSAFE-EVAL" in _ids(findings)
