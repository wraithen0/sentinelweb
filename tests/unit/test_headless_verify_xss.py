"""Unit tests for headless XSS verification.

These tests do NOT require Firefox or geckodriver. They feed a stub
verifier into :func:`verify_xss_findings` so we can exercise every
branch deterministically.
"""

from __future__ import annotations

from sentinelweb.headless.verify_xss import (
    VERIFIED_FINDING_PREFIX,
    _inject_payload,
    _payload_for,
    verify_xss_findings,
)
from sentinelweb.reporting.findings import Confidence, Evidence, Finding, Severity
from sentinelweb.scope.policy import ScopePolicy


class StubVerifier:
    """Capture every URL passed to verify_title_change and return ``decisions``.

    ``decisions`` is consumed in order. If ``always`` is set, every call
    returns that boolean without consuming the queue.
    """

    def __init__(
        self,
        decisions: list[bool] | None = None,
        *,
        always: bool | None = None,
    ) -> None:
        self.decisions = list(decisions or [])
        self.always = always
        self.calls: list[tuple[str, str]] = []

    def verify_title_change(self, url: str, nonce: str) -> bool:
        self.calls.append((url, nonce))
        if self.always is not None:
            return self.always
        if not self.decisions:
            return False
        return self.decisions.pop(0)


def _reflected_finding(
    *,
    param: str = "Q",
    target: str = "https://example.test/search?q=foo",
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.TENTATIVE,
) -> Finding:
    """Build a Finding shaped like what scanners.xss emits."""
    return Finding(
        id=f"XSS-REFLECTED-{param}",
        title="Reflected canary",
        severity=severity,
        confidence=confidence,
        target=target,
        category="xss",
        cwe="79",
        description="canary reflected",
        remediation="encode",
        detected_by="scanners.xss",
        evidence=[Evidence(description="reflected")],
    )


# ---------------------------------------------------------------------- payload


def test_payload_is_benign() -> None:
    """The verification payload must not exfiltrate or persist anything."""
    payload = _payload_for("deadbeef")
    assert "SW_XSS_deadbeef" in payload
    # No exfil primitives.
    forbidden = ["fetch(", "XMLHttpRequest", "XHR", "WebSocket", "navigator.sendBeacon",
                 "localStorage", "sessionStorage", "cookie", "form.submit", "location.href",
                 "window.open", "eval("]
    for token in forbidden:
        assert token not in payload, f"payload must not contain {token!r}"


# --------------------------------------------------------------------- _inject_payload


def test_inject_replaces_named_param() -> None:
    out = _inject_payload(
        "https://example.test/s?q=hello&page=2", "q", "<XSS>"
    )
    assert out is not None
    assert "q=%3CXSS%3E" in out
    assert "page=2" in out


def test_inject_case_insensitive_param() -> None:
    out = _inject_payload(
        "https://example.test/s?Search=foo", "search", "<XSS>"
    )
    assert out is not None
    assert "Search=" in out  # original case preserved
    assert "%3CXSS%3E" in out


def test_inject_synthetic_q_when_no_query() -> None:
    """Mirror the scanner's `q=` synthetic probe so unparameterized URLs work."""
    out = _inject_payload("https://example.test/", "q", "<XSS>")
    assert out is not None
    assert "q=%3CXSS%3E" in out


def test_inject_returns_none_when_param_absent() -> None:
    """If the named parameter is not present we MUST NOT fire blindly."""
    out = _inject_payload(
        "https://example.test/s?other=foo", "search", "<XSS>"
    )
    assert out is None


# --------------------------------------------------------------------- verify_xss_findings


def test_verifier_promotes_confirmed_finding(policy: ScopePolicy) -> None:
    findings = [_reflected_finding(param="Q")]
    verifier = StubVerifier(always=True)

    out = verify_xss_findings(
        findings, policy, verifier, nonce_factory=lambda: "abc123"
    )

    # Original is preserved + verified is appended.
    assert len(out) == 2
    assert out[0].id == "XSS-REFLECTED-Q"
    assert out[1].id == f"{VERIFIED_FINDING_PREFIX}-Q"
    assert out[1].severity is Severity.CRITICAL
    assert out[1].confidence is Confidence.CERTAIN
    assert "verified-headless" in out[1].tags
    assert out[1].detected_by == "headless.verify_xss"
    # The verifier was called with the mutated URL containing the marker.
    assert len(verifier.calls) == 1
    url, nonce = verifier.calls[0]
    assert nonce == "abc123"
    assert "SW_XSS_abc123" in url or "SW_XSS_" in url  # encoded form


def test_verifier_does_not_promote_when_unconfirmed(policy: ScopePolicy) -> None:
    findings = [_reflected_finding(param="Q")]
    verifier = StubVerifier(always=False)

    out = verify_xss_findings(findings, policy, verifier)

    assert len(out) == 1
    assert out[0].id == "XSS-REFLECTED-Q"
    assert verifier.calls  # we did try to verify


def test_non_xss_findings_are_passed_through_untouched(policy: ScopePolicy) -> None:
    other = Finding(
        id="HDR-MISSING-CONTENT-SECURITY-POLICY",
        title="Missing CSP",
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        target="https://example.test/",
        category="headers",
        description="missing csp",
    )
    verifier = StubVerifier(always=True)

    out = verify_xss_findings([other], policy, verifier)

    assert out == [other]
    assert verifier.calls == []  # never bothered the verifier


def test_skipped_when_param_not_in_target(policy: ScopePolicy) -> None:
    """Scanner emits XSS-REFLECTED-SEARCH but target has no `search=`."""
    finding = _reflected_finding(
        param="SEARCH", target="https://example.test/?other=foo"
    )
    verifier = StubVerifier(always=True)

    out = verify_xss_findings([finding], policy, verifier)

    assert len(out) == 1
    assert verifier.calls == []  # never fired because we couldn't locate the param


def test_out_of_scope_target_skipped(policy: ScopePolicy) -> None:
    """Defense-in-depth: even if a finding's target is somehow out of scope, skip it."""
    finding = _reflected_finding(
        target="https://admin.example.test/?q=foo"  # admin is in policy.out_of_scope
    )
    verifier = StubVerifier(always=True)

    out = verify_xss_findings([finding], policy, verifier)

    assert len(out) == 1  # original preserved, no verified added
    assert verifier.calls == []


def test_verifier_exception_is_swallowed(policy: ScopePolicy) -> None:
    """A flaky browser must never crash the whole scan."""

    class ExplodingVerifier:
        def verify_title_change(self, url: str, nonce: str) -> bool:
            raise RuntimeError("driver died")

    findings = [_reflected_finding(param="Q")]

    out = verify_xss_findings(findings, policy, ExplodingVerifier())

    assert len(out) == 1
    assert out[0].id == "XSS-REFLECTED-Q"


def test_all_findings_traversed_with_unique_nonces(policy: ScopePolicy) -> None:
    findings = [
        _reflected_finding(param="Q", target="https://example.test/?q=1"),
        _reflected_finding(param="S", target="https://example.test/?s=2"),
    ]
    nonces = iter(["aaa", "bbb"])
    verifier = StubVerifier(always=True)

    out = verify_xss_findings(
        findings, policy, verifier, nonce_factory=lambda: next(nonces)
    )

    assert len(out) == 4  # 2 originals + 2 verified
    assert {f.id for f in out if f.id.startswith(VERIFIED_FINDING_PREFIX)} == {
        f"{VERIFIED_FINDING_PREFIX}-Q",
        f"{VERIFIED_FINDING_PREFIX}-S",
    }
    assert verifier.calls[0][1] == "aaa"
    assert verifier.calls[1][1] == "bbb"


# --------------------------------------------------------------------- contracts


def test_verified_finding_has_no_canary_or_payload_in_evidence(
    policy: ScopePolicy,
) -> None:
    """Verified finding evidence should describe what happened, not leak the payload.

    Specifically the evidence ``description`` should not echo the
    ``<svg/onload>`` payload back so reports stay readable in tooling
    that doesn't HTML-escape strings.
    """
    findings = [_reflected_finding(param="Q")]
    verifier = StubVerifier(always=True)

    out = verify_xss_findings(findings, policy, verifier)

    verified = next(f for f in out if f.id.startswith(VERIFIED_FINDING_PREFIX))
    for ev in verified.evidence:
        assert "<svg" not in ev.description
        assert "<script" not in ev.description
