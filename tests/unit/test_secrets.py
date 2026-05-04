"""Tests for the secrets scanner.

The pattern catalog is curated for high precision, so for each rule we
prove BOTH that a known-good secret of that family is detected AND that an
obvious negative (a similar-looking string just outside the rule's bounds)
is not. This is the regression net that keeps future pattern tweaks from
silently turning the scanner into a noise generator.

Fixtures are deliberately assembled from string fragments rather than
written as literals: the goal is to make this file safe to commit even
when GitHub Push Protection is enabled, while still exercising the same
regexes the live scanner uses.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from sentinelweb.reporting.findings import Confidence, Severity
from sentinelweb.scanners import secrets as secrets_scanner
from sentinelweb.scanners._secrets_patterns import (
    SecretPattern,
    patterns,
    redact_match,
)
from sentinelweb.scope.policy import OutOfScopeError, ScopePolicy
from sentinelweb.utils.http import make_client

# Build secret-shaped fixtures from fragments so the source file does not
# itself contain a string that GitHub's secret scanner would flag.
_SLACK_HOOK = "https://hooks.slack" + ".com/services"
_SLACK_WEBHOOK_POSITIVE = (
    f"{_SLACK_HOOK}/T01ABCDEFGH/B01ABCDEFGH/" + "A" * 24
)
_SLACK_WEBHOOK_NEGATIVE = f"{_SLACK_HOOK}/T01ABCDEFGH/Bnope/short"

# ---------------------------------------------------------------------------
# Pattern-by-pattern ground-truth corpus.
# Each entry is (pattern_id, positive_sample, negative_sample).
# Positives MUST match exactly; negatives MUST NOT match.
# ---------------------------------------------------------------------------
GROUND_TRUTH: list[tuple[str, str, str]] = [
    (
        "AWS-ACCESS-KEY-ID",
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAIOSFODNN7EXAMPLE_TOO_LONG_AND_BAD",  # extra chars break boundary
    ),
    (
        "GITHUB-PAT-CLASSIC",
        "ghp_" + "a" * 36,
        "ghp_" + "a" * 35,  # one short of rule
    ),
    (
        "GITHUB-PAT-FINE-GRAINED",
        "github_pat_" + "A" * 82,
        "github_pat_" + "A" * 81,
    ),
    (
        "GITHUB-OAUTH",
        "gho_" + "B" * 36,
        "gho_BBBB",
    ),
    (
        "GITHUB-APP-TOKEN",
        "ghs_" + "1" * 36,
        "ghs_short",
    ),
    (
        "GITHUB-USER-TOKEN",
        "ghu_" + "Z" * 36,
        "ghu_short",
    ),
    (
        "GITHUB-REFRESH-TOKEN",
        "ghr_" + "x" * 36,
        "ghr_short",
    ),
    (
        "SLACK-TOKEN",
        "xoxb-1234567890-abcdef-ABCDEFGHIJ",
        "xoxz-1234567890-abcdef",  # invalid type letter
    ),
    (
        "SLACK-WEBHOOK",
        _SLACK_WEBHOOK_POSITIVE,
        _SLACK_WEBHOOK_NEGATIVE,
    ),
    (
        "STRIPE-SECRET-LIVE",
        "sk_live_" + "a" * 32,
        "sk_live_" + "a" * 10,  # too short
    ),
    (
        "STRIPE-RESTRICTED-LIVE",
        "rk_live_" + "x" * 32,
        "rk_live_short",
    ),
    (
        "STRIPE-SECRET-TEST",
        "sk_test_" + "b" * 32,
        "sk_test_short",
    ),
    (
        "STRIPE-PUBLISHABLE-LIVE",
        "pk_live_" + "c" * 32,
        "pk_live_short",
    ),
    (
        "GOOGLE-API-KEY",
        # AIza + exactly 35 chars from [0-9A-Za-z_-]
        "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234",
        # AIza but only 26 chars after prefix (rule wants 35)
        "AIzaSyA-tooshort-abc-def",
    ),
    (
        "GOOGLE-OAUTH-CLIENT-ID",
        # digits + '-' + exactly 32 [0-9a-z] + '.apps.googleusercontent.com'
        "1234567890-abcdef0123456789abcdef0123456789"  # 32 chars after dash
        ".apps.googleusercontent.com",
        "1234567890-too-short.apps.googleusercontent.com",
    ),
    (
        "NPM-TOKEN",
        "npm_" + "Q" * 36,
        "npm_short",
    ),
    (
        "PYPI-TOKEN",
        "pypi-AgE" + "x" * 60,
        "pypi-XYZ" + "x" * 60,  # wrong header bytes
    ),
    (
        "TWILIO-ACCOUNT-SID",
        "AC" + "0" * 32,
        "AC" + "0" * 31,
    ),
    (
        "SENDGRID-API-KEY",
        "SG." + "a" * 22 + "." + "b" * 43,
        "SG." + "a" * 5 + "." + "b" * 5,  # both segments too short
    ),
    (
        "MAILGUN-API-KEY",
        "key-" + "f" * 32,
        "key-" + "f" * 31,
    ),
    (
        "SQUARE-ACCESS-TOKEN",
        "sq0atp-" + "a" * 32,
        "sq0atp-tooshort",
    ),
    (
        "SQUARE-OAUTH-SECRET",
        "sq0csp-" + "a" * 50,
        "sq0csp-shortish",
    ),
    (
        "PRIVATE-KEY-PEM",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "-----BEGIN CERTIFICATE-----\nMIIE...",  # not a private key header
    ),
    (
        "JWT",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-def_ghi",
        "eyJabc-only-one-segment",
    ),
]


def _by_id(pid: str) -> SecretPattern:
    for p in patterns():
        if p.id == pid:
            return p
    raise AssertionError(f"unknown pattern id: {pid}")


@pytest.mark.parametrize("pid,positive,negative", GROUND_TRUTH)
def test_pattern_matches_positive_and_rejects_negative(
    pid: str, positive: str, negative: str
) -> None:
    pattern = _by_id(pid)
    assert pattern.regex.search(positive), (
        f"{pid} must match positive sample"
    )
    assert pattern.regex.search(negative) is None, (
        f"{pid} must reject negative sample {negative!r}"
    )


def test_every_pattern_has_ground_truth() -> None:
    """Failure here means a new pattern was added without a positive+negative
    fixture. Add it to GROUND_TRUTH."""
    covered = {pid for pid, _, _ in GROUND_TRUTH}
    cataloged = {p.id for p in patterns()}
    missing = cataloged - covered
    assert not missing, f"new patterns missing ground-truth fixtures: {sorted(missing)}"


def test_redact_match_for_long_secret_keeps_only_first_and_last_four() -> None:
    redacted = redact_match("AKIAIOSFODNN7EXAMPLE")
    assert redacted == "AKIA***MPLE"
    # The middle MUST NOT be reconstructable from the redacted form.
    assert "IOSFODNN7EXA" not in redacted


def test_redact_match_for_short_value_collapses_uniformly() -> None:
    assert redact_match("abc") == "***"
    assert redact_match("a") == "***"


# ---------------------------------------------------------------------------
# scan_text — pure, network-free entry point.
# ---------------------------------------------------------------------------


def test_scan_text_emits_finding_with_redacted_evidence() -> None:
    body = (
        "/* fetched from CI */\n"
        "const aws = 'AKIAIOSFODNN7EXAMPLE';\n"
        "const stripe = 'sk_live_" + "z" * 32 + "';\n"
    )
    findings = secrets_scanner.scan_text(body, target="https://example.test/app.js")
    ids = {f.id for f in findings}
    assert "SECRETS-AWS-ACCESS-KEY-ID" in ids
    assert "SECRETS-STRIPE-SECRET-LIVE" in ids
    # Critical assertion: the literal secret must NOT appear anywhere in the
    # finding payloads.
    blob = "\n".join(
        (f.description + "\n" + e.response_excerpt)
        for f in findings
        for e in f.evidence
        if e.response_excerpt
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "z" * 32 not in blob
    assert "AKIA***MPLE" in blob


def test_scan_text_dedupes_repeated_secret() -> None:
    secret = "ghp_" + "Q" * 36
    body = "\n".join([f"line {i}: {secret}" for i in range(20)])
    findings = secrets_scanner.scan_text(body, target="x")
    matching = [f for f in findings if f.id == "SECRETS-GITHUB-PAT-CLASSIC"]
    assert len(matching) == 1, "the same secret string should produce exactly one finding"


def test_scan_text_caps_distinct_findings_per_pattern() -> None:
    # Six distinct GitHub PATs in the same body must produce no more than 5
    # findings (the per-pattern cap), so reports stay readable.
    distinct = [f"ghp_{chr(ord('a') + i)}" + "y" * 35 for i in range(6)]
    body = " ".join(distinct)
    findings = secrets_scanner.scan_text(body, target="x")
    matching = [f for f in findings if f.id == "SECRETS-GITHUB-PAT-CLASSIC"]
    assert len(matching) == 5


def test_scan_text_publishable_finding_emitted_at_info() -> None:
    pk = "pk_live_" + "z" * 32
    findings = secrets_scanner.scan_text(pk, target="x")
    [f] = [f for f in findings if f.id == "SECRETS-STRIPE-PUBLISHABLE-LIVE"]
    assert f.severity == Severity.INFO
    assert f.confidence == Confidence.CERTAIN
    assert "intentionally public" in f.remediation.lower()


def test_scan_text_finding_carries_location() -> None:
    findings = secrets_scanner.scan_text(
        "AKIAIOSFODNN7EXAMPLE",
        target="https://example.test/x",
        location="header: Set-Cookie",
    )
    [f] = [f for f in findings if f.id == "SECRETS-AWS-ACCESS-KEY-ID"]
    assert any("header: Set-Cookie" in (e.description or "") for e in f.evidence)


def test_scan_text_with_empty_input_returns_empty() -> None:
    assert secrets_scanner.scan_text("", target="x") == []


# ---------------------------------------------------------------------------
# Async scan() — exercises the HTTP path with mocked transport.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_scan_finds_secrets_in_response_body(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            text='var token = "ghp_' + "A" * 36 + '";',
            headers={"Content-Type": "application/javascript"},
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await secrets_scanner.scan(
            "https://example.test/", policy, client
        )
    ids = {f.id for f in findings}
    assert "SECRETS-GITHUB-PAT-CLASSIC" in ids
    [f] = [f for f in findings if f.id == "SECRETS-GITHUB-PAT-CLASSIC"]
    assert f.detected_by == "scanners.secrets"
    assert "secrets" in f.tags


@pytest.mark.asyncio
@respx.mock
async def test_scan_finds_secrets_in_non_boring_header(
    policy: ScopePolicy,
) -> None:
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            text="hello",
            headers={
                # Not in the boring-headers list, so we DO scan it.
                "X-Debug-Auth": "ghp_" + "C" * 36,
            },
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await secrets_scanner.scan(
            "https://example.test/", policy, client
        )
    [f] = [f for f in findings if f.id == "SECRETS-GITHUB-PAT-CLASSIC"]
    # httpx normalizes header names to lowercase; the scanner inherits that.
    assert any(
        "header: x-debug-auth" in (e.description or "").lower()
        for e in f.evidence
    )


@pytest.mark.asyncio
@respx.mock
async def test_scan_does_not_scan_boring_headers(policy: ScopePolicy) -> None:
    """A JWT-shaped string in Content-Type would be a noise FP. The boring
    list keeps us quiet on standard transport headers."""
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaa"
    respx.get("https://example.test/").mock(
        return_value=Response(
            200,
            text="hi",
            headers={"content-type": f"application/json; trace={fake_jwt}"},
        )
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await secrets_scanner.scan(
            "https://example.test/", policy, client
        )
    assert not any(f.id == "SECRETS-JWT" for f in findings)


@pytest.mark.asyncio
async def test_scan_refuses_out_of_scope(policy: ScopePolicy) -> None:
    async with make_client(rate_per_sec=100) as client:
        with pytest.raises(OutOfScopeError):
            await secrets_scanner.scan(
                "https://elsewhere.invalid/", policy, client
            )


@pytest.mark.asyncio
@respx.mock
async def test_scan_swallows_network_errors(policy: ScopePolicy) -> None:
    respx.get("https://example.test/").mock(
        side_effect=RuntimeError("connection reset")
    )
    async with make_client(rate_per_sec=100) as client:
        findings = await secrets_scanner.scan(
            "https://example.test/", policy, client
        )
    assert findings == []
