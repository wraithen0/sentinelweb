"""Security-headers audit scanner.

Inspects the response headers of a single URL against a curated checklist
based on OWASP Secure Headers Project guidance.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client


@dataclass(frozen=True)
class HeaderCheck:
    name: str
    required: bool
    severity: Severity
    advice: str
    cwe: str | None = None


CHECKS: tuple[HeaderCheck, ...] = (
    HeaderCheck(
        "strict-transport-security",
        required=True,
        severity=Severity.MEDIUM,
        advice="Set HSTS, e.g. 'max-age=31536000; includeSubDomains; preload'.",
        cwe="319",
    ),
    HeaderCheck(
        "content-security-policy",
        required=True,
        severity=Severity.MEDIUM,
        advice="Define a CSP that restricts script-src/object-src.",
        cwe="1021",
    ),
    HeaderCheck(
        "x-content-type-options",
        required=True,
        severity=Severity.LOW,
        advice="Send 'X-Content-Type-Options: nosniff'.",
        cwe="436",
    ),
    HeaderCheck(
        "referrer-policy",
        required=True,
        severity=Severity.LOW,
        advice="Set Referrer-Policy to e.g. 'strict-origin-when-cross-origin'.",
        cwe="200",
    ),
    HeaderCheck(
        "permissions-policy",
        required=False,
        severity=Severity.INFO,
        advice="Set Permissions-Policy to restrict powerful features (camera, geolocation, etc.).",
    ),
    HeaderCheck(
        "x-frame-options",
        required=False,
        severity=Severity.LOW,
        advice="Set X-Frame-Options 'DENY' or 'SAMEORIGIN' (CSP frame-ancestors is preferred).",
        cwe="1021",
    ),
)


def _grade_existing(name: str, value: str) -> str | None:
    """Return a remediation note when the header value itself is weak."""
    v = value.lower()
    if name == "strict-transport-security":
        if "max-age" not in v:
            return "HSTS present but missing max-age."
        try:
            ma = int(v.split("max-age=")[1].split(";")[0].split(",")[0].strip())
            if ma < 15768000:  # 6 months
                return f"HSTS max-age is short ({ma}s); recommend >=15768000."
        except (ValueError, IndexError):
            return "HSTS header present but unparseable."
    if name == "x-content-type-options" and "nosniff" not in v:
        return "X-Content-Type-Options is set but not to 'nosniff'."
    if name == "referrer-policy" and v.strip() in {"unsafe-url", ""}:
        return "Referrer-Policy is permissive."
    return None


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    """Audit security headers on a single URL."""
    scope.assert_in_scope(url)
    findings: list[Finding] = []
    response = await client.get(url)

    for check in CHECKS:
        present = check.name in {k.lower() for k in response.headers}
        if not present and check.required:
            findings.append(
                Finding(
                    id=f"HDR-MISSING-{check.name.upper()}",
                    title=f"Missing security header: {check.name}",
                    severity=check.severity,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    category="security-headers",
                    cwe=check.cwe,
                    description=(
                        f"The response from {url} does not include the "
                        f"`{check.name}` header."
                    ),
                    remediation=check.advice,
                    detected_by="scanners.headers",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                    evidence=[
                        Evidence(
                            description="Response headers (excerpt)",
                            response_excerpt=_excerpt_headers(response.headers.items()),
                        )
                    ],
                )
            )
            continue
        if present:
            value = response.headers.get(check.name, "")
            note = _grade_existing(check.name, value)
            if note:
                findings.append(
                    Finding(
                        id=f"HDR-WEAK-{check.name.upper()}",
                        title=f"Weak security header value: {check.name}",
                        severity=Severity.LOW,
                        confidence=Confidence.FIRM,
                        target=url,
                        category="security-headers",
                        cwe=check.cwe,
                        description=note,
                        remediation=check.advice,
                        detected_by="scanners.headers",
                        evidence=[
                            Evidence(
                                description=f"{check.name}: {value}",
                                response_excerpt=f"{check.name}: {value}",
                            )
                        ],
                    )
                )
    return findings


def _excerpt_headers(items: Iterable[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in items)
