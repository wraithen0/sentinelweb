"""IDOR / broken-access-control heuristic detector.

Compares responses for two cookie/auth contexts (e.g. user A vs user B)
on the same URL. If both contexts get a non-error response and the
responses substantially overlap, it's a strong signal of broken access
control on that endpoint.

This module is designed for *authorized* multi-account testing: the
operator must already have valid credentials/cookies for both contexts.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client


@dataclass(frozen=True)
class AuthContext:
    label: str
    cookies: dict[str, str]
    headers: dict[str, str]


async def scan(
    url: str,
    scope: ScopePolicy,
    client: Client,
    *,
    primary: AuthContext,
    secondary: AuthContext,
    similarity_threshold: float = 0.9,
) -> list[Finding]:
    """Run an IDOR comparison between two auth contexts on the same URL.

    The expected outcome on a correctly-authorized endpoint is one of:
        - secondary returns 401/403/404
        - secondary returns a different 200 body (no overlap with primary)
    Anything else is suspicious.
    """
    scope.assert_in_scope(url)
    primary_resp = await client.get(
        url, cookies=primary.cookies, headers=primary.headers
    )
    secondary_resp = await client.get(
        url, cookies=secondary.cookies, headers=secondary.headers
    )

    if primary_resp.status_code >= 400 or secondary_resp.status_code >= 400:
        return []

    p_body = primary_resp.text or ""
    s_body = secondary_resp.text or ""
    if not p_body or not s_body:
        return []

    ratio = difflib.SequenceMatcher(None, p_body, s_body).ratio()
    if ratio < similarity_threshold:
        return []

    return [
        Finding(
            id="IDOR-CROSS-CONTEXT-MATCH",
            title="Endpoint returns same response across two auth contexts",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            target=url,
            category="idor",
            cwe="639",
            description=(
                f"Both `{primary.label}` and `{secondary.label}` received "
                f"successful responses with body similarity {ratio:.2f}. This "
                f"strongly suggests the endpoint does not perform per-user "
                f"authorization. Manual verification required."
            ),
            remediation=(
                "Enforce object-level authorization on every request: verify "
                "the authenticated user owns / is permitted to access the "
                "referenced resource, not just authenticated."
            ),
            detected_by="scanners.idor",
            references=[
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            ],
            evidence=[
                Evidence(
                    description=f"Body similarity: {ratio:.2f}",
                    response_excerpt=(p_body[:240] + "\n---\n" + s_body[:240]),
                )
            ],
        )
    ]
