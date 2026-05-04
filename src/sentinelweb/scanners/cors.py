"""CORS misconfiguration detection.

Tests three classes of CORS bugs:

1. ``Origin`` reflected verbatim with ``Access-Control-Allow-Credentials: true``.
2. ``Access-Control-Allow-Origin: null`` accepted with credentials.
3. ``Access-Control-Allow-Origin: *`` with credentials (impossible per spec
   in browsers, but still a misconfig flag).
"""

from __future__ import annotations

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

_PROBE_ORIGINS = (
    "https://evil.example.test",
    "null",
)


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    scope.assert_in_scope(url)
    findings: list[Finding] = []

    for origin in _PROBE_ORIGINS:
        resp = await client.get(url, headers={"Origin": origin})
        aco = resp.headers.get("access-control-allow-origin", "")
        acc = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        if not aco:
            continue

        if aco == origin and acc:
            findings.append(
                Finding(
                    id="CORS-REFLECTED-ORIGIN",
                    title="CORS reflects arbitrary Origin with credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    target=url,
                    category="cors",
                    cwe="942",
                    description=(
                        "The server reflected the supplied Origin header into "
                        "Access-Control-Allow-Origin while also setting "
                        "Access-Control-Allow-Credentials: true. Any origin "
                        "can read credentialed responses from this endpoint."
                    ),
                    remediation=(
                        "Maintain an explicit allowlist of trusted origins. "
                        "Never reflect arbitrary Origin headers when "
                        "credentials are enabled."
                    ),
                    detected_by="scanners.cors",
                    evidence=[
                        Evidence(
                            description=f"Origin: {origin}",
                            response_excerpt=(
                                f"access-control-allow-origin: {aco}\n"
                                "access-control-allow-credentials: true"
                            ),
                        )
                    ],
                    references=[
                        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    ],
                )
            )
        elif aco == "*" and acc:
            findings.append(
                Finding(
                    id="CORS-WILDCARD-WITH-CREDENTIALS",
                    title="ACAO=* combined with credentials=true",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    category="cors",
                    cwe="942",
                    description=(
                        "Server combines a wildcard Access-Control-Allow-Origin "
                        "with Access-Control-Allow-Credentials: true. Browsers "
                        "will refuse the combination but it indicates a misconfig."
                    ),
                    remediation="Set ACAO to a specific origin or omit credentials.",
                    detected_by="scanners.cors",
                    evidence=[
                        Evidence(
                            description="Wildcard ACAO with credentials",
                            response_excerpt=(
                                f"access-control-allow-origin: {aco}\n"
                                "access-control-allow-credentials: true"
                            ),
                        )
                    ],
                )
            )
    return findings
