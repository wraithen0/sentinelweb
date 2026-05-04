"""Open redirect detection.

Looks at common redirect parameters and checks whether the server issues
a 30x to an attacker-controlled host.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

REDIRECT_PARAMS = (
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "returnUrl",
    "destination",
    "rurl",
    "continue",
    "dest",
)

_PROBE = "https://example.test/sentinelweb-redirect-probe"


def _candidate_urls(url: str) -> list[tuple[str, str]]:
    """Return list of (probe_url, injected_param)."""
    parsed = urlparse(url)
    base_q = list(parse_qsl(parsed.query, keep_blank_values=True))
    out: list[tuple[str, str]] = []
    for p in REDIRECT_PARAMS:
        new_q = [(k, v) for k, v in base_q if k != p]
        new_q.append((p, _PROBE))
        out.append(
            (
                urlunparse(parsed._replace(query=urlencode(new_q))),
                p,
            )
        )
    return out


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    scope.assert_in_scope(url)
    findings: list[Finding] = []

    for probe_url, param in _candidate_urls(url):
        resp = await client.get(probe_url, follow_redirects=False)
        if resp.status_code not in (301, 302, 303, 307, 308):
            continue
        location = resp.headers.get("location", "")
        if not location:
            continue
        target_host = urlparse(location).hostname or ""
        if target_host == "example.test":
            findings.append(
                Finding(
                    id=f"REDIRECT-OPEN-{param.upper()}",
                    title=f"Open redirect via `{param}` parameter",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    target=url,
                    category="open-redirect",
                    cwe="601",
                    description=(
                        f"The `{param}` parameter is honored without validation. "
                        f"An attacker can craft a link that redirects victims "
                        f"to an arbitrary external host."
                    ),
                    remediation=(
                        "Validate redirect targets against an allowlist of "
                        "trusted hosts/paths, or use opaque redirect tokens."
                    ),
                    detected_by="scanners.redirect",
                    evidence=[
                        Evidence(
                            description=f"Probe sent with {param}={_PROBE}",
                            request=f"GET {probe_url}",
                            response_excerpt=(
                                f"HTTP/{resp.http_version} {resp.status_code}\n"
                                f"Location: {location}"
                            ),
                        )
                    ],
                    references=[
                        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                    ],
                )
            )
    return findings
