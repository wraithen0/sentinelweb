"""SSRF detection — out-of-band style (signal-only).

The scanner injects a configurable callback URL into common URL-shaped
parameters. If the operator's listener observes a hit, SSRF is confirmed.
This module does NOT probe internal addresses or cloud metadata services
directly — that would be a destructive payload.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

URL_PARAMS = (
    "url",
    "uri",
    "src",
    "source",
    "target",
    "dest",
    "destination",
    "redirect",
    "fetch",
    "next",
    "callback",
    "image",
    "imageurl",
    "feed",
)


def _candidate_urls(url: str, callback: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    base_q = list(parse_qsl(parsed.query, keep_blank_values=True))
    out: list[tuple[str, str]] = []
    for p in URL_PARAMS:
        new_q = [(k, v) for k, v in base_q if k != p]
        new_q.append((p, callback))
        out.append(
            (
                urlunparse(parsed._replace(query=urlencode(new_q))),
                p,
            )
        )
    return out


async def scan(
    url: str,
    scope: ScopePolicy,
    client: Client,
    *,
    callback_url: str,
) -> list[Finding]:
    """Send SSRF probes pointing at ``callback_url``.

    The operator is responsible for running a listener at ``callback_url``
    and confirming any hits. SentinelWeb only records that the probe was
    sent.
    """
    scope.assert_in_scope(url)
    if not callback_url.startswith(("http://", "https://")):
        raise ValueError("callback_url must be an http(s) URL")

    findings: list[Finding] = []
    for probe_url, param in _candidate_urls(url, callback_url):
        resp = await client.get(probe_url)
        # No automatic confirmation — emit an INFO record so operator can
        # cross-reference with their listener logs.
        findings.append(
            Finding(
                id=f"SSRF-PROBE-{param.upper()}",
                title=f"SSRF probe sent via `{param}` (verify with listener)",
                severity=Severity.INFO,
                confidence=Confidence.TENTATIVE,
                target=url,
                category="ssrf",
                cwe="918",
                description=(
                    f"SentinelWeb sent a callback URL ({callback_url}) in "
                    f"parameter `{param}`. Inspect your listener — a hit "
                    f"confirms server-side request forgery. Do not use "
                    f"internal IPs or cloud-metadata endpoints as callbacks."
                ),
                remediation=(
                    "Validate URL parameters against an allowlist; resolve "
                    "DNS server-side and reject private/loopback addresses; "
                    "block cloud metadata endpoints."
                ),
                detected_by="scanners.ssrf",
                references=[
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                ],
                evidence=[
                    Evidence(
                        description=f"Probe sent via `{param}`",
                        request=f"GET {probe_url}",
                        response_excerpt=f"HTTP {resp.status_code}",
                    )
                ],
            )
        )
    return findings
