"""Reflected-XSS *detection* (signal-only).

Sends a benign canary token in each query parameter and checks whether the
token is reflected unescaped into the response body. We do NOT submit
script payloads — reflected canary + un-encoded HTML context is enough
signal to flag a finding for manual validation.
"""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

CANARY = "sw9173canary\"'"
DANGEROUS_CONTEXTS = re.compile(
    rf"(<[^>]*{re.escape(CANARY)}[^>]*>)"  # inside a tag
    rf"|(<script[^>]*>[^<]*{re.escape(CANARY)})",  # inside <script>
    re.IGNORECASE,
)


def _candidate_urls(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    params = list(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        # Probe a single synthetic parameter so completely unparameterized URLs
        # still get a basic check.
        params = [("q", "")]
    out: list[tuple[str, str]] = []
    for i, (k, _v) in enumerate(params):
        mutated = list(params)
        mutated[i] = (k, CANARY)
        out.append(
            (
                urlunparse(parsed._replace(query=urlencode(mutated))),
                k,
            )
        )
    return out


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    scope.assert_in_scope(url)
    findings: list[Finding] = []

    for probe_url, param in _candidate_urls(url):
        resp = await client.get(probe_url)
        body = resp.text or ""
        if CANARY not in body:
            continue

        # Distinguish encoded vs raw reflection.
        encoded = html.escape(CANARY)
        only_encoded = encoded in body and CANARY not in body.replace(encoded, "")
        if only_encoded:
            continue

        dangerous = bool(DANGEROUS_CONTEXTS.search(body))
        sev = Severity.HIGH if dangerous else Severity.MEDIUM
        title = (
            f"Reflected input in dangerous context via `{param}` (potential XSS)"
            if dangerous
            else f"Reflected input via `{param}` (review for XSS)"
        )
        findings.append(
            Finding(
                id=f"XSS-REFLECTED-{param.upper()}",
                title=title,
                severity=sev,
                confidence=Confidence.TENTATIVE if not dangerous else Confidence.FIRM,
                target=url,
                category="xss",
                cwe="79",
                description=(
                    f"The value of parameter `{param}` was reflected into the "
                    f"response body without HTML-encoding. SentinelWeb only "
                    f"injects a benign canary; manual validation is required "
                    f"to confirm executability."
                ),
                remediation=(
                    "Context-aware output encoding (HTML, attribute, JS, URL). "
                    "Prefer safe templating frameworks; validate and reject "
                    "untrusted input in JS sinks."
                ),
                detected_by="scanners.xss",
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
                evidence=[
                    Evidence(
                        description=f"Canary `{CANARY}` reflected via `{param}`",
                        request=f"GET {probe_url}",
                        response_excerpt=_extract_excerpt(body, CANARY),
                    )
                ],
            )
        )
    return findings


def _extract_excerpt(body: str, needle: str, window: int = 80) -> str:
    idx = body.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - window)
    end = min(len(body), idx + len(needle) + window)
    return body[start:end]
