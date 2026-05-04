"""SQL-injection *detection* via error-based heuristics (signal-only).

This scanner sends a single quote in each query parameter and looks for
known SQL error fragments in the response. It does **not** attempt to
exploit, dump data, or run sqlmap. Use the sqlmap integration in
``--detect`` mode if you want deeper coverage.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

ERROR_PATTERNS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"sqlite_error", re.I),
    re.compile(r"odbc sql server driver", re.I),
    re.compile(r"microsoft jet database engine", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"psqlexception", re.I),
    re.compile(r"sqlstate\[", re.I),
)

PROBE = "'"


def _candidate_urls(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    params = list(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        params = [("id", "")]
    out: list[tuple[str, str]] = []
    for i, (k, v) in enumerate(params):
        mutated = list(params)
        mutated[i] = (k, (v or "1") + PROBE)
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
    baseline = await client.get(url)
    baseline_body = baseline.text or ""

    for probe_url, param in _candidate_urls(url):
        resp = await client.get(probe_url)
        body = resp.text or ""

        matched = next((p.pattern for p in ERROR_PATTERNS if p.search(body)), None)
        if not matched:
            continue
        # If the same error appears in baseline, suppress (likely template).
        if any(p.search(baseline_body) for p in ERROR_PATTERNS if p.pattern == matched):
            continue
        findings.append(
            Finding(
                id=f"SQLI-ERROR-{param.upper()}",
                title=f"SQL error revealed via `{param}` (possible SQLi)",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                target=url,
                category="sqli",
                cwe="89",
                description=(
                    f"Submitting a single quote in parameter `{param}` produced "
                    f"a SQL error fragment matching pattern: `{matched}`. "
                    f"This strongly indicates that user input reaches a SQL "
                    f"query without parameterization. Manual validation is "
                    f"required before exploitation testing."
                ),
                remediation=(
                    "Use parameterized queries / prepared statements. Never "
                    "concatenate user input into SQL. Disable verbose database "
                    "errors in production responses."
                ),
                detected_by="scanners.sqli",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
                evidence=[
                    Evidence(
                        description=f"Probe `{param}={PROBE}` triggered a SQL error",
                        request=f"GET {probe_url}",
                        response_excerpt=_extract_match_excerpt(body, matched),
                    )
                ],
            )
        )
    return findings


def _extract_match_excerpt(body: str, pattern: str) -> str:
    m = re.search(pattern, body, re.I)
    if not m:
        return body[:200]
    start = max(0, m.start() - 80)
    end = min(len(body), m.end() + 80)
    return body[start:end]
