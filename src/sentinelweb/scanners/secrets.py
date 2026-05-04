"""Secrets-in-responses scanner.

Detects accidentally-exposed credentials in HTTP response bodies, headers,
and inline JavaScript fetched from a single in-scope URL.

Defensive guarantees
--------------------
- **Scope-bound**: ``scope.assert_in_scope(url)`` is the very first step;
  out-of-scope targets raise before any traffic.
- **Read-only**: the scanner only issues a single ``GET``; no probes are
  ever generated to trigger or amplify a leak.
- **Redacted evidence**: matched secrets are stored only as a redacted
  fingerprint (``first4***last4``) — the full secret is never written to
  the audit log, findings.json, or any rendered report.
- **High-precision rules**: see ``_secrets_patterns.py``. Every rule is
  provider-prefixed and length-bounded; no generic ``api_key="..."``
  heuristics that train people to ignore the scanner.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

from ..reporting.findings import Evidence, Finding
from ..scope.policy import ScopePolicy
from ..utils.http import Client
from ._secrets_patterns import SecretPattern, patterns, redact_match

# Cap how many findings we emit *per pattern per target* so a leaked file
# full of (e.g.) test JWTs doesn't drown out the real signal. Triagers can
# always retrieve the file and grep it themselves.
_MAX_PER_PATTERN_PER_TARGET = 5

# Don't try to scan response bodies larger than this (8 MiB). Anything bigger
# is almost certainly a binary asset — and our regex engine will choke on it.
_MAX_BODY_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class _Hit:
    """Internal: one regex hit before deduplication / redaction."""

    pattern: SecretPattern
    matched: str
    location: str  # e.g. "response body", "header: Set-Cookie"


def scan_text(
    text: str,
    target: str,
    *,
    location: str = "response body",
    rules: Iterable[SecretPattern] | None = None,
) -> list[Finding]:
    """Scan a single chunk of text for known secret patterns.

    This is the pure, network-free entry point used by both the async
    scanner and unit tests. ``location`` is included verbatim in the
    finding's evidence to help triagers locate the leak in the original
    response.
    """
    if not text:
        return []

    hits = _collect_hits(text, location, rules=rules)
    if not hits:
        return []

    findings: list[Finding] = []
    seen_per_pattern: dict[str, set[str]] = {}
    for hit in hits:
        bucket = seen_per_pattern.setdefault(hit.pattern.id, set())
        if hit.matched in bucket:
            continue
        if len(bucket) >= _MAX_PER_PATTERN_PER_TARGET:
            continue
        bucket.add(hit.matched)
        findings.append(_build_finding(hit, target))
    return findings


def _collect_hits(
    text: str, location: str, *, rules: Iterable[SecretPattern] | None
) -> list[_Hit]:
    catalog = tuple(rules) if rules is not None else patterns()
    out: list[_Hit] = []
    for pattern in catalog:
        for m in pattern.regex.finditer(text):
            out.append(_Hit(pattern=pattern, matched=m.group(0), location=location))
    return out


def _build_finding(hit: _Hit, target: str) -> Finding:
    p = hit.pattern
    redacted = redact_match(hit.matched)
    base_id = f"SECRETS-{p.id}"
    title = f"Exposed secret: {p.name}"
    description = (
        f"A value matching the {p.name} pattern was observed in the "
        f"{hit.location} of {target}. {p.description}"
    ).strip()
    remediation = (
        "Rotate the credential at the issuing provider, then audit upstream "
        "templates / build pipelines to find how it ended up in this response."
    )
    if p.publishable:
        remediation = (
            "No rotation required: this key class is intentionally public. "
            "Reported for inventory only."
        )
    return Finding(
        id=base_id,
        title=title,
        severity=p.severity,
        confidence=p.confidence,
        target=target,
        category="secrets",
        cwe=p.cwe,
        description=description,
        remediation=remediation,
        detected_by="scanners.secrets",
        references=list(p.references),
        evidence=[
            Evidence(
                description=f"{p.name} fingerprint at {hit.location}",
                response_excerpt=f"{redacted}",
                extra={
                    "pattern_id": p.id,
                    "location": hit.location,
                    "publishable": p.publishable,
                },
            )
        ],
        tags=["secrets", p.id.lower()],
    )


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    """Fetch ``url`` and run the secret patterns over body + headers.

    Raises ``OutOfScopeError`` (re-raised from ``ScopePolicy.assert_in_scope``)
    when ``url`` is not in scope. Network failures are swallowed and an
    empty list is returned — the caller's other scanners run independently.
    """
    scope.assert_in_scope(url)
    try:
        response = await client.get(url)
    except Exception:
        return []

    findings: list[Finding] = []

    # 1. Body (HTML, JS, JSON, plain text, ...). Skip obviously-binary or
    #    very large payloads to avoid pathological regex behavior.
    body = _decode_body(response)
    if body:
        findings.extend(scan_text(body, target=url, location="response body"))

    # 2. Headers. We scan every header value individually (rather than a
    #    flattened blob) so the location string in evidence pinpoints the
    #    leaking header (e.g. ``Set-Cookie``).
    for name, value in response.headers.items():
        # Skip standard, obviously-non-secret headers to keep noise down on
        # the JWT / generic patterns.
        lname = name.lower()
        if lname in _BORING_HEADERS:
            continue
        findings.extend(
            scan_text(value, target=url, location=f"header: {name}")
        )

    return findings


def _decode_body(response: object) -> str:
    """Return the response body as text if it's plausibly textual."""
    # ``response`` is an ``httpx.Response``; we type-erase to keep this
    # module's public surface independent of the HTTP backend.
    text_attr = getattr(response, "text", None)
    if not isinstance(text_attr, str):
        return ""
    content_attr = getattr(response, "content", None)
    if isinstance(content_attr, bytes | bytearray) and len(content_attr) > _MAX_BODY_BYTES:
        return ""
    return text_attr


# Standard non-credential-bearing response headers we don't bother scanning.
_BORING_HEADERS: frozenset[str] = frozenset(
    {
        "content-type",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "date",
        "expires",
        "last-modified",
        "etag",
        "cache-control",
        "vary",
        "accept-ranges",
        "connection",
        "keep-alive",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "strict-transport-security",
        "content-security-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
    }
)


def _classify_target(url: str) -> str:
    """Used by tests; returns 'http' or 'other' for ``url``'s scheme."""
    scheme = (urlparse(url).scheme or "").lower()
    return "http" if scheme in {"http", "https"} else "other"
