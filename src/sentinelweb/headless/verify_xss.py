"""Promote tentative reflected-XSS findings via headless verification."""

from __future__ import annotations

import logging
import re
import secrets
from collections.abc import Callable, Sequence
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy

log = logging.getLogger(__name__)

VERIFIED_FINDING_PREFIX = "XSS-VERIFIED"

# Regex used to recover the parameter name from the existing scanner's
# id (``XSS-REFLECTED-<UPPERCASED-PARAM>``).
_REFLECTED_ID_RE = re.compile(r"^XSS-REFLECTED-(?P<param>.+)$")


class _Verifier(Protocol):
    """Minimal interface required by :func:`verify_xss_findings`."""

    def verify_title_change(self, url: str, nonce: str) -> bool: ...


def _payload_for(nonce: str) -> str:
    """Return the benign verification payload.

    Sets ``document.title`` to a per-finding marker. No exfiltration,
    no XHR, no form submit — the only side effect is the title.
    """
    return f"<svg/onload=\"document.title='SW_XSS_{nonce}'\">"


def _inject_payload(target: str, param_name_lower: str, payload: str) -> str | None:
    """Mutate ``target``'s query string to set ``param=payload``.

    Returns ``None`` if the parameter is not present and cannot be
    inferred — we'd rather skip verification than fire a payload at a
    URL whose semantics we don't understand.
    """
    parsed = urlparse(target)
    pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    if not pairs:
        # Mirror the scanner's "synthetic q=" probe so we can still
        # verify against unparameterized URLs that the scanner flagged.
        pairs = [("q", "")]
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k.lower() == param_name_lower:
            new_pairs.append((k, payload))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        return None
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _looks_like_reflected_xss(finding: Finding) -> bool:
    return (
        finding.id.startswith("XSS-REFLECTED-")
        and finding.category == "xss"
    )


def _build_verified_finding(original: Finding, probe_url: str) -> Finding:
    match = _REFLECTED_ID_RE.match(original.id)
    if match is None:  # pragma: no cover - filtered out earlier
        param_label = "parameter"
        param_id = "PARAM"
    else:
        param_id = match.group("param")
        param_label = f"`{param_id.lower()}`"
    return Finding(
        id=f"{VERIFIED_FINDING_PREFIX}-{param_id}",
        title=f"Reflected XSS confirmed via {param_label} (headless verification)",
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        target=original.target,
        category="xss",
        cwe="79",
        description=(
            "A benign verification payload (sets `document.title` to a "
            "per-finding nonce, no exfiltration) was rendered and executed "
            f"by a headless Firefox instance. Parameter {param_label} "
            "executes attacker-controlled HTML."
        ),
        remediation=(
            "Context-aware output encoding (HTML, attribute, JS, URL). "
            "Prefer safe templating frameworks; validate and reject "
            "untrusted input in JS sinks."
        ),
        detected_by="headless.verify_xss",
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        tags=["verified-headless"],
        evidence=[
            Evidence(
                description=(
                    "Headless Firefox loaded the payload URL and the page "
                    "title changed to the unique nonce, proving the "
                    "parameter executes injected HTML."
                ),
                request=f"GET {probe_url}",
            )
        ],
    )


def verify_xss_findings(
    findings: Sequence[Finding],
    scope: ScopePolicy,
    verifier: _Verifier,
    *,
    nonce_factory: Callable[[], str] = lambda: secrets.token_hex(8),
) -> list[Finding]:
    """Return a new list of findings extended with verified ones.

    The original tentative ``XSS-REFLECTED-*`` findings are preserved
    unchanged (so triagers can see candidates and verifications side by
    side). For every reflected XSS the verifier confirms, an extra
    ``XSS-VERIFIED-<PARAM>`` finding is appended.

    The caller supplies the verifier instance so unit tests can inject
    a stub without spinning up a real browser.
    """
    extra: list[Finding] = []
    for f in findings:
        if not _looks_like_reflected_xss(f):
            continue
        match = _REFLECTED_ID_RE.match(f.id)
        if match is None:
            continue
        param_lower = match.group("param").lower()
        nonce = nonce_factory()
        payload = _payload_for(nonce)
        probe_url = _inject_payload(f.target, param_lower, payload)
        if probe_url is None:
            log.debug(
                "skipping XSS verification for %s: cannot find parameter %s in target",
                f.id,
                param_lower,
            )
            continue
        try:
            scope.assert_in_scope(probe_url)
        except Exception:
            log.warning("verification target %s out of scope; skipping", probe_url)
            continue
        try:
            confirmed = verifier.verify_title_change(probe_url, nonce)
        except Exception:
            log.warning("headless verification raised on %s; skipping", probe_url, exc_info=True)
            continue
        if confirmed:
            extra.append(_build_verified_finding(f, probe_url))
    return [*findings, *extra]
