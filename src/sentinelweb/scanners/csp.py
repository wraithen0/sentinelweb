"""Content-Security-Policy weakness analyzer.

The :mod:`headers` scanner already flags missing ``Content-Security-Policy``
headers. This scanner is complementary: it parses a *present* CSP and
flags directives whose **values** weaken the protection in known ways.

The detections follow the CSP-Evaluator (Google, MIT-licensed) and OWASP
CSP cheat-sheet rules:

* ``'unsafe-inline'`` in effective script-src → defeats CSP's main XSS
  defense (unless ``'strict-dynamic'`` is present, which makes browsers
  ignore unsafe-inline).
* ``'unsafe-eval'`` in effective script-src → allows ``eval`` /
  ``Function()`` / ``setTimeout(string)``.
* Wildcard ``*`` source in script-src → permits any script origin.
* ``data:`` source in script-src → an XSS payload can ship its own
  script as a data URL.
* No ``object-src`` (and no ``default-src 'none'``) → ``<object>`` /
  ``<embed>`` can load arbitrary content; modern best practice is
  ``object-src 'none'`` regardless of the rest of the policy.
* No ``frame-ancestors`` → no CSP-level clickjacking defense; falls back
  to ``X-Frame-Options`` which the headers scanner audits separately.
* No ``base-uri`` → a ``<base>`` tag injection (a primitive available in
  many DOM-based XSS contexts) can re-target every relative URL on the
  page.
* CSP delivered via ``Content-Security-Policy-Report-Only`` only → the
  policy is observed, not enforced. This is INFO-level by design — it's
  often a deliberate rollout step — but worth surfacing because it's
  easy to ship a "report-only" header to production by accident.

The scanner is signal-only and stateless: a single ``GET`` per target,
no probes. Scope-gating fires before any HTTP traffic.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

# Source values that must appear on the script-src allowlist for a
# finding to fire. Quoted CSP keywords keep their surrounding
# single-quotes (``'unsafe-inline'`` etc.); literal sources like ``*``
# and ``data:`` do not.
_UNSAFE_INLINE = "'unsafe-inline'"
_UNSAFE_EVAL = "'unsafe-eval'"
_STRICT_DYNAMIC = "'strict-dynamic'"
_NONE = "'none'"
_WILDCARD = "*"
_DATA_SCHEME = "data:"


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a single CSP header value into ``{directive: [tokens...]}``.

    Whitespace and case for the *directive name* are normalized; source
    values are preserved verbatim because keyword tokens like
    ``'unsafe-inline'`` are quoted and case-sensitive.
    """
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        if directive in out:
            # CSP semantics: a repeated directive in the same policy is
            # ignored by browsers (only the first wins). Mirror that so
            # we don't double-count.
            continue
        out[directive] = tokens[1:]
    return out


def _effective_script_src(parsed: dict[str, list[str]]) -> list[str] | None:
    """Return the effective script-src token list, falling back to
    ``default-src`` if no script-src directive is present.

    Per CSP3, ``script-src-elem`` and ``script-src-attr`` further
    constrain script-src but do not loosen it, so they're not consulted
    for finding *weakness*.
    """
    if "script-src" in parsed:
        return parsed["script-src"]
    if "default-src" in parsed:
        return parsed["default-src"]
    return None


def _has_object_protection(parsed: dict[str, list[str]]) -> bool:
    """Return True if either ``object-src`` is set OR ``default-src 'none'``."""
    if "object-src" in parsed:
        return True
    default_src = parsed.get("default-src", [])
    return _NONE in default_src and len(default_src) == 1


def _csp_headers(response: httpx.Response) -> tuple[list[str], list[str]]:
    """Return ``(enforced, report_only)`` lists of CSP header values."""
    enforced: list[str] = []
    report_only: list[str] = []
    for raw_name, raw_value in response.headers.items():
        name = raw_name.lower()
        if name == "content-security-policy":
            enforced.append(raw_value)
        elif name == "content-security-policy-report-only":
            report_only.append(raw_value)
    return enforced, report_only


def _make(
    *,
    finding_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    target: str,
    cwe: str,
    description: str,
    remediation: str,
    csp_value: str,
    references: Iterable[str] = (),
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=confidence,
        target=target,
        category="csp",
        cwe=cwe,
        description=description,
        remediation=remediation,
        detected_by="scanners.csp",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "https://csp-evaluator.withgoogle.com/",
            *references,
        ],
        evidence=[
            Evidence(
                description="Content-Security-Policy header observed.",
                response_excerpt=f"Content-Security-Policy: {csp_value}",
            )
        ],
    )


def _analyze_one_policy(url: str, csp_value: str) -> list[Finding]:
    parsed = _parse_csp(csp_value)
    findings: list[Finding] = []
    eff_script = _effective_script_src(parsed)

    if eff_script is not None:
        # 'strict-dynamic' instructs modern browsers to ignore
        # 'unsafe-inline', host-source allowlists, and wildcards. If
        # it's present, downgrade or skip those findings to avoid
        # false-positives on policies that opt into the modern model.
        has_strict_dynamic = _STRICT_DYNAMIC in eff_script

        if _UNSAFE_INLINE in eff_script and not has_strict_dynamic:
            findings.append(
                _make(
                    finding_id="CSP-UNSAFE-INLINE-SCRIPT",
                    title="CSP allows 'unsafe-inline' for script-src",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    cwe="79",
                    description=(
                        "The effective ``script-src`` directive includes "
                        "``'unsafe-inline'``, which permits inline ``<script>`` "
                        "blocks and inline event handlers. This is the most "
                        "common CSP weakness and effectively defeats CSP as "
                        "an XSS mitigation."
                    ),
                    remediation=(
                        "Remove ``'unsafe-inline'`` from ``script-src``. "
                        "Replace inline scripts with external files, "
                        "nonce-based allowlisting (``'nonce-RANDOM'``), or "
                        "hash-based allowlisting (``'sha256-...'``). For "
                        "modern apps, prefer ``'strict-dynamic'`` with "
                        "nonces."
                    ),
                    csp_value=csp_value,
                )
            )

        if _UNSAFE_EVAL in eff_script:
            findings.append(
                _make(
                    finding_id="CSP-UNSAFE-EVAL",
                    title="CSP allows 'unsafe-eval' for script-src",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    cwe="79",
                    description=(
                        "The effective ``script-src`` directive includes "
                        "``'unsafe-eval'``, which permits ``eval()``, "
                        "``Function(string)``, ``setTimeout(string)``, and "
                        "``setInterval(string)``. An attacker who controls "
                        "string content (e.g. via DOM-based XSS) can "
                        "execute arbitrary JavaScript."
                    ),
                    remediation=(
                        "Remove ``'unsafe-eval'`` from ``script-src`` and "
                        "refactor any code paths that rely on string-eval "
                        "(JSON.parse for data, libraries that don't use "
                        "eval for templating, etc.)."
                    ),
                    csp_value=csp_value,
                )
            )

        if _WILDCARD in eff_script and not has_strict_dynamic:
            findings.append(
                _make(
                    finding_id="CSP-WILDCARD-SCRIPT-SRC",
                    title="CSP allows wildcard '*' for script-src",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    cwe="79",
                    description=(
                        "The effective ``script-src`` directive includes "
                        "the wildcard ``*`` source, which permits scripts "
                        "from any HTTPS origin. An attacker with any "
                        "uploaded-file or open-redirect primitive on a "
                        "third-party host can pivot to script execution."
                    ),
                    remediation=(
                        "Replace ``*`` with an explicit allowlist of "
                        "trusted hosts, or move to a nonce-based / "
                        "``'strict-dynamic'`` policy."
                    ),
                    csp_value=csp_value,
                )
            )

        if _DATA_SCHEME in eff_script:
            findings.append(
                _make(
                    finding_id="CSP-DATA-URL-SCRIPT-SRC",
                    title="CSP allows data: URLs for script-src",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    target=url,
                    cwe="79",
                    description=(
                        "The effective ``script-src`` directive includes "
                        "the ``data:`` scheme, which lets an XSS payload "
                        "ship its own script body inside the URL "
                        "(``data:text/javascript,...``). This bypasses the "
                        "host allowlist entirely."
                    ),
                    remediation=(
                        "Remove ``data:`` from ``script-src``. ``data:`` is "
                        "only safe for ``img-src`` / ``font-src``."
                    ),
                    csp_value=csp_value,
                )
            )

    if not _has_object_protection(parsed):
        findings.append(
            _make(
                finding_id="CSP-MISSING-OBJECT-SRC",
                title="CSP does not restrict object-src",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                target=url,
                cwe="693",
                description=(
                    "The policy does not set ``object-src`` and does not "
                    "fall back to ``default-src 'none'``. ``<object>`` and "
                    "``<embed>`` tags can host plugins (Flash, Java, Silverlight) "
                    "or arbitrary content; modern apps should pin "
                    "``object-src 'none'`` regardless of the rest of the policy."
                ),
                remediation="Add ``object-src 'none'`` to the policy.",
                csp_value=csp_value,
            )
        )

    if "frame-ancestors" not in parsed:
        findings.append(
            _make(
                finding_id="CSP-MISSING-FRAME-ANCESTORS",
                title="CSP does not set frame-ancestors",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                target=url,
                cwe="1021",
                description=(
                    "The policy omits ``frame-ancestors``. Without it, "
                    "clickjacking defense relies on ``X-Frame-Options`` "
                    "alone, which lacks the granularity of CSP's "
                    "host-source list and is not a CSP directive."
                ),
                remediation=(
                    "Add ``frame-ancestors 'self'`` (or an explicit "
                    "allowlist) to the policy. CSP ``frame-ancestors`` "
                    "supersedes ``X-Frame-Options`` in modern browsers."
                ),
                csp_value=csp_value,
            )
        )

    if "base-uri" not in parsed:
        findings.append(
            _make(
                finding_id="CSP-MISSING-BASE-URI",
                title="CSP does not set base-uri",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                target=url,
                cwe="693",
                description=(
                    "The policy omits ``base-uri``. A DOM-XSS primitive "
                    "that injects ``<base href=//attacker>`` can re-target "
                    "every subsequent relative URL on the page (script, "
                    "image, fetch). ``base-uri`` is the only CSP directive "
                    "that prevents this."
                ),
                remediation="Add ``base-uri 'self'`` (or ``'none'``) to the policy.",
                csp_value=csp_value,
            )
        )

    return findings


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    scope.assert_in_scope(url)
    try:
        response = await client.get(url)
    except Exception:  # network errors are non-findings
        return []

    enforced, report_only = _csp_headers(response)
    findings: list[Finding] = []

    for csp_value in enforced:
        findings.extend(_analyze_one_policy(url, csp_value))

    if not enforced and report_only:
        # The policy is declared but not enforced. Surface this as INFO
        # so it shows up in inventory; do not analyze the directives —
        # the headers scanner will already flag the missing enforced
        # CSP at MEDIUM, which is the actionable finding.
        findings.append(
            Finding(
                id="CSP-REPORT-ONLY-MODE",
                title="CSP is delivered in report-only mode",
                severity=Severity.INFO,
                confidence=Confidence.FIRM,
                target=url,
                category="csp",
                cwe=None,
                description=(
                    "The response carries ``Content-Security-Policy-Report-Only`` "
                    "but no enforced ``Content-Security-Policy`` header. "
                    "Violations are reported to the configured endpoint "
                    "but the browser does NOT block them. This is often a "
                    "deliberate rollout step; surfaced for inventory only."
                ),
                remediation=(
                    "When the policy is stable, switch the header name "
                    "from ``Content-Security-Policy-Report-Only`` to "
                    "``Content-Security-Policy`` (or ship both during "
                    "rollout). Keep the ``report-uri`` / ``report-to`` "
                    "directive in the enforced policy too."
                ),
                detected_by="scanners.csp",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                ],
                evidence=[
                    Evidence(
                        description="Report-only CSP header observed.",
                        response_excerpt=(
                            f"Content-Security-Policy-Report-Only: {report_only[0]}"
                        ),
                    )
                ],
            )
        )

    return findings
