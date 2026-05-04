"""Subdomain-takeover detection (signal-only).

Resolves a host's CNAME chain and, when a CNAME points to a known SaaS
endpoint, fetches that endpoint to look for an "unclaimed resource"
fingerprint. Detection only — this scanner never registers/claims the
dangling resource itself.

Fingerprints are inspired by the publicly-maintained projects
``can-i-take-over-xyz`` (EdOverflow) and ``subjack`` (haccer), narrowed
to a small high-confidence subset to keep false-positive rate low. The
bias is toward TENTATIVE / FIRM confidence — actually claiming the
target is what graduates a finding to CERTAIN, and that's a manual
operator step, not the scanner's job.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client
from ..utils.logging import get_logger
from ..utils.urls import normalize_host

log = get_logger(__name__)


@dataclass(frozen=True)
class TakeoverFingerprint:
    """A SaaS provider's subdomain-takeover signature.

    A finding is emitted only when *both*:

    * the resolved CNAME chain matches one of ``cname_patterns`` AND
    * fetching the target returns a body containing ``unclaimed_marker``.
    """

    service: str
    cname_patterns: tuple[str, ...]
    unclaimed_marker: str
    severity: Severity = Severity.HIGH
    notes: str = ""


# A deliberately small, high-confidence list. Each marker has been
# observed in practice on public unclaimed pages from the respective
# provider. Adding new providers is welcome but should be backed by a
# captured response excerpt referenced in the PR.
FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    TakeoverFingerprint(
        service="GitHub Pages",
        cname_patterns=(r"\.github\.io$",),
        unclaimed_marker="There isn't a GitHub Pages site here.",
    ),
    TakeoverFingerprint(
        service="AWS S3",
        cname_patterns=(
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[.-][^.]+\.amazonaws\.com$",
        ),
        unclaimed_marker="NoSuchBucket",
    ),
    TakeoverFingerprint(
        service="Heroku",
        cname_patterns=(r"\.herokuapp\.com$", r"\.herokudns\.com$"),
        unclaimed_marker="No such app",
    ),
    TakeoverFingerprint(
        service="Vercel",
        cname_patterns=(r"\.vercel\.app$",),
        unclaimed_marker="DEPLOYMENT_NOT_FOUND",
    ),
    TakeoverFingerprint(
        service="Netlify",
        cname_patterns=(r"\.netlify\.app$", r"\.netlify\.com$"),
        unclaimed_marker="Not Found - Request ID",
    ),
    TakeoverFingerprint(
        service="Azure",
        cname_patterns=(
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
        ),
        unclaimed_marker="404 Web Site not found",
    ),
    TakeoverFingerprint(
        service="Bitbucket",
        cname_patterns=(r"\.bitbucket\.io$",),
        unclaimed_marker="Repository not found",
    ),
    TakeoverFingerprint(
        service="Shopify",
        cname_patterns=(r"\.myshopify\.com$",),
        unclaimed_marker="Sorry, this shop is currently unavailable.",
    ),
    TakeoverFingerprint(
        service="Tumblr",
        cname_patterns=(r"\.tumblr\.com$",),
        unclaimed_marker="Whatever you were looking for doesn't currently exist",
    ),
)


async def _resolve_cname_chain(host: str) -> list[str]:
    """Resolve the full CNAME chain for ``host``.

    Returns the list of CNAME targets in resolution order. Empty list
    when the host has no CNAME or fails to resolve.
    """
    chain: list[str] = []
    current = host
    seen: set[str] = set()
    for _ in range(10):  # cap chain depth defensively
        if current in seen:
            break
        seen.add(current)
        try:
            answer = await dns.asyncresolver.resolve(current, "CNAME")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            break
        target = ""
        for rdata in answer:
            target = str(rdata.target).rstrip(".").lower()
            break
        if not target:
            break
        chain.append(target)
        current = target
    return chain


def _match_fingerprint(cname: str) -> TakeoverFingerprint | None:
    for fp in FINGERPRINTS:
        for pattern in fp.cname_patterns:
            if re.search(pattern, cname):
                return fp
    return None


async def scan(
    host_or_url: str,
    scope: ScopePolicy,
    client: Client,
    *,
    fingerprints: Iterable[TakeoverFingerprint] = FINGERPRINTS,
) -> list[Finding]:
    """Probe ``host`` for a likely subdomain takeover.

    Steps:
      1. Resolve the CNAME chain.
      2. If any CNAME matches a known SaaS pattern, fetch
         ``http(s)://<host>`` and look for the unclaimed marker.
      3. Emit a TENTATIVE/FIRM finding when both signals fire.
    """
    host = normalize_host(host_or_url)
    scope.assert_in_scope(host)

    cnames = await _resolve_cname_chain(host)
    if not cnames:
        return []

    matched: TakeoverFingerprint | None = None
    matched_cname: str = ""
    for cname in cnames:
        for fp in fingerprints:
            for pattern in fp.cname_patterns:
                if re.search(pattern, cname):
                    matched, matched_cname = fp, cname
                    break
            if matched is not None:
                break
        if matched is not None:
            break

    if matched is None:
        return []

    findings: list[Finding] = []
    body = ""
    status: int | None = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = await client.get(url)
        except Exception as exc:
            log.debug("takeover probe %s failed: %s", url, exc)
            continue
        body = resp.text or ""
        status = resp.status_code
        if matched.unclaimed_marker.lower() in body.lower():
            findings.append(
                _build_finding(host, matched, matched_cname, status, body)
            )
            return findings
    # CNAME matched a SaaS pattern but no unclaimed marker — emit a
    # lower-confidence advisory so the operator can still investigate
    # (the resource may exist today but become orphaned later).
    findings.append(
        _build_advisory(host, matched, matched_cname, status)
    )
    return findings


def _build_finding(
    host: str,
    fp: TakeoverFingerprint,
    cname: str,
    status: int | None,
    body: str,
) -> Finding:
    return Finding(
        id=f"TAKEOVER-{_slug(fp.service)}",
        title=f"Possible subdomain takeover on {fp.service}",
        severity=fp.severity,
        confidence=Confidence.FIRM,
        target=host,
        category="dns-takeover",
        description=(
            f"{host} has a CNAME pointing at {cname!r} (matches {fp.service} "
            f"pattern) and the response body contains the {fp.service!s} "
            f"'unclaimed resource' marker {fp.unclaimed_marker!r}. An attacker "
            "who can register the dangling resource at the SaaS provider "
            "could take control of this hostname."
        ),
        remediation=(
            f"Either remove the CNAME if {fp.service} is no longer used, or "
            f"reclaim the resource at {fp.service} so it returns a real page."
        ),
        detected_by="scanners.takeover",
        references=[
            "https://github.com/EdOverflow/can-i-take-over-xyz",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        ],
        evidence=[
            Evidence(
                description=f"CNAME chain ends at {cname}; HTTP {status}",
                response_excerpt=body[:300],
            )
        ],
    )


def _build_advisory(
    host: str,
    fp: TakeoverFingerprint,
    cname: str,
    status: int | None,
) -> Finding:
    return Finding(
        id=f"TAKEOVER-{_slug(fp.service)}-CNAME-ADVISORY",
        title=f"Hostname CNAMEs to {fp.service} (takeover-prone)",
        severity=Severity.LOW,
        confidence=Confidence.TENTATIVE,
        target=host,
        category="dns-takeover",
        description=(
            f"{host} CNAMEs to {cname!r}, which matches the {fp.service} "
            "takeover pattern. The endpoint currently serves content (no "
            "unclaimed marker observed) but if the underlying resource is "
            "ever deleted without removing the CNAME, the host becomes "
            "vulnerable to takeover."
        ),
        remediation=(
            f"Treat the {fp.service} resource as load-bearing for this "
            "hostname; remove the CNAME first if you decommission it."
        ),
        detected_by="scanners.takeover",
        references=[
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ],
        evidence=[
            Evidence(
                description=(
                    f"CNAME chain ends at {cname}; HTTP {status}; no "
                    "unclaimed-resource marker observed"
                )
            )
        ],
    )


_NON_SLUG = re.compile(r"[^A-Z0-9]+")


def _slug(value: str) -> str:
    s = _NON_SLUG.sub("-", value.upper()).strip("-")
    return s or "UNKNOWN"
