"""Lightweight TLS audit (cert + protocol)."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy


def scan(url: str, scope: ScopePolicy) -> list[Finding]:
    """Synchronous because the stdlib ssl module is sync. Fast enough."""
    scope.assert_in_scope(url)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [
            Finding(
                id="TLS-NOT-HTTPS",
                title="HTTPS not in use",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                target=url,
                category="tls",
                cwe="319",
                description=f"URL `{url}` does not use HTTPS.",
                remediation="Serve all traffic over HTTPS and set HSTS.",
                detected_by="scanners.tls",
            )
        ]

    host = parsed.hostname or ""
    port = parsed.port or 443
    findings: list[Finding] = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as sock, ctx.wrap_socket(
            sock, server_hostname=host
        ) as ssock:
            cert = ssock.getpeercert(binary_form=False) or {}
            proto = ssock.version() or ""
            cipher = ssock.cipher()
    except (OSError, ssl.SSLError) as exc:
        return [
            Finding(
                id="TLS-CONNECT-ERROR",
                title="TLS connection failed",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                target=url,
                category="tls",
                description=f"Could not establish TLS connection: {exc}",
                detected_by="scanners.tls",
            )
        ]

    # Verify hostname & expiry.
    try:
        ssl.match_hostname(cert, host)
    except (ssl.CertificateError, KeyError):
        findings.append(
            Finding(
                id="TLS-HOSTNAME-MISMATCH",
                title="Certificate hostname mismatch",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                target=url,
                category="tls",
                cwe="297",
                description=f"Server certificate does not match host {host}.",
                remediation="Issue a certificate that includes this hostname.",
                detected_by="scanners.tls",
                evidence=[Evidence(description="cert", response_excerpt=str(cert))],
            )
        )

    not_after = cert.get("notAfter")
    if isinstance(not_after, str):
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            days = (expiry - datetime.now(UTC)).days
            if days < 0:
                findings.append(
                    Finding(
                        id="TLS-EXPIRED",
                        title="TLS certificate expired",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        target=url,
                        category="tls",
                        description=f"Certificate expired on {not_after}.",
                        detected_by="scanners.tls",
                    )
                )
            elif days < 14:
                findings.append(
                    Finding(
                        id="TLS-EXPIRING-SOON",
                        title="TLS certificate expires soon",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        target=url,
                        category="tls",
                        description=f"Certificate expires in {days} day(s) ({not_after}).",
                        remediation="Renew the certificate; consider auto-renewal.",
                        detected_by="scanners.tls",
                    )
                )
        except ValueError:
            pass

    if proto in {"TLSv1", "TLSv1.1", "SSLv3"}:
        findings.append(
            Finding(
                id="TLS-LEGACY-PROTO",
                title=f"Legacy TLS protocol negotiated: {proto}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target=url,
                category="tls",
                cwe="327",
                description=f"Server negotiated {proto}; deprecated and unsafe.",
                remediation="Disable TLS <1.2; require TLS 1.2 or 1.3.",
                detected_by="scanners.tls",
                evidence=[
                    Evidence(
                        description=f"Negotiated cipher: {cipher}",
                        response_excerpt=str(cipher),
                    )
                ],
            )
        )
    return findings
