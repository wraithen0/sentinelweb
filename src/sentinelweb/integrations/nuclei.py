"""Nuclei integration — runs templates and adapts results into Findings."""

from __future__ import annotations

import json

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ._subprocess import IntegrationError, require, run

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def scan(
    targets: list[str],
    scope: ScopePolicy,
    *,
    severity: str = "low,medium,high,critical",
    rate_limit: int | None = None,
    extra_args: tuple[str, ...] = (),
    timeout: int = 1800,
) -> list[Finding]:
    """Run nuclei against ``targets`` and return findings."""
    if not targets:
        return []
    for t in targets:
        scope.assert_in_scope(t)
    binary = require("nuclei")

    cmd = [
        binary,
        "-jsonl",
        "-silent",
        "-disable-update-check",
        "-severity",
        severity,
    ]
    if rate_limit is None:
        rate_limit = max(1, int(scope.rate_per_sec * 60))
    cmd += ["-rate-limit", str(rate_limit)]
    for t in targets:
        cmd += ["-u", t]
    cmd += list(extra_args)

    res = run(cmd, timeout=timeout)
    if res.returncode not in (0, 1):  # nuclei exits 1 if it found nothing
        raise IntegrationError(f"nuclei failed: {res.stderr.strip()[:300]}")

    findings: list[Finding] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        template_id = row.get("template-id") or row.get("templateID") or ""
        matched_at = row.get("matched-at") or row.get("matched_at") or ""
        findings.append(
            Finding(
                id=f"NUCLEI-{template_id.upper()}",
                title=str(info.get("name") or template_id or "nuclei finding"),
                severity=sev,
                confidence=Confidence.FIRM,
                target=matched_at or (targets[0] if targets else ""),
                category="nuclei",
                description=str(info.get("description") or "Detected by nuclei."),
                detected_by="integrations.nuclei",
                tags=list(info.get("tags") or []),
                references=list(info.get("reference") or []),
                evidence=[
                    Evidence(
                        description=f"Template {template_id}",
                        request=str(row.get("request") or "")[:500],
                        response_excerpt=str(row.get("response") or "")[:500],
                    )
                ],
            )
        )
    return findings
