"""SARIF 2.1.0 emitter for SentinelWeb findings.

The Static Analysis Results Interchange Format (SARIF) 2.1.0 is the
de-facto standard consumed by GitHub code-scanning, GitLab, and
DefectDojo's SARIF importer. Mapping rules:

- Each unique ``Finding.id`` becomes a ``rules[]`` entry on the run's
  driver. Repeated IDs collapse so the rule set stays small.
- Each finding becomes a ``results[]`` entry referring back to its rule
  via ``ruleId``.
- Severity maps both to the SARIF ``level`` enum (``error|warning|note``)
  AND to ``properties.security-severity`` (a 0-10 string) which GitHub
  code-scanning uses for finer-grained UI ranking.
- Confidence, CVSS vector, CWE, evidence, tags, and engagement metadata
  are preserved under ``properties`` for downstream consumers that want
  the full record.
- The target URL is encoded as a ``physicalLocation.artifactLocation``;
  any path component becomes the artifact URI.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from .. import __version__
from ..scope.policy import Engagement
from .findings import Finding, Severity

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/"
    "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/wraithen0/sentinelweb"

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}

# GitHub code-scanning uses these numeric thresholds for its severity UI.
_SECURITY_SEVERITY_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def _security_severity(finding: Finding) -> str:
    """Numeric severity string in 0-10 range for GitHub code-scanning."""
    if finding.cvss_score is not None:
        return f"{finding.cvss_score:.1f}"
    return _SECURITY_SEVERITY_BY_SEVERITY[finding.severity]


def _normalize_cwe(cwe: str) -> str:
    """Return ``cwe`` with the canonical ``CWE-`` prefix.

    Findings may carry CWE values either as bare numeric IDs (``"1021"``)
    or already-prefixed (``"CWE-1021"``). Both rule and result properties
    must agree on the format so downstream consumers (DefectDojo, custom
    triage scripts) don't need to disambiguate.
    """
    return cwe if cwe.upper().startswith("CWE-") else f"CWE-{cwe}"


def _rule_for(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[finding.severity]},
        "properties": {
            "category": finding.category,
            "tags": [finding.category, *finding.tags],
            "security-severity": _security_severity(finding),
        },
    }
    if finding.cwe:
        rule["properties"]["cwe"] = _normalize_cwe(finding.cwe)
    if finding.remediation:
        rule["help"] = {"text": finding.remediation, "markdown": finding.remediation}
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _location_for(target: str) -> dict[str, Any]:
    """Best-effort SARIF location for a URL-style target.

    SARIF expects file-like artifacts; for HTTP targets we encode the
    full URL into ``artifactLocation.uri`` and surface the path under
    ``logicalLocations`` so downstream tools that expect both shapes
    (file-based linters vs. URL-based scanners) can find what they need.
    """
    parts = urlsplit(target)
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": target},
        },
    }
    if parts.path and parts.path != "/":
        location["logicalLocations"] = [
            {"name": parts.path, "kind": "url-path"},
        ]
    return location


def _result_for(finding: Finding) -> dict[str, Any]:
    message_parts: list[str] = [finding.description.strip()]
    if finding.evidence:
        message_parts.append("")
        for ev in finding.evidence:
            message_parts.append(f"Evidence: {ev.description}")
            if ev.response_excerpt:
                message_parts.append(ev.response_excerpt.strip())
    message_text = "\n".join(message_parts).strip()

    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": message_text},
        "locations": [_location_for(finding.target)],
        "properties": {
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "security-severity": _security_severity(finding),
            "category": finding.category,
            "detected_by": finding.detected_by,
            "detected_at": finding.detected_at.isoformat(),
            "tags": [finding.category, *finding.tags],
        },
    }
    if finding.cvss_score is not None:
        result["properties"]["cvss_score"] = finding.cvss_score
    if finding.cvss_vector:
        result["properties"]["cvss_vector"] = finding.cvss_vector
    if finding.cwe:
        result["properties"]["cwe"] = _normalize_cwe(finding.cwe)
    if finding.references:
        result["properties"]["references"] = list(finding.references)
    if finding.evidence:
        result["properties"]["evidence"] = [ev.model_dump() for ev in finding.evidence]
    return result


def to_sarif(findings: list[Finding], engagement: Engagement) -> dict[str, Any]:
    """Build a SARIF 2.1.0 dict from a list of findings."""
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.id not in rules:
            rules[f.id] = _rule_for(f)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentinelWeb",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    },
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "engagement": engagement.program,
                            "authorization": engagement.authorization,
                        },
                    }
                ],
                "results": [_result_for(f) for f in findings],
            }
        ],
    }


def render_sarif(findings: list[Finding], engagement: Engagement) -> str:
    """Render findings to a SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(findings, engagement), indent=2, sort_keys=False)
