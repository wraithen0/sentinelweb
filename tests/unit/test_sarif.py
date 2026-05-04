"""SARIF 2.1.0 emitter tests."""

from __future__ import annotations

import json

from sentinelweb.reporting.findings import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from sentinelweb.reporting.sarif import render_sarif, to_sarif
from sentinelweb.scope.policy import Engagement


def _engagement() -> Engagement:
    return Engagement(
        program="demo",
        authorization="local-only",
        contact="x@example.test",
    )


def _csp_finding() -> Finding:
    return Finding(
        id="HDR-MISSING-CONTENT-SECURITY-POLICY",
        title="Missing security header: content-security-policy",
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        target="http://127.0.0.1:3000/admin",
        category="security-headers",
        cwe="1021",
        description="No CSP.",
        remediation="Set a CSP.",
        detected_by="scanners.headers",
        evidence=[
            Evidence(
                description="Response headers", response_excerpt="x-frame-options: SAMEORIGIN"
            )
        ],
        references=["https://owasp.org/secure-headers/"],
    )


def _critical_finding() -> Finding:
    return Finding(
        id="JWT-WEAK-SECRET",
        title="JWT signed with weak/dictionary secret",
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        target="<token>",
        category="jwt",
        description="Recovered.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        detected_by="cli.jwt",
    )


def test_sarif_top_level_shape() -> None:
    doc = to_sarif([_csp_finding()], _engagement())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SentinelWeb"
    assert run["tool"]["driver"]["informationUri"].startswith("https://")
    assert isinstance(run["results"], list)


def test_sarif_rule_dedupe() -> None:
    """Two findings with the same id collapse to one rule."""
    f1 = _csp_finding()
    f2 = _csp_finding()
    f2.target = "http://127.0.0.1:3000/login"
    doc = to_sarif([f1, f2], _engagement())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "HDR-MISSING-CONTENT-SECURITY-POLICY"
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_severity_to_level_mapping() -> None:
    doc = to_sarif([_csp_finding(), _critical_finding()], _engagement())
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["HDR-MISSING-CONTENT-SECURITY-POLICY"] == "warning"
    assert levels["JWT-WEAK-SECRET"] == "error"


def test_sarif_security_severity_uses_cvss() -> None:
    """When CVSS is present, security-severity must reflect it (for GitHub)."""
    doc = to_sarif([_critical_finding()], _engagement())
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "9.8"
    assert result["properties"]["cvss_score"] == 9.8
    assert result["properties"]["cvss_vector"].startswith("CVSS:3.1/")


def test_sarif_security_severity_falls_back_when_no_cvss() -> None:
    doc = to_sarif([_csp_finding()], _engagement())
    result = doc["runs"][0]["results"][0]
    # MEDIUM without CVSS maps to 5.5
    assert result["properties"]["security-severity"] == "5.5"


def test_sarif_cwe_normalized_with_prefix() -> None:
    doc = to_sarif([_csp_finding()], _engagement())
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["cwe"] == "CWE-1021"


def test_sarif_location_includes_url() -> None:
    doc = to_sarif([_csp_finding()], _engagement())
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == (
        "http://127.0.0.1:3000/admin"
    )
    # Path component is also surfaced as a logical location.
    logical = loc.get("logicalLocations", [])
    assert any(ll["name"] == "/admin" for ll in logical)


def test_sarif_evidence_preserved_in_properties() -> None:
    doc = to_sarif([_csp_finding()], _engagement())
    result = doc["runs"][0]["results"][0]
    assert "evidence" in result["properties"]
    assert result["properties"]["evidence"][0]["description"] == "Response headers"


def test_render_sarif_returns_valid_json() -> None:
    text = render_sarif([_csp_finding()], _engagement())
    parsed = json.loads(text)
    assert parsed["version"] == "2.1.0"
