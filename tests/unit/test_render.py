from __future__ import annotations

from pathlib import Path

from sentinelweb.reporting import render
from sentinelweb.reporting.findings import (
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from sentinelweb.scope.policy import Engagement


def _finding() -> Finding:
    return Finding(
        id="HDR-1",
        title="Missing HSTS",
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        target="https://example.test/",
        category="security-headers",
        description="HSTS header is missing.",
        remediation="Set HSTS",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        cvss_score=5.3,
        cwe="319",
        references=["https://example.test/ref"],
        evidence=[Evidence(description="response")],
        detected_by="scanners.headers",
    )


def test_markdown_render_contains_finding() -> None:
    md = render.render_markdown(
        [_finding()],
        Engagement(
            program="Test", authorization="https://h1/test", contact="x@example.test"
        ),
    )
    assert "Missing HSTS" in md
    assert "MEDIUM" in md
    assert "CVSS 3.1" in md
    assert "`HDR-1`" in md, "structured finding ID must be present in markdown"
    assert "MEDIUM`-" not in md, (
        "metadata bullets must be on separate lines, not collapsed by trim_blocks"
    )


def test_html_render_contains_finding() -> None:
    html = render.render_html(
        [_finding()],
        Engagement(
            program="Test", authorization="https://h1/test", contact="x@example.test"
        ),
    )
    assert "Missing HSTS" in html
    assert "<html" in html
    assert "HDR-1" in html, "structured finding ID must be present in html"


def test_write_report_writes_files(tmp_path: Path) -> None:
    written = render.write_report(
        [_finding()],
        Engagement(program="Test", authorization="x"),
        tmp_path,
    )
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "findings.json").exists(), (
        "findings.json sidecar must be emitted regardless of formats"
    )
    assert set(written.keys()) == {"md", "html", "json"}


def test_write_report_findings_json_is_round_trippable(tmp_path: Path) -> None:
    """findings.json must round-trip through Finding.model_validate."""
    import json as _json

    from sentinelweb.reporting.findings import Finding

    render.write_report(
        [_finding()],
        Engagement(program="Test", authorization="x"),
        tmp_path,
    )
    payload = _json.loads((tmp_path / "findings.json").read_text())
    assert payload["version"]
    assert payload["engagement"]["program"] == "Test"
    assert len(payload["findings"]) == 1
    rebuilt = Finding.model_validate(payload["findings"][0])
    assert rebuilt.id == "HDR-1"


def test_write_report_emits_sarif_when_requested(tmp_path: Path) -> None:
    import json as _json

    written = render.write_report(
        [_finding()],
        Engagement(program="Test", authorization="x"),
        tmp_path,
        formats=["md", "sarif"],
    )
    assert (tmp_path / "report.sarif").exists()
    assert "sarif" in written
    parsed = _json.loads((tmp_path / "report.sarif").read_text())
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"][0]["ruleId"] == "HDR-1"


def test_hackerone_template() -> None:
    out = render.render_hackerone(_finding())
    assert "Missing HSTS" in out
    assert "Steps to reproduce" in out
    assert "`HDR-1`" in out, "structured finding ID must be present"
    assert "MEDIUM**" not in out, "severity must not be glued to next field"


def test_bugcrowd_template() -> None:
    out = render.render_bugcrowd(_finding())
    assert "Missing HSTS" in out
    assert "Steps to reproduce" in out
    assert "`HDR-1`" in out
    assert "CWE-319" in out
