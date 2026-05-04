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


# ---- severity threshold ---------------------------------------------------


def _findings_pyramid() -> list[Finding]:
    """One finding at every severity level, with predictable ids."""
    return [
        Finding(
            id="F-INFO",
            title="info-only finding",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target="https://example.test/",
            category="recon",
            description="d",
            detected_by="t",
        ),
        Finding(
            id="F-LOW",
            title="low finding",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            target="https://example.test/",
            category="recon",
            description="d",
            detected_by="t",
        ),
        Finding(
            id="F-MED",
            title="medium finding",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            target="https://example.test/",
            category="recon",
            description="d",
            detected_by="t",
        ),
        Finding(
            id="F-HIGH",
            title="high finding",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            target="https://example.test/",
            category="recon",
            description="d",
            detected_by="t",
        ),
        Finding(
            id="F-CRIT",
            title="critical finding",
            severity=Severity.CRITICAL,
            confidence=Confidence.FIRM,
            target="https://example.test/",
            category="recon",
            description="d",
            detected_by="t",
        ),
    ]


def test_filter_by_min_severity_info_is_noop() -> None:
    from sentinelweb.reporting.findings import filter_by_min_severity

    pyramid = _findings_pyramid()
    out = filter_by_min_severity(pyramid, Severity.INFO)
    assert [f.id for f in out] == [f.id for f in pyramid]


def test_filter_by_min_severity_high_keeps_only_high_and_critical() -> None:
    from sentinelweb.reporting.findings import filter_by_min_severity

    out = filter_by_min_severity(_findings_pyramid(), Severity.HIGH)
    assert [f.id for f in out] == ["F-HIGH", "F-CRIT"]


def test_filter_by_min_severity_critical_keeps_only_critical() -> None:
    from sentinelweb.reporting.findings import filter_by_min_severity

    out = filter_by_min_severity(_findings_pyramid(), Severity.CRITICAL)
    assert [f.id for f in out] == ["F-CRIT"]


def test_write_report_min_severity_filters_md_html_sarif_but_not_json(
    tmp_path: Path,
) -> None:
    """findings.json must keep every observation; md/html/sarif must respect threshold."""
    import json as _json

    render.write_report(
        _findings_pyramid(),
        Engagement(program="Test", authorization="x"),
        tmp_path,
        formats=["md", "html", "sarif"],
        min_severity=Severity.HIGH,
    )

    payload = _json.loads((tmp_path / "findings.json").read_text())
    json_ids = {f["id"] for f in payload["findings"]}
    assert json_ids == {"F-INFO", "F-LOW", "F-MED", "F-HIGH", "F-CRIT"}, (
        "findings.json is the canonical record and must NOT be filtered"
    )

    md = (tmp_path / "report.md").read_text()
    assert "F-HIGH" in md and "F-CRIT" in md
    for suppressed in ("F-INFO", "F-LOW", "F-MED"):
        assert suppressed not in md, (
            f"markdown must suppress {suppressed} when threshold=high"
        )

    html = (tmp_path / "report.html").read_text()
    assert "F-HIGH" in html and "F-CRIT" in html
    for suppressed in ("F-INFO", "F-LOW", "F-MED"):
        assert suppressed not in html

    sarif = _json.loads((tmp_path / "report.sarif").read_text())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"F-HIGH", "F-CRIT"}, (
        "SARIF rules must be filtered to threshold so code-scanning UIs "
        "don't show suppressed findings"
    )


def test_write_report_min_severity_info_emits_everything(tmp_path: Path) -> None:
    """Threshold=INFO is a no-op; output must equal the unfiltered case."""
    import json as _json

    render.write_report(
        _findings_pyramid(),
        Engagement(program="Test", authorization="x"),
        tmp_path,
        formats=["sarif"],
        min_severity=Severity.INFO,
    )
    sarif = _json.loads((tmp_path / "report.sarif").read_text())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"F-INFO", "F-LOW", "F-MED", "F-HIGH", "F-CRIT"}


# ---- re_render_from_json --------------------------------------------------


def test_re_render_from_json_round_trip(tmp_path: Path) -> None:
    """report subcommand backbone: write findings.json then re-render with threshold."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    render.write_report(
        _findings_pyramid(),
        Engagement(program="Triage", authorization="local-only"),
        src_dir,
        formats=["md"],
    )
    findings_json = src_dir / "findings.json"
    assert findings_json.exists()

    out_dir = tmp_path / "out"
    written = render.re_render_from_json(
        findings_json,
        out_dir,
        formats=["md", "html", "sarif"],
        min_severity=Severity.MEDIUM,
    )
    assert set(written.keys()) == {"md", "html", "sarif"}, (
        "report must NOT write findings.json — input is the canonical record"
    )
    assert not (out_dir / "findings.json").exists()

    md = (out_dir / "report.md").read_text()
    assert "Triage" in md, "engagement metadata must be carried over from input json"
    assert "F-MED" in md and "F-HIGH" in md and "F-CRIT" in md
    for suppressed in ("F-INFO", "F-LOW"):
        assert suppressed not in md


def test_re_render_from_json_rejects_malformed_input(tmp_path: Path) -> None:
    """A garbage findings.json must yield a clean ValueError, not a stack trace."""
    import pytest

    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        render.re_render_from_json(bad, tmp_path / "out", formats=["md"])

    missing_eng = tmp_path / "missing_eng.json"
    missing_eng.write_text('{"findings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="engagement"):
        render.re_render_from_json(missing_eng, tmp_path / "out", formats=["md"])

    missing_findings = tmp_path / "missing_findings.json"
    missing_findings.write_text(
        '{"engagement": {"program": "p", "authorization": "a"}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="findings"):
        render.re_render_from_json(
            missing_findings, tmp_path / "out", formats=["md"]
        )
