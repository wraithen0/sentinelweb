"""CLI tests for the `report` subcommand and `--severity-threshold` on `scan`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from sentinelweb.cli.main import cli
from sentinelweb.reporting import render
from sentinelweb.reporting.findings import (
    Confidence,
    Finding,
    Severity,
)
from sentinelweb.scope.policy import Engagement


def _five_finding_pyramid() -> list[Finding]:
    return [
        Finding(
            id="F-INFO",
            title="info finding",
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


def _seed_findings_json(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    render.write_report(
        _five_finding_pyramid(),
        Engagement(program="Triage", authorization="local-only"),
        src,
        formats=["md"],  # findings.json always emitted
    )
    return src / "findings.json"


def test_report_help_lists_severity_threshold_choices() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["report", "--help"])
    assert result.exit_code == 0, result.output
    assert "--severity-threshold" in result.output
    for choice in ("info", "low", "medium", "high", "critical"):
        assert choice in result.output, (
            f"--severity-threshold help must list '{choice}' as a choice"
        )
    assert "findings.json" in result.output, (
        "report --help should mention findings.json so users know "
        "the input shape"
    )


def test_report_re_renders_with_high_threshold(tmp_path: Path) -> None:
    findings_json = _seed_findings_json(tmp_path)
    out_dir = tmp_path / "out"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report",
            "--input",
            str(findings_json),
            "--report-dir",
            str(out_dir),
            "--format",
            "md",
            "--format",
            "sarif",
            "--severity-threshold",
            "high",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (out_dir / "report.md").exists()
    assert (out_dir / "report.sarif").exists()
    assert not (out_dir / "findings.json").exists(), (
        "report must NOT write findings.json — it's the input"
    )

    md = (out_dir / "report.md").read_text()
    assert "F-HIGH" in md and "F-CRIT" in md
    for suppressed in ("F-INFO", "F-LOW", "F-MED"):
        assert suppressed not in md, (
            f"--severity-threshold high must suppress {suppressed}"
        )

    sarif = json.loads((out_dir / "report.sarif").read_text())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"F-HIGH", "F-CRIT"}


def test_report_threshold_info_emits_everything(tmp_path: Path) -> None:
    findings_json = _seed_findings_json(tmp_path)
    out_dir = tmp_path / "out"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report",
            "--input",
            str(findings_json),
            "--report-dir",
            str(out_dir),
            "--format",
            "sarif",
            "--severity-threshold",
            "info",
        ],
    )
    assert result.exit_code == 0, result.output
    sarif = json.loads((out_dir / "report.sarif").read_text())
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"F-INFO", "F-LOW", "F-MED", "F-HIGH", "F-CRIT"}


def test_report_rejects_garbage_input(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("definitely not JSON", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["report", "--input", str(bad), "--report-dir", str(tmp_path / "o")],
    )
    assert result.exit_code != 0, (
        "report must exit non-zero on malformed input"
    )
    assert "not valid JSON" in (result.output or "") + (
        result.stderr if result.stderr_bytes else ""
    ), (
        "the error message should be human-readable, not a stack trace; "
        f"got: {result.output!r}"
    )


def test_report_missing_input_argument() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["report"])
    assert result.exit_code != 0
    assert "--input" in result.output


# ---- scan --severity-threshold integration -------------------------------


def _scope_yaml(p: Path) -> Path:
    p.write_text(
        """
engagement:
  program: t
  authorization: https://h1/t
in_scope: ["127.0.0.1"]
""",
        encoding="utf-8",
    )
    return p


def test_scan_help_lists_severity_threshold() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--severity-threshold" in result.output
    for choice in ("info", "low", "medium", "high", "critical"):
        assert choice in result.output


def test_scan_severity_threshold_filters_md_but_keeps_findings_json(
    tmp_path: Path, monkeypatch
) -> None:
    """Run scan with a stubbed scanner that returns findings at every severity.

    Use --severity-threshold high; verify findings.json keeps all 5
    findings while report.md only contains F-HIGH/F-CRIT.
    """
    scope = _scope_yaml(tmp_path / "scope.yaml")
    out = tmp_path / "out"

    # Stub all scanners that the `scan` CLI walks through. We hijack
    # scan_headers so we don't have to make network calls.
    pyramid = _five_finding_pyramid()

    async def fake_scan(url, policy, client):
        return list(pyramid)

    from sentinelweb.cli import main as cli_main

    monkeypatch.setattr(cli_main.scan_headers, "scan", fake_scan)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--scope",
            str(scope),
            "--scanner",
            "headers",
            "--report-dir",
            str(out),
            "--format",
            "md",
            "--severity-threshold",
            "high",
            "http://127.0.0.1/",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads((out / "findings.json").read_text())
    json_ids = {f["id"] for f in payload["findings"]}
    assert json_ids == {"F-INFO", "F-LOW", "F-MED", "F-HIGH", "F-CRIT"}, (
        "findings.json must be the canonical record and not respect threshold"
    )

    md = (out / "report.md").read_text()
    assert "F-HIGH" in md and "F-CRIT" in md
    for suppressed in ("F-INFO", "F-LOW", "F-MED"):
        assert suppressed not in md

    # CLI summary should mention threshold so triagers know findings are suppressed
    assert "threshold" in result.output.lower(), (
        "CLI summary must indicate the threshold so suppressed findings "
        "aren't lost in plain sight"
    )
