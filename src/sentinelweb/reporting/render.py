"""Render :class:`Finding` collections to Markdown / HTML / per-platform reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .. import __version__
from ..scope.policy import Engagement
from .findings import Finding, Severity, sort_findings
from .sarif import render_sarif

_env = Environment(
    loader=PackageLoader("sentinelweb.reporting", "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def render_markdown(findings: list[Finding], engagement: Engagement) -> str:
    template = _env.get_template("markdown_default.j2")
    return template.render(
        findings=sort_findings(findings),
        engagement=engagement,
        severity_counts=_severity_counts(findings),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        version=__version__,
    )


def render_html(findings: list[Finding], engagement: Engagement) -> str:
    template = _env.get_template("html_default.j2")
    return template.render(
        findings=sort_findings(findings),
        engagement=engagement,
        severity_counts=_severity_counts(findings),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        version=__version__,
    )


def render_hackerone(finding: Finding) -> str:
    return _env.get_template("hackerone.j2").render(finding=finding)


def render_bugcrowd(finding: Finding) -> str:
    return _env.get_template("bugcrowd.j2").render(finding=finding)


def render_findings_json(
    findings: list[Finding], engagement: Engagement
) -> str:
    """Serialize findings + engagement metadata to a stable JSON string.

    Format: ``{"version", "engagement", "generated_at", "findings": [...]}``.
    Field names match the :class:`Finding` model exactly so consumers can
    round-trip the JSON through ``Finding.model_validate``.
    """
    payload = {
        "version": __version__,
        "engagement": {
            "program": engagement.program,
            "authorization": engagement.authorization,
            "contact": engagement.contact,
        },
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "findings": [f.model_dump(mode="json") for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def write_report(
    findings: list[Finding],
    engagement: Engagement,
    out_dir: str | Path,
    *,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Render and write a multi-format report. Returns map of format -> path.

    Always emits ``findings.json`` regardless of the requested ``formats``
    so structured triage tooling has a stable machine-readable input.
    """
    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    formats = formats or ["md", "html"]
    written: dict[str, Path] = {}

    json_path = out_dir_p / "findings.json"
    json_path.write_text(render_findings_json(findings, engagement), encoding="utf-8")
    written["json"] = json_path

    if "md" in formats:
        p = out_dir_p / "report.md"
        p.write_text(render_markdown(findings, engagement), encoding="utf-8")
        written["md"] = p
    if "html" in formats:
        p = out_dir_p / "report.html"
        p.write_text(render_html(findings, engagement), encoding="utf-8")
        written["html"] = p
    if "sarif" in formats:
        p = out_dir_p / "report.sarif"
        p.write_text(render_sarif(findings, engagement), encoding="utf-8")
        written["sarif"] = p
    return written
