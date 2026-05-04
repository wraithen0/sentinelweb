"""Render :class:`Finding` collections to Markdown / HTML / per-platform reports."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .. import __version__
from ..scope.policy import Engagement
from .findings import Finding, Severity, sort_findings

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


def write_report(
    findings: list[Finding],
    engagement: Engagement,
    out_dir: str | Path,
    *,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Render and write a multi-format report. Returns map of format -> path."""
    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    formats = formats or ["md", "html"]
    written: dict[str, Path] = {}
    if "md" in formats:
        p = out_dir_p / "report.md"
        p.write_text(render_markdown(findings, engagement), encoding="utf-8")
        written["md"] = p
    if "html" in formats:
        p = out_dir_p / "report.html"
        p.write_text(render_html(findings, engagement), encoding="utf-8")
        written["html"] = p
    return written
