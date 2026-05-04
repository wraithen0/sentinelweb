"""Render :class:`Finding` collections to Markdown / HTML / per-platform reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .. import __version__
from ..scope.policy import Engagement
from .findings import Finding, Severity, filter_by_min_severity, sort_findings
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
    min_severity: Severity | None = None,
) -> dict[str, Path]:
    """Render and write a multi-format report. Returns map of format -> path.

    Always emits ``findings.json`` regardless of the requested ``formats``
    so structured triage tooling has a stable machine-readable input.

    ``min_severity`` filters the human-readable formats (``md`` / ``html`` /
    ``sarif``) and is the foundation of ``--severity-threshold``: callers
    can use ``sentinelweb report`` to re-render findings.json at a stricter
    or looser threshold without re-scanning. ``findings.json`` itself is
    intentionally **not** filtered — the canonical record always contains
    every observation so triagers can re-render at any threshold later.
    """
    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    formats = formats or ["md", "html"]
    written: dict[str, Path] = {}

    json_path = out_dir_p / "findings.json"
    json_path.write_text(render_findings_json(findings, engagement), encoding="utf-8")
    written["json"] = json_path

    rendered = (
        filter_by_min_severity(findings, min_severity)
        if min_severity is not None and min_severity is not Severity.INFO
        else findings
    )

    if "md" in formats:
        p = out_dir_p / "report.md"
        p.write_text(render_markdown(rendered, engagement), encoding="utf-8")
        written["md"] = p
    if "html" in formats:
        p = out_dir_p / "report.html"
        p.write_text(render_html(rendered, engagement), encoding="utf-8")
        written["html"] = p
    if "sarif" in formats:
        p = out_dir_p / "report.sarif"
        p.write_text(render_sarif(rendered, engagement), encoding="utf-8")
        written["sarif"] = p
    return written


def re_render_from_json(
    findings_json_path: str | Path,
    out_dir: str | Path,
    *,
    formats: list[str] | None = None,
    min_severity: Severity | None = None,
) -> dict[str, Path]:
    """Re-render an existing ``findings.json`` to MD / HTML / SARIF.

    The input file's ``engagement`` block is reused so the regenerated
    report carries identical authorization metadata. **No new
    ``findings.json`` is written** — the input *is* the canonical record.
    Returns a map of format -> output path. Raises :class:`ValueError` if
    the JSON is malformed (missing ``findings``/``engagement``, or any
    finding cannot be parsed by :class:`Finding`).
    """
    src = Path(findings_json_path)
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{src} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{src} root must be a JSON object")
    eng_data = payload.get("engagement")
    if not isinstance(eng_data, dict):
        raise ValueError(f"{src} is missing the 'engagement' object")
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError(f"{src} is missing a 'findings' list")

    engagement = Engagement.from_dict(eng_data)
    findings: list[Finding] = []
    for i, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            raise ValueError(f"{src}: findings[{i}] is not an object")
        try:
            findings.append(Finding.model_validate(item))
        except Exception as exc:
            raise ValueError(f"{src}: findings[{i}] failed to parse: {exc}") from exc

    rendered = (
        filter_by_min_severity(findings, min_severity)
        if min_severity is not None and min_severity is not Severity.INFO
        else findings
    )

    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    formats = formats or ["md", "html"]
    written: dict[str, Path] = {}

    if "md" in formats:
        p = out_dir_p / "report.md"
        p.write_text(render_markdown(rendered, engagement), encoding="utf-8")
        written["md"] = p
    if "html" in formats:
        p = out_dir_p / "report.html"
        p.write_text(render_html(rendered, engagement), encoding="utf-8")
        written["html"] = p
    if "sarif" in formats:
        p = out_dir_p / "report.sarif"
        p.write_text(render_sarif(rendered, engagement), encoding="utf-8")
        written["sarif"] = p
    return written
