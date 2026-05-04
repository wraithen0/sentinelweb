from __future__ import annotations

import pytest

from sentinelweb.reporting.findings import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    sort_findings,
)


def make(severity: Severity, title: str = "x", target: str = "https://e.test") -> Finding:
    return Finding(
        id="X",
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        category="cat",
        description="desc",
        evidence=[Evidence(description="e")],
    )


def test_severity_from_cvss() -> None:
    assert Severity.from_cvss(9.8) == Severity.CRITICAL
    assert Severity.from_cvss(7.0) == Severity.HIGH
    assert Severity.from_cvss(5.5) == Severity.MEDIUM
    assert Severity.from_cvss(2.1) == Severity.LOW
    assert Severity.from_cvss(0.0) == Severity.INFO


def test_sort_findings_orders_by_severity_desc() -> None:
    items = [
        make(Severity.LOW),
        make(Severity.CRITICAL),
        make(Severity.MEDIUM),
        make(Severity.HIGH),
    ]
    out = sort_findings(items)
    assert [f.severity for f in out] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_empty_title_rejected() -> None:
    with pytest.raises(ValueError):
        Finding(
            id="X",
            title="",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            target="t",
            category="c",
            description="d",
        )
