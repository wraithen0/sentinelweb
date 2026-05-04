"""Finding model — the canonical output unit of every scanner."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(StrEnum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CERTAIN = "certain"


class Evidence(BaseModel):
    """A single piece of evidence backing a finding."""

    description: str
    request: str | None = None
    response_excerpt: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A vulnerability or security observation produced by a scanner.

    Findings are signal-only: they describe what was *observed* and how to
    reproduce it, never how to weaponize it.
    """

    id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.FIRM
    target: str
    category: str
    description: str
    remediation: str = ""
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    detected_by: str = ""
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    tags: list[str] = Field(default_factory=list)

    @field_validator("title", "description", "target", "category", "id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v.strip()

    def severity_rank(self) -> int:
        return _SEVERITY_ORDER.index(self.severity)


_SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def severity_rank_of(severity: Severity) -> int:
    """Return the ordinal rank (0..4) of ``severity`` for filter comparisons."""
    return _SEVERITY_ORDER.index(severity)


def filter_by_min_severity(
    findings: list[Finding], min_severity: Severity
) -> list[Finding]:
    """Return only those findings whose severity is at least ``min_severity``.

    ``Severity.INFO`` is the lowest rank, so ``min_severity=Severity.INFO``
    is a no-op (returns ``findings`` unchanged). The function is pure: it
    does not mutate the input list, and order is preserved.
    """
    threshold = severity_rank_of(min_severity)
    return [f for f in findings if f.severity_rank() >= threshold]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity_rank(), f.target, f.title))
