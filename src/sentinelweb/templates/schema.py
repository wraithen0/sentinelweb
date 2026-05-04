"""Pydantic models for the YAML template DSL.

A template file looks like:

.. code-block:: yaml

    id: exposed-env-file
    info:
      name: "Exposed .env file"
      severity: high
      description: "/.env is reachable and contains key=value pairs."
      remediation: "Block dotfiles at the web server."
      references:
        - https://owasp.org/www-project-web-security-testing-guide/
      cwe: 200
      tags: [exposure, owasp-top-10]

    requests:
      - method: GET
        path:
          - "/.env"
        matchers-condition: and
        matchers:
          - type: status
            status: [200]
          - type: regex
            part: body
            regex:
              - "^[A-Z][A-Z0-9_]+=.+$"

The schema is intentionally a small subset of nuclei's template language
(HTTP only, status / word / regex / header matchers) so the entire
runtime is auditable.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from ..reporting.findings import Severity

ALLOWED_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "POST", "OPTIONS"})
"""Methods the runner is willing to issue.

Deliberately excludes PUT / DELETE / PATCH because those have observable
side effects on most servers; SentinelWeb is signal-only.
"""


class TemplateInfo(BaseModel):
    """The ``info:`` block of a template."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Annotated[str, Field(min_length=1, max_length=200)]
    severity: Severity
    description: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    cwe: str | None = None
    category: str = "yaml-template"
    tags: tuple[str, ...] = ()

    @field_validator("cwe", mode="before")
    @classmethod
    def _coerce_cwe(cls, v: object) -> str | None:
        if v is None:
            return None
        # Accept ``200`` (int) or ``"200"`` or ``"CWE-200"``; normalize to
        # ``"200"`` so :mod:`reporting.sarif` can apply its CWE- prefix.
        s = str(v).strip()
        if not s:
            return None
        if s.upper().startswith("CWE-"):
            s = s[4:]
        if not s.isdigit():
            raise ValueError("cwe must be a number, optional 'CWE-' prefix")
        return s


class _BaseMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    negative: bool = False


class StatusMatcher(_BaseMatcher):
    type: Literal["status"]
    status: tuple[int, ...] = Field(min_length=1)

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, v: object) -> tuple[int, ...]:
        if isinstance(v, int):
            return (v,)
        if isinstance(v, list):
            return tuple(int(x) for x in v)
        raise TypeError("status must be int or list of int")


class WordMatcher(_BaseMatcher):
    type: Literal["word"]
    words: tuple[str, ...] = Field(min_length=1)
    part: Literal["body", "header", "response"] = "body"
    condition: Literal["and", "or"] = "or"
    case_insensitive: bool = Field(default=False, alias="case-insensitive")
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @field_validator("words", mode="before")
    @classmethod
    def _coerce_words(cls, v: object) -> tuple[str, ...]:
        if isinstance(v, str):
            return (v,)
        if isinstance(v, list):
            return tuple(str(x) for x in v)
        raise TypeError("words must be str or list of str")


class RegexMatcher(_BaseMatcher):
    type: Literal["regex"]
    regex: tuple[str, ...] = Field(min_length=1)
    part: Literal["body", "header", "response"] = "body"
    condition: Literal["and", "or"] = "or"
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("regex", mode="before")
    @classmethod
    def _coerce_regex(cls, v: object) -> tuple[str, ...]:
        if isinstance(v, str):
            return (v,)
        if isinstance(v, list):
            return tuple(str(x) for x in v)
        raise TypeError("regex must be str or list of str")

    @field_validator("regex")
    @classmethod
    def _check_compilable(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for pat in v:
            try:
                re.compile(pat)
            except re.error as exc:
                raise ValueError(f"invalid regex {pat!r}: {exc}") from exc
        return v


Matcher = Annotated[
    StatusMatcher | WordMatcher | RegexMatcher,
    Field(discriminator="type"),
]


class HttpRequest(BaseModel):
    """A single ``requests:`` entry."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True
    )

    method: str = "GET"
    path: tuple[str, ...] = ("/",)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    matchers_condition: Literal["and", "or"] = Field(
        default="or", alias="matchers-condition"
    )
    matchers: tuple[Matcher, ...] = Field(min_length=1)

    @field_validator("method")
    @classmethod
    def _check_method(cls, v: str) -> str:
        m = v.upper().strip()
        if m not in ALLOWED_METHODS:
            raise ValueError(
                f"method {m!r} not allowed (allowed: {sorted(ALLOWED_METHODS)})"
            )
        return m

    @field_validator("path", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> tuple[str, ...]:
        if isinstance(v, str):
            return (v,)
        if isinstance(v, list):
            return tuple(str(x) for x in v)
        raise TypeError("path must be str or list of str")

    @field_validator("path")
    @classmethod
    def _validate_paths(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for p in v:
            if "://" in p or p.startswith("//"):
                raise ValueError(
                    f"path {p!r} looks like an absolute URL; templates must "
                    "use paths relative to the target so scope is enforceable"
                )
            if not p.startswith("/"):
                raise ValueError(f"path {p!r} must start with '/'")
        return v


class Template(BaseModel):
    """A complete template file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Annotated[str, Field(min_length=1, max_length=64)]
    info: TemplateInfo
    requests: tuple[HttpRequest, ...] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        s = v.strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*[a-z0-9]", s):
            raise ValueError(
                "template id must be kebab-case (lowercase letters, digits, "
                "hyphens; must start and end with alphanumeric)"
            )
        return s

    @property
    def finding_id(self) -> str:
        """Stable upper-case finding id derived from the template id.

        Always prefixed with ``TEMPLATE-`` so template-emitted findings
        cannot collide with the namespaces used by the built-in
        scanners (``HDR-``, ``CORS-``, ``TAKEOVER-``, etc.).
        """
        return f"TEMPLATE-{self.id.upper()}"
