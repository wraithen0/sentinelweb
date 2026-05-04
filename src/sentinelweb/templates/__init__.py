"""YAML template engine for SentinelWeb.

Lets non-Python operators ship detection checks as YAML files in a
nuclei-inspired DSL. Templates are scope-gated end-to-end: every
HTTP request goes through the same :class:`~sentinelweb.utils.http.Client`
that scope-checks the host before a single packet leaves the box.

This is a deliberately small subset of nuclei's template language:
HTTP requests with status / word / regex matchers, no extractors, no
helpers, no DSL expressions, no templating beyond simple ``{{BaseURL}}``
substitution. The aim is "auditable in five minutes" rather than "every
nuclei template runs verbatim".
"""

from __future__ import annotations

from .loader import (
    TemplateError,
    list_builtin_paths,
    load_builtin,
    load_directory,
    load_template,
)
from .runner import run_templates_against
from .schema import HttpRequest, Matcher, Template, TemplateInfo

__all__ = [
    "HttpRequest",
    "Matcher",
    "Template",
    "TemplateError",
    "TemplateInfo",
    "list_builtin_paths",
    "load_builtin",
    "load_directory",
    "load_template",
    "run_templates_against",
]
