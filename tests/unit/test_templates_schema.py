"""Tests for :mod:`sentinelweb.templates.schema`.

Schema validation is the first line of defense for the YAML template
engine: a malformed template should never reach the runner. These tests
cover positive cases, negative cases, and the safety guards (no absolute
URLs in paths, no destructive HTTP verbs, no id collision with builtin
finding namespaces).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinelweb.templates.schema import (
    HttpRequest,
    RegexMatcher,
    StatusMatcher,
    Template,
    TemplateInfo,
    WordMatcher,
)


def _minimal_template_dict() -> dict:
    return {
        "id": "minimal",
        "info": {"name": "Minimal", "severity": "low"},
        "requests": [
            {
                "path": ["/"],
                "matchers": [{"type": "status", "status": [200]}],
            }
        ],
    }


def test_minimal_template_loads() -> None:
    t = Template.model_validate(_minimal_template_dict())
    assert t.id == "minimal"
    assert t.finding_id == "TEMPLATE-MINIMAL"
    assert t.requests[0].method == "GET"
    assert t.info.severity.value == "low"


def test_id_must_be_kebab_case() -> None:
    bad = _minimal_template_dict()
    bad["id"] = "Minimal_With_Underscore"
    with pytest.raises(ValidationError, match="kebab-case"):
        Template.model_validate(bad)


def test_id_collision_with_builtin_namespace_is_safe() -> None:
    """The TEMPLATE- prefix protects against accidental finding-id collisions."""
    data = _minimal_template_dict()
    data["id"] = "hdr-leakage"  # would yield TEMPLATE-HDR-LEAKAGE
    t = Template.model_validate(data)
    # Always namespaced so it cannot clash with HDR-* / SARIF rule ids
    # produced by the built-in scanners.
    assert t.finding_id.startswith("TEMPLATE-")
    assert t.finding_id == "TEMPLATE-HDR-LEAKAGE"


def test_method_restricted_to_safe_verbs() -> None:
    bad = _minimal_template_dict()
    bad["requests"][0]["method"] = "DELETE"
    with pytest.raises(ValidationError, match="not allowed"):
        Template.model_validate(bad)


def test_path_must_be_relative() -> None:
    bad = _minimal_template_dict()
    bad["requests"][0]["path"] = ["http://attacker.test/"]
    with pytest.raises(ValidationError, match="relative"):
        Template.model_validate(bad)


def test_path_must_start_with_slash() -> None:
    bad = _minimal_template_dict()
    bad["requests"][0]["path"] = ["foo"]
    with pytest.raises(ValidationError, match="must start with '/'"):
        Template.model_validate(bad)


def test_extra_top_level_keys_rejected() -> None:
    bad = _minimal_template_dict()
    bad["unknown_field"] = "value"
    with pytest.raises(ValidationError, match=r"(?i)extra"):
        Template.model_validate(bad)


def test_word_matcher_alias_case_insensitive() -> None:
    """``case-insensitive`` (with hyphen) should map to ``case_insensitive``."""
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = [
        {
            "type": "word",
            "words": ["DEBUG"],
            "case-insensitive": True,
        }
    ]
    t = Template.model_validate(data)
    matcher = t.requests[0].matchers[0]
    assert isinstance(matcher, WordMatcher)
    assert matcher.case_insensitive is True


def test_matchers_condition_alias() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers-condition"] = "and"
    t = Template.model_validate(data)
    assert t.requests[0].matchers_condition == "and"


def test_regex_must_be_compilable() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = [{"type": "regex", "regex": ["[unclosed"]}]
    with pytest.raises(ValidationError, match="invalid regex"):
        Template.model_validate(data)


def test_status_int_coerced_to_tuple() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = [{"type": "status", "status": 200}]
    t = Template.model_validate(data)
    matcher = t.requests[0].matchers[0]
    assert isinstance(matcher, StatusMatcher)
    assert matcher.status == (200,)


def test_words_str_coerced_to_tuple() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = [{"type": "word", "words": "secret"}]
    t = Template.model_validate(data)
    matcher = t.requests[0].matchers[0]
    assert isinstance(matcher, WordMatcher)
    assert matcher.words == ("secret",)


def test_regex_str_coerced_to_tuple() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = [{"type": "regex", "regex": r"^foo"}]
    t = Template.model_validate(data)
    matcher = t.requests[0].matchers[0]
    assert isinstance(matcher, RegexMatcher)
    assert matcher.regex == (r"^foo",)


def test_template_requires_at_least_one_request() -> None:
    data = _minimal_template_dict()
    data["requests"] = []
    with pytest.raises(ValidationError):
        Template.model_validate(data)


def test_request_requires_at_least_one_matcher() -> None:
    data = _minimal_template_dict()
    data["requests"][0]["matchers"] = []
    with pytest.raises(ValidationError):
        Template.model_validate(data)


def test_info_severity_restricted_to_enum() -> None:
    data = _minimal_template_dict()
    data["info"]["severity"] = "extreme"
    with pytest.raises(ValidationError):
        Template.model_validate(data)


def test_cwe_normalization() -> None:
    info = TemplateInfo.model_validate(
        {"name": "X", "severity": "low", "cwe": "CWE-200"}
    )
    assert info.cwe == "200"

    info = TemplateInfo.model_validate(
        {"name": "X", "severity": "low", "cwe": 200}
    )
    assert info.cwe == "200"

    with pytest.raises(ValidationError):
        TemplateInfo.model_validate(
            {"name": "X", "severity": "low", "cwe": "abc"}
        )


def test_http_request_default_path_and_method() -> None:
    req = HttpRequest.model_validate(
        {"matchers": [{"type": "status", "status": [200]}]}
    )
    assert req.method == "GET"
    assert req.path == ("/",)
