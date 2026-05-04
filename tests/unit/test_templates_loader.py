"""Tests for :mod:`sentinelweb.templates.loader`."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelweb.templates.loader import (
    TemplateError,
    list_builtin_paths,
    load_builtin,
    load_directory,
    load_template,
)


def _write_yaml(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_load_template_from_file(tmp_path: Path) -> None:
    p = _write_yaml(
        tmp_path / "x.yaml",
        """\
id: cool-id
info:
  name: Cool
  severity: low
requests:
  - path:
      - "/x"
    matchers:
      - type: status
        status: [200]
""",
    )
    t = load_template(p)
    assert t.id == "cool-id"


def test_load_template_missing_file() -> None:
    with pytest.raises(TemplateError, match="not found"):
        load_template("/no/such/path.yaml")


def test_load_template_invalid_yaml(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "bad.yaml", "id: [unterminated")
    with pytest.raises(TemplateError, match="invalid YAML"):
        load_template(p)


def test_load_template_non_mapping(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "list.yaml", "- 1\n- 2\n")
    with pytest.raises(TemplateError, match="mapping"):
        load_template(p)


def test_load_template_schema_error(tmp_path: Path) -> None:
    p = _write_yaml(
        tmp_path / "bad.yaml",
        """\
id: bad
info:
  name: X
  severity: bogus
requests:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
""",
    )
    with pytest.raises(TemplateError, match="schema error"):
        load_template(p)


def test_load_directory_roundtrip(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "a.yaml",
        """\
id: a-template
info:
  name: A
  severity: low
requests:
  - path: ["/a"]
    matchers:
      - type: status
        status: [200]
""",
    )
    _write_yaml(
        tmp_path / "b.yml",
        """\
id: b-template
info:
  name: B
  severity: medium
requests:
  - path: ["/b"]
    matchers:
      - type: status
        status: [200]
""",
    )
    # Stray non-yaml file should be ignored.
    (tmp_path / "readme.md").write_text("# notes\n")
    out = load_directory(tmp_path)
    assert sorted(t.id for t in out) == ["a-template", "b-template"]


def test_load_directory_duplicate_id_rejected(tmp_path: Path) -> None:
    body = """\
id: dup
info:
  name: D
  severity: low
requests:
  - path: ["/x"]
    matchers:
      - type: status
        status: [200]
"""
    _write_yaml(tmp_path / "one.yaml", body)
    _write_yaml(tmp_path / "two.yaml", body)
    with pytest.raises(TemplateError, match="duplicate template id"):
        load_directory(tmp_path)


def test_load_directory_missing_dir() -> None:
    with pytest.raises(TemplateError, match="not found"):
        load_directory("/no/such/dir")


def test_load_directory_not_a_dir(tmp_path: Path) -> None:
    p = tmp_path / "notdir"
    p.write_text("not a dir")
    with pytest.raises(TemplateError, match="not a directory"):
        load_directory(p)


def test_load_builtin_loads_at_least_one() -> None:
    builtins = load_builtin()
    assert len(builtins) >= 3
    ids = {t.id for t in builtins}
    # Sanity check a known bundled id; if this drifts we want CI to flag it.
    assert "exposed-env-file" in ids


def test_list_builtin_paths_returns_yaml_files() -> None:
    paths = list_builtin_paths()
    assert paths
    for p in paths:
        assert p.suffix.lower() in {".yaml", ".yml"}
