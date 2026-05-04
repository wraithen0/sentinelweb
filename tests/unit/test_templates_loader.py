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


def test_load_builtin_does_not_depend_on_disk_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test: ``load_builtin`` must work even when on-disk paths
    are unavailable (e.g. zip-imported install). It should read each
    resource via :py:meth:`Traversable.read_text` and never call
    ``__fspath__`` to obtain a temporary path that would dangle.
    """
    from sentinelweb.templates import loader

    # Fail loudly if any code path calls __fspath__ on a Traversable;
    # this is what the previous as_file()-after-context-exit bug did.
    real_iter = loader._iter_builtin_resources

    class FsPathTrap:
        def __init__(self, real: object) -> None:
            self._real = real

        def __getattr__(self, name: str) -> object:
            if name == "__fspath__":
                raise AssertionError(
                    "load_builtin must not depend on Traversable.__fspath__ "
                    "(would break zip-imported installs)"
                )
            return getattr(self._real, name)

        # Forward read_text directly so we don't trip __getattr__'s magic
        # filter on a dunder method.
        def read_text(self, encoding: str = "utf-8") -> str:
            return self._real.read_text(encoding=encoding)

        @property
        def name(self) -> str:
            return self._real.name

        def is_file(self) -> bool:
            return self._real.is_file()

    def _wrapped() -> object:
        for entry in real_iter():
            yield FsPathTrap(entry)

    monkeypatch.setattr(loader, "_iter_builtin_resources", _wrapped)
    out = load_builtin()
    assert out, "load_builtin should still return templates without filesystem paths"


def test_builtin_package_has_init_file() -> None:
    """The bundled-templates dir must be an explicit package (not namespace).

    Without ``__init__.py`` ``importlib.resources.files`` falls back to
    implicit-namespace-package handling, which CPython 3.11 only
    "partially supports". Adding the ``__init__.py`` makes the loader
    behave the same way regardless of how SentinelWeb was installed.
    """
    import sentinelweb.templates.builtin as pkg

    # The package must have a real loader; namespace packages have ``__path__``
    # but no ``__file__``.
    assert hasattr(pkg, "__file__"), (
        "templates/builtin must be a regular package with __init__.py, "
        "not a namespace package"
    )
