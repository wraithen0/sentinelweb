"""Filesystem loader for YAML templates."""

from __future__ import annotations

from collections.abc import Iterator
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .schema import Template

BUILTIN_PACKAGE = "sentinelweb.templates.builtin"


class TemplateError(Exception):
    """Raised when a template file is invalid or a directory contains a duplicate id."""


def _parse_template(data: Any, source_label: str) -> Template:
    """Validate already-loaded YAML data into a :class:`Template`."""
    if not isinstance(data, dict):
        raise TemplateError(
            f"{source_label}: template must be a YAML mapping at the top level"
        )
    try:
        return Template.model_validate(data)
    except ValidationError as exc:
        raise TemplateError(f"{source_label}: schema error: {exc}") from exc


def load_template(path: str | Path) -> Template:
    """Load a single template file."""
    p = Path(path)
    if not p.exists():
        raise TemplateError(f"template file not found: {p}")
    try:
        with p.open("r", encoding="utf-8") as fh:
            data: Any = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise TemplateError(f"{p}: invalid YAML: {exc}") from exc
    return _parse_template(data, str(p))


def load_directory(path: str | Path) -> list[Template]:
    """Load every ``*.yaml`` / ``*.yml`` file in the directory.

    Raises :class:`TemplateError` if any file fails to parse, or if two
    templates share the same ``id``.
    """
    p = Path(path)
    if not p.exists():
        raise TemplateError(f"templates directory not found: {p}")
    if not p.is_dir():
        raise TemplateError(f"templates path is not a directory: {p}")
    seen: dict[str, Path] = {}
    out: list[Template] = []
    for f in sorted(p.iterdir()):
        if not f.is_file():
            continue
        if f.suffix.lower() not in {".yaml", ".yml"}:
            continue
        tpl = load_template(f)
        if tpl.id in seen:
            raise TemplateError(
                f"duplicate template id {tpl.id!r}: {seen[tpl.id]} vs {f}"
            )
        seen[tpl.id] = f
        out.append(tpl)
    return out


def _iter_builtin_resources() -> Iterator[Traversable]:
    """Yield each bundled template file as an ``importlib.resources`` Traversable."""
    pkg_root = resources.files(BUILTIN_PACKAGE)
    for entry in sorted(pkg_root.iterdir(), key=lambda x: x.name):
        if not entry.is_file():
            continue
        if not (entry.name.endswith(".yaml") or entry.name.endswith(".yml")):
            continue
        yield entry


def load_builtin() -> list[Template]:
    """Load every template bundled inside the package.

    Reads each resource via ``Traversable.read_text`` so the loader
    works regardless of how the package was installed (wheel, sdist,
    editable, or zip-imported). Earlier versions stored a temporary
    on-disk path returned by ``resources.as_file`` *after* its context
    manager exited, which dangled for zip installs.
    """
    out: list[Template] = []
    for entry in _iter_builtin_resources():
        try:
            text = entry.read_text(encoding="utf-8")
        except OSError as exc:
            raise TemplateError(
                f"{entry.name}: failed to read built-in template: {exc}"
            ) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise TemplateError(
                f"{entry.name}: invalid YAML: {exc}"
            ) from exc
        out.append(_parse_template(data, entry.name))
    return out


def list_builtin_paths() -> list[Path]:
    """Return on-disk paths of bundled templates for disk-based installs.

    .. note::
       Prefer :func:`load_builtin` for actually loading templates — it
       works under every installation method. This helper exists for
       diagnostic tooling that wants paths and is only valid when the
       package is installed on a real filesystem (wheel, sdist, or
       editable). For zip-imported installs the returned paths would be
       temporary and invalid; we deliberately return an empty list in
       that case rather than handing back dangling paths.
    """
    paths: list[Path] = []
    for entry in _iter_builtin_resources():
        # Traversable's __fspath__ is only guaranteed for filesystem
        # backings. We try and skip on any failure rather than leaking
        # a temporary extraction path.
        try:
            paths.append(Path(entry.__fspath__()))  # type: ignore[attr-defined]
        except (AttributeError, TypeError, NotImplementedError):
            continue
    return paths
