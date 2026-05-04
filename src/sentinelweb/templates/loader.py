"""Filesystem loader for YAML templates."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .schema import Template

BUILTIN_PACKAGE = "sentinelweb.templates.builtin"


class TemplateError(Exception):
    """Raised when a template file is invalid or a directory contains a duplicate id."""


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
    if not isinstance(data, dict):
        raise TemplateError(f"{p}: template must be a YAML mapping at the top level")
    try:
        return Template.model_validate(data)
    except ValidationError as exc:
        raise TemplateError(f"{p}: schema error: {exc}") from exc


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


def list_builtin_paths() -> list[Path]:
    """Return the on-disk paths to the bundled built-in templates."""
    pkg_root = resources.files(BUILTIN_PACKAGE)
    paths: list[Path] = []
    for entry in sorted(pkg_root.iterdir(), key=lambda x: x.name):
        if not entry.is_file():
            continue
        if not (entry.name.endswith(".yaml") or entry.name.endswith(".yml")):
            continue
        # ``Traversable`` is back-compat with Path on the disk-based loader.
        with resources.as_file(entry) as p:
            paths.append(Path(p))
    return paths


def load_builtin() -> list[Template]:
    """Load every template bundled inside the package."""
    return [load_template(p) for p in list_builtin_paths()]
