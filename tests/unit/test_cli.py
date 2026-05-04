"""Smoke tests for the CLI entry points."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from sentinelweb.cli.main import cli


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "sentinelweb" in result.output.lower()


def test_scope_init_prints_yaml() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scope", "init"])
    assert result.exit_code == 0
    assert "engagement:" in result.output
    assert "in_scope" in result.output


def test_scope_validate(tmp_path: Path) -> None:
    p = tmp_path / "scope.yaml"
    p.write_text(
        """
engagement:
  program: t
  authorization: https://h1/t
in_scope: ["example.test"]
"""
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["scope", "validate", str(p)])
    assert result.exit_code == 0


def test_scope_check_in_scope(tmp_path: Path) -> None:
    p = tmp_path / "scope.yaml"
    p.write_text(
        """
engagement:
  program: t
  authorization: https://h1/t
in_scope: ["example.test"]
"""
    )
    runner = CliRunner()
    ok = runner.invoke(cli, ["scope", "check", str(p), "example.test"])
    assert ok.exit_code == 0
    bad = runner.invoke(cli, ["scope", "check", str(p), "evil.test"])
    assert bad.exit_code != 0
