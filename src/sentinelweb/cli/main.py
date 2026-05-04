"""SentinelWeb command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..recon import endpoints as recon_endpoints
from ..recon import ports as recon_ports
from ..recon import subdomains as recon_subdomains
from ..recon import tech as recon_tech
from ..reporting import render
from ..reporting.findings import (
    Finding,
    Severity,
    filter_by_min_severity,
    sort_findings,
)
from ..scanners import cors as scan_cors
from ..scanners import headers as scan_headers
from ..scanners import jwt as scan_jwt
from ..scanners import redirect as scan_redirect
from ..scanners import secrets as scan_secrets
from ..scanners import sqli as scan_sqli
from ..scanners import ssrf as scan_ssrf
from ..scanners import takeover as scan_takeover
from ..scanners import tls as scan_tls
from ..scanners import xss as scan_xss
from ..scope.audit import AuditLog, verify
from ..scope.policy import OutOfScopeError, ScopeError, ScopePolicy, example_yaml
from ..scope.session import Session, SessionError
from ..templates import (
    Template,
    TemplateError,
    load_builtin,
    load_directory,
    run_templates_against,
)
from ..utils.http import make_client
from ..utils.logging import configure, fatal, get_logger
from ..utils.urls import normalize_host

console = Console()
log = get_logger(__name__)


def _load_scope(path: str) -> ScopePolicy:
    try:
        return ScopePolicy.load(path)
    except ScopeError as exc:
        fatal(str(exc))
        raise  # for type checkers


def _load_session(
    session_path: str | None, policy: ScopePolicy
) -> Session | None:
    """Load and scope-bind a session file. Returns None when path is None."""
    if not session_path:
        return None
    try:
        return Session.load(session_path).bind(policy)
    except SessionError as exc:
        fatal(str(exc))
        raise


def _load_templates(
    templates_dir: str | None, ids: tuple[str, ...] = ()
) -> list[Template]:
    """Load templates from ``templates_dir`` or fall back to built-ins.

    When ``ids`` is non-empty, filter to that set; abort if any id is
    missing. Returns at least one template or aborts with ``fatal``.
    """
    try:
        templates = (
            load_directory(templates_dir)
            if templates_dir
            else load_builtin()
        )
    except TemplateError as exc:
        fatal(str(exc))
        raise

    if ids:
        wanted = {i.strip() for i in ids if i.strip()}
        templates = [t for t in templates if t.id in wanted]
        missing = wanted - {t.id for t in templates}
        if missing:
            fatal(f"unknown template id(s): {sorted(missing)}")

    if not templates:
        fatal(
            "no templates loaded (empty directory or all filtered out by --id)"
        )

    return templates


def _verify_xss(findings: list[Finding], policy: ScopePolicy) -> list[Finding]:
    """Promote tentative XSS findings via headless Firefox.

    Imported lazily so the optional ``[headless]`` extra (Selenium) is
    only required when the user actually passes ``--verify-xss``.
    """
    try:
        from ..headless import (
            FirefoxVerifier,
            verify_xss_findings,
        )
    except ImportError as exc:  # pragma: no cover - defensive
        fatal(
            "headless verification unavailable: "
            f"{exc}. Install with `pip install -e '.[headless]'`."
        )
        return findings
    ok, reason = FirefoxVerifier.is_available()
    if not ok:
        console.print(
            f"[yellow]--verify-xss skipped:[/yellow] {reason}"
        )
        return findings
    candidates = [f for f in findings if f.id.startswith("XSS-REFLECTED-")]
    if not candidates:
        console.print(
            "[yellow]--verify-xss:[/yellow] no XSS-REFLECTED-* findings to verify."
        )
        return findings
    console.print(
        f"[cyan]--verify-xss:[/cyan] launching headless Firefox to verify "
        f"{len(candidates)} candidate(s)..."
    )
    with FirefoxVerifier(scope=policy) as verifier:
        return verify_xss_findings(findings, policy, verifier)


def _attach_audit(policy: ScopePolicy, audit_path: str | None) -> AuditLog | None:
    if not audit_path:
        return None
    log_obj = AuditLog(audit_path)
    log_obj.append(
        "run.start",
        target=policy.engagement.program,
        detail={
            "authorization": policy.engagement.authorization,
            "in_scope": list(policy.in_scope),
            "out_of_scope": list(policy.out_of_scope),
            "rate_per_sec": policy.rate_per_sec,
        },
    )
    return log_obj


@click.group(help="SentinelWeb — defensive web2 security framework.")
@click.version_option(__version__, prog_name="sentinelweb")
@click.option("--log-level", default="INFO", show_default=True, help="Logging level.")
def cli(log_level: str) -> None:
    configure(level=log_level)


# ---------------------------------------------------------------------------
# scope subcommands
# ---------------------------------------------------------------------------


@cli.group(help="Scope management commands.")
def scope() -> None: ...


@scope.command("init", help="Print an example scope.yaml to stdout.")
def scope_init() -> None:
    click.echo(example_yaml())


@scope.command("validate", help="Validate a scope file.")
@click.argument("scope_path", type=click.Path(exists=True, dir_okay=False))
def scope_validate(scope_path: str) -> None:
    policy = _load_scope(scope_path)
    console.print(
        f"[green]ok[/green] scope file is valid; "
        f"{len(policy.in_scope)} in-scope, {len(policy.out_of_scope)} out-of-scope, "
        f"rate={policy.rate_per_sec}/s"
    )


@scope.command("check", help="Check whether a host/URL is in scope.")
@click.argument("scope_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("target")
def scope_check(scope_path: str, target: str) -> None:
    policy = _load_scope(scope_path)
    ok = policy.is_in_scope(target)
    if ok:
        console.print(f"[green]in-scope[/green]: {target}")
    else:
        console.print(f"[red]OUT OF SCOPE[/red]: {target}")
        sys.exit(2)


@scope.command("audit-verify", help="Verify the hash chain of an audit log.")
@click.argument("audit_path", type=click.Path(exists=True, dir_okay=False))
def scope_audit_verify(audit_path: str) -> None:
    ok, n, err = verify(audit_path)
    if ok:
        console.print(f"[green]ok[/green] audit chain verified across {n} entries")
    else:
        console.print(f"[red]FAIL[/red] audit chain broken: {err}")
        sys.exit(2)


# ---------------------------------------------------------------------------
# recon subcommands
# ---------------------------------------------------------------------------


@cli.group(help="Reconnaissance commands.")
def recon() -> None: ...


@recon.command("subs", help="Enumerate subdomains for a registered domain.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.option("--wordlist", type=click.Path(exists=True), default=None)
@click.argument("domain")
def recon_subs(
    scope_path: str, audit_path: str | None, wordlist: str | None, domain: str
) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)

    async def _run() -> list[str]:
        async with make_client(rate_per_sec=policy.rate_per_sec) as client:
            words = None
            if wordlist:
                words = Path(wordlist).read_text().splitlines()
            return await recon_subdomains.enumerate(
                domain, policy, client, wordlist=words
            )

    results = asyncio.run(_run())
    if audit:
        audit.append("recon.subs", target=domain, detail={"count": len(results)})
    for r in results:
        click.echo(r)


@recon.command("ports", help="Run nmap against a host (must be in scope).")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--ports", default="80,443,8080,8443", show_default=True)
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.argument("host")
def recon_ports_cmd(scope_path: str, ports: str, audit_path: str | None, host: str) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)
    try:
        services = recon_ports.scan(host, policy, ports=ports)
    except recon_ports.NmapError as exc:
        fatal(str(exc))
        return
    if audit:
        audit.append("recon.ports", target=host, detail={"count": len(services)})
    table = Table(title=f"Open services on {host}")
    table.add_column("port")
    table.add_column("proto")
    table.add_column("state")
    table.add_column("service")
    table.add_column("product/version")
    for s in services:
        table.add_row(
            str(s.port),
            s.proto,
            s.state,
            s.service,
            f"{s.product} {s.version}".strip(),
        )
    console.print(table)


@recon.command("tech", help="Fingerprint tech stack of a URL.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.argument("url")
def recon_tech_cmd(scope_path: str, audit_path: str | None, url: str) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)

    async def _run() -> list[recon_tech.Tech]:
        async with make_client(rate_per_sec=policy.rate_per_sec) as client:
            return await recon_tech.fingerprint(url, policy, client)

    techs = asyncio.run(_run())
    if audit:
        audit.append("recon.tech", target=url, detail={"count": len(techs)})
    for t in techs:
        click.echo(f"[{t.where}] {t.name}  {t.detail}".rstrip())


@recon.command("endpoints", help="Discover URLs/forms/params on a page.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.argument("url")
def recon_endpoints_cmd(scope_path: str, audit_path: str | None, url: str) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)

    async def _run() -> dict[str, list[str]]:
        async with make_client(rate_per_sec=policy.rate_per_sec) as client:
            return await recon_endpoints.discover(url, policy, client)

    results = asyncio.run(_run())
    if audit:
        audit.append(
            "recon.endpoints",
            target=url,
            detail={k: len(v) for k, v in results.items()},
        )
    click.echo(json.dumps(results, indent=2))


# ---------------------------------------------------------------------------
# scan subcommand — runs the OWASP-oriented scanners.
# ---------------------------------------------------------------------------


@cli.command("scan", help="Run a scan suite against URL targets.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.option(
    "--session",
    "session_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=(
        "Authenticated session file (YAML/JSON) carrying cookies + headers. "
        "Session credentials are attached only to in-scope hosts."
    ),
)
@click.option(
    "--scanner",
    multiple=True,
    type=click.Choice(
        [
            "headers",
            "cors",
            "redirect",
            "xss",
            "sqli",
            "tls",
            "takeover",
            "templates",
            "secrets",
            "all",
        ]
    ),
    default=["all"],
    show_default=True,
)
@click.option(
    "--templates-dir",
    "templates_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help=(
        "Directory of YAML detection templates to use when --scanner "
        "templates is selected. Defaults to the bundled built-in set."
    ),
)
@click.option(
    "--template-id",
    "template_ids",
    multiple=True,
    default=(),
    help=(
        "Restrict --scanner templates to specific template ids "
        "(repeat the flag to allow several)."
    ),
)
@click.option(
    "--verify-xss",
    "verify_xss",
    is_flag=True,
    default=False,
    help=(
        "Headlessly verify reflected-XSS findings using system Firefox "
        "(via geckodriver). Requires the `headless` optional extra and "
        "`firefox` + `geckodriver` on PATH. Confirmed findings are "
        "appended as XSS-VERIFIED-<PARAM> with severity CRITICAL."
    ),
)
@click.option("--report-dir", type=click.Path(), default="reports", show_default=True)
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(["md", "html", "sarif"]),
    default=("md", "html"),
    show_default=True,
    help=(
        "Report formats to render. findings.json is always emitted; "
        "use --format sarif for SARIF 2.1.0 output suitable for "
        "GitHub code-scanning."
    ),
)
@click.option(
    "--severity-threshold",
    "severity_threshold",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default="info",
    show_default=True,
    help=(
        "Minimum severity to render in the human-readable report and CLI "
        "summary. ``findings.json`` always contains every observation so "
        "you can re-render at any threshold via ``sentinelweb report``."
    ),
)
@click.argument("targets", nargs=-1, required=True)
def scan_cmd(
    scope_path: str,
    audit_path: str | None,
    session_path: str | None,
    scanner: tuple[str, ...],
    templates_dir: str | None,
    template_ids: tuple[str, ...],
    verify_xss: bool,
    report_dir: str,
    formats: tuple[str, ...],
    severity_threshold: str,
    targets: tuple[str, ...],
) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)
    session = _load_session(session_path, policy)
    selected = set(scanner)
    if "all" in selected:
        selected = {
            "headers",
            "cors",
            "redirect",
            "xss",
            "sqli",
            "tls",
            "takeover",
            "templates",
            "secrets",
        }

    for url in targets:
        try:
            policy.assert_in_scope(url)
        except OutOfScopeError as exc:
            fatal(str(exc))
            return

    templates: list[Template] = (
        _load_templates(templates_dir, template_ids)
        if "templates" in selected
        else []
    )

    findings: list[Finding] = []

    async def _run_async() -> None:
        async with make_client(
            rate_per_sec=policy.rate_per_sec,
            max_redirects=0,
            session=session,
            policy=policy,
        ) as client:
            for url in targets:
                if "headers" in selected:
                    findings.extend(await scan_headers.scan(url, policy, client))
                if "cors" in selected:
                    findings.extend(await scan_cors.scan(url, policy, client))
                if "redirect" in selected:
                    findings.extend(await scan_redirect.scan(url, policy, client))
                if "xss" in selected:
                    findings.extend(await scan_xss.scan(url, policy, client))
                if "sqli" in selected:
                    findings.extend(await scan_sqli.scan(url, policy, client))
                if "takeover" in selected:
                    findings.extend(await scan_takeover.scan(url, policy, client))
                if "secrets" in selected:
                    findings.extend(await scan_secrets.scan(url, policy, client))
            if templates:
                findings.extend(
                    await run_templates_against(
                        templates, list(targets), policy, client
                    )
                )

    asyncio.run(_run_async())

    if "tls" in selected:
        for url in targets:
            findings.extend(scan_tls.scan(url, policy))

    if verify_xss:
        findings = _verify_xss(findings, policy)

    findings = sort_findings(findings)
    threshold = Severity(severity_threshold)
    rendered_findings = (
        filter_by_min_severity(findings, threshold)
        if threshold is not Severity.INFO
        else findings
    )
    _print_summary(
        rendered_findings,
        threshold=threshold,
        unfiltered_total=len(findings),
    )
    written = render.write_report(
        findings,
        policy.engagement,
        report_dir,
        formats=list(formats),
        min_severity=threshold,
    )
    for fmt, path in written.items():
        console.print(f"[bold]{fmt}[/bold] -> {path}")
    if audit:
        audit.append(
            "scan.complete",
            target=",".join(targets),
            detail={
                "scanners": sorted(selected),
                "findings": len(findings),
                "rendered_findings": len(rendered_findings),
                "severity_threshold": threshold.value,
            },
        )


# ---------------------------------------------------------------------------
# report subcommand — re-render an existing findings.json without re-scanning.
# ---------------------------------------------------------------------------


@cli.command(
    "report",
    help=(
        "Re-render an existing findings.json into MD / HTML / SARIF without "
        "re-scanning. Useful for tweaking templates, applying a stricter "
        "severity threshold, or producing a SARIF artifact for a previously "
        "scanned target."
    ),
)
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a findings.json produced by `sentinelweb scan`.",
)
@click.option(
    "--report-dir",
    type=click.Path(),
    default="reports-rerendered",
    show_default=True,
    help="Directory to write rendered reports into. Created if missing.",
)
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(["md", "html", "sarif"]),
    default=("md", "html"),
    show_default=True,
    help=(
        "Report formats to render. Unlike `scan`, no findings.json is "
        "written here — the input file is the canonical record."
    ),
)
@click.option(
    "--severity-threshold",
    "severity_threshold",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default="info",
    show_default=True,
    help=(
        "Minimum severity to render. The original findings.json is left "
        "untouched; only the rendered MD / HTML / SARIF respect this "
        "filter."
    ),
)
def report_cmd(
    input_path: str,
    report_dir: str,
    formats: tuple[str, ...],
    severity_threshold: str,
) -> None:
    threshold = Severity(severity_threshold)
    try:
        written = render.re_render_from_json(
            input_path,
            report_dir,
            formats=list(formats),
            min_severity=threshold,
        )
    except ValueError as exc:
        fatal(str(exc))
        return
    for fmt, path in written.items():
        console.print(f"[bold]{fmt}[/bold] -> {path}")


# ---------------------------------------------------------------------------
# jwt subcommand — analyzes a JWT directly.
# ---------------------------------------------------------------------------


@cli.command("jwt", help="Statically analyze a JWT for common weaknesses.")
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None)
@click.option(
    "--target",
    default="<token>",
    show_default=True,
    help="Display target the token is associated with (e.g. URL).",
)
@click.option("--wordlist", type=click.Path(exists=True), default=None)
@click.argument("token")
def jwt_cmd(
    scope_path: str | None, target: str, wordlist: str | None, token: str
) -> None:
    policy = None
    if scope_path:
        policy = _load_scope(scope_path)
        if target != "<token>":
            try:
                policy.assert_in_scope(target)
            except OutOfScopeError as exc:
                fatal(str(exc))
                return
    findings = scan_jwt.analyze(token, target=target)
    if wordlist:
        words = Path(wordlist).read_text().splitlines()
        secret = scan_jwt.try_weak_secret(token, words)
        if secret:
            from ..reporting.findings import Confidence, Evidence, Severity

            findings.append(
                Finding(
                    id="JWT-WEAK-SECRET",
                    title="JWT signed with weak/dictionary secret",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    target=target,
                    category="jwt",
                    cwe="798",
                    description=(
                        "The HMAC secret was found in the supplied wordlist. "
                        "Anyone with this secret can forge arbitrary tokens."
                    ),
                    remediation="Rotate the signing key to a 32+ byte random secret.",
                    detected_by="scanners.jwt",
                    evidence=[Evidence(description="secret recovered (redacted)")],
                )
            )
    _print_summary(findings)
    for f in findings:
        console.print(f"[bold]{f.severity.value.upper()}[/bold] {f.title}")
    _ = policy  # silence unused


# ---------------------------------------------------------------------------
# ssrf subcommand
# ---------------------------------------------------------------------------


@cli.command("ssrf", help="Send SSRF probes pointing at a callback URL you control.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.option(
    "--callback",
    required=True,
    help="External callback URL you control (e.g. interactsh / collaborator).",
)
@click.argument("targets", nargs=-1, required=True)
def ssrf_cmd(
    scope_path: str, audit_path: str | None, callback: str, targets: tuple[str, ...]
) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)

    async def _run() -> list[Finding]:
        out: list[Finding] = []
        async with make_client(rate_per_sec=policy.rate_per_sec) as client:
            for url in targets:
                try:
                    policy.assert_in_scope(url)
                except OutOfScopeError as exc:
                    fatal(str(exc))
                out.extend(
                    await scan_ssrf.scan(url, policy, client, callback_url=callback)
                )
        return out

    findings = asyncio.run(_run())
    if audit:
        audit.append(
            "scan.ssrf",
            target=",".join(targets),
            detail={"callback": callback, "findings": len(findings)},
        )
    _print_summary(findings)


# ---------------------------------------------------------------------------
# takeover subcommand — DNS+HTTP fingerprint for dangling SaaS CNAMEs.
# ---------------------------------------------------------------------------


@cli.command(
    "takeover",
    help="Probe in-scope hosts for dangling-CNAME subdomain takeovers.",
)
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.argument("hosts", nargs=-1, required=True)
def takeover_cmd(
    scope_path: str, audit_path: str | None, hosts: tuple[str, ...]
) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)

    for h in hosts:
        try:
            policy.assert_in_scope(h)
        except OutOfScopeError as exc:
            fatal(str(exc))
            return

    async def _run() -> list[Finding]:
        out: list[Finding] = []
        async with make_client(rate_per_sec=policy.rate_per_sec) as client:
            for h in hosts:
                out.extend(await scan_takeover.scan(h, policy, client))
        return out

    findings = asyncio.run(_run())
    if audit:
        audit.append(
            "scan.takeover",
            target=",".join(hosts),
            detail={"findings": len(findings)},
        )
    _print_summary(findings)
    for f in findings:
        console.print(
            f"[bold]{f.severity.value.upper()}[/bold] {f.id}  {f.target}"
        )


# ---------------------------------------------------------------------------
# templates subgroup — list/run YAML detection templates.
# ---------------------------------------------------------------------------


@cli.group(help="YAML detection-template engine.")
def templates() -> None: ...


@templates.command("list", help="List available templates.")
@click.option(
    "--templates-dir",
    "templates_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Directory of templates to list. Defaults to bundled built-ins.",
)
def templates_list(templates_dir: str | None) -> None:
    loaded = _load_templates(templates_dir)
    table = Table(title=f"Templates ({len(loaded)})")
    table.add_column("id")
    table.add_column("severity")
    table.add_column("category")
    table.add_column("name")
    for t in loaded:
        table.add_row(
            t.id, t.info.severity.value.upper(), t.info.category, t.info.name
        )
    console.print(table)


@templates.command("run", help="Run YAML detection templates against in-scope targets.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(), default=None)
@click.option(
    "--session",
    "session_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=(
        "Authenticated session file (YAML/JSON) carrying cookies + headers. "
        "Session credentials are attached only to in-scope hosts."
    ),
)
@click.option(
    "--templates-dir",
    "templates_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Directory of templates to run. Defaults to bundled built-ins.",
)
@click.option(
    "--template-id",
    "template_ids",
    multiple=True,
    default=(),
    help="Restrict the run to specific template ids (repeatable).",
)
@click.argument("targets", nargs=-1, required=True)
def templates_run_cmd(
    scope_path: str,
    audit_path: str | None,
    session_path: str | None,
    templates_dir: str | None,
    template_ids: tuple[str, ...],
    targets: tuple[str, ...],
) -> None:
    policy = _load_scope(scope_path)
    audit = _attach_audit(policy, audit_path)
    session = _load_session(session_path, policy)
    loaded = _load_templates(templates_dir, template_ids)

    for url in targets:
        try:
            policy.assert_in_scope(url)
        except OutOfScopeError as exc:
            fatal(str(exc))
            return

    async def _run() -> list[Finding]:
        async with make_client(
            rate_per_sec=policy.rate_per_sec,
            max_redirects=0,
            session=session,
            policy=policy,
        ) as client:
            return await run_templates_against(
                loaded, list(targets), policy, client
            )

    findings = asyncio.run(_run())
    if audit:
        audit.append(
            "scan.templates",
            target=",".join(targets),
            detail={
                "templates": [t.id for t in loaded],
                "findings": len(findings),
            },
        )
    _print_summary(findings)
    for f in findings:
        console.print(
            f"[bold]{f.severity.value.upper()}[/bold] {f.id}  {f.target}"
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _print_summary(
    findings: list[Finding],
    *,
    threshold: Severity | None = None,
    unfiltered_total: int | None = None,
) -> None:
    """Render the rich-table summary.

    When ``threshold`` is set above ``INFO`` and ``unfiltered_total`` is the
    pre-filter count, the table title makes the suppression visible
    (``Findings (rendered 3 of 7) — threshold: high``) so triagers know
    findings.json still contains the unrendered ones.
    """
    if threshold is not None and threshold is not Severity.INFO:
        title = (
            f"Findings (rendered {len(findings)} "
            f"of {unfiltered_total if unfiltered_total is not None else len(findings)})"
            f" — threshold: {threshold.value}"
        )
    else:
        title = f"Findings ({len(findings)})"
    if not findings:
        if threshold is not None and threshold is not Severity.INFO:
            console.print(
                "[green]no findings at or above[/green] "
                f"[bold]{threshold.value}[/bold] "
                f"(filtered {unfiltered_total if unfiltered_total is not None else 0})"
            )
        else:
            console.print("[green]no findings[/green]")
        return
    table = Table(title=title)
    table.add_column("severity")
    table.add_column("category")
    table.add_column("target")
    table.add_column("title")
    for f in findings:
        sev = f.severity.value.upper()
        color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "cyan",
        }.get(sev, "white")
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            f.category,
            normalize_host(f.target) or f.target,
            f.title,
        )
    console.print(table)


def main() -> None:
    cli(prog_name="sentinelweb")


if __name__ == "__main__":  # pragma: no cover
    main()
