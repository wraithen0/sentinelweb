# SentinelWeb

> Defensive web2 security framework for **authorized** bug bounty and whitehat
> testing — recon, OWASP-oriented detection, and bug-bounty-ready reporting,
> all gated on an explicit scope policy.

[![CI](https://github.com/wraithen0/sentinelweb/actions/workflows/ci.yml/badge.svg)](https://github.com/wraithen0/sentinelweb/actions/workflows/ci.yml)

SentinelWeb is **not** an exploit framework. Every module is signal-only and
refuses to run without a `scope.yaml` declaring the engagement, in-scope
hosts, and rate limits. Every run produces a tamper-evident audit log
(`audit.jsonl`) so you can demonstrate to a program owner exactly what was
tested, when, and against which targets.

> ⚠️ **Read [`ETHICS.md`](ETHICS.md) before using.** Unauthorized testing of
> systems you do not own is illegal in most jurisdictions. If you're not on
> a bug-bounty program or under a written ROE, this is not the right tool.

## Features

| Layer       | Modules                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------ |
| **Scope**       | YAML policy, glob+wildcard matching, hash-chained audit log, `scope check` / `audit-verify` |
| **Recon**       | passive subdomain enum (crt.sh + brute), nmap wrapper, tech fingerprint, JS/form/param mining |
| **Scanners**    | security headers, CORS, open-redirect, reflected-XSS canary, error-based SQLi, CVSS-aware JWT analyzer, TLS / cert audit, SSRF callback probes, IDOR cross-context detector |
| **Integrations**| nuclei, ProjectDiscovery httpx, ffuf, sqlmap (detection-only)                                |
| **Reporting**   | Jinja-templated Markdown + HTML, HackerOne and Bugcrowd submission templates, CVSS v3.1 base scoring |

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/wraithen0/sentinelweb
cd sentinelweb
pip install -e ".[dev]"
sentinelweb --help
```

External tools are optional and only required for their respective
integration commands:

| Tool     | Used by                              | Install                                      |
| -------- | ------------------------------------ | -------------------------------------------- |
| `nmap`   | `recon ports`                        | `apt install nmap`                           |
| `nuclei` | `integrations.nuclei`                | https://github.com/projectdiscovery/nuclei   |
| `httpx`  | `integrations.httpx_tool`            | https://github.com/projectdiscovery/httpx    |
| `ffuf`   | `integrations.ffuf`                  | https://github.com/ffuf/ffuf                 |
| `sqlmap` | `integrations.sqlmap` (detect mode)  | `apt install sqlmap`                         |

## Quickstart

1. Generate a scope file and edit it for your engagement:

   ```bash
   sentinelweb scope init > scope.yaml
   $EDITOR scope.yaml
   sentinelweb scope validate scope.yaml
   ```

2. Verify a target is in scope before doing anything else:

   ```bash
   sentinelweb scope check scope.yaml https://api.example.test/users
   ```

3. Run a recon pass:

   ```bash
   sentinelweb recon subs --scope scope.yaml example.test
   sentinelweb recon tech --scope scope.yaml https://example.test/
   sentinelweb recon endpoints --scope scope.yaml https://example.test/login
   ```

4. Run the OWASP-oriented detection suite, with audit log + report:

   ```bash
   sentinelweb scan \
     --scope scope.yaml \
     --audit audit.jsonl \
     --scanner all \
     --report-dir reports/run-1 \
     https://example.test/ https://api.example.test/
   ```

5. Verify the audit log later (e.g. when submitting to a program):

   ```bash
   sentinelweb scope audit-verify audit.jsonl
   ```

6. Analyze a JWT independently (no network):

   ```bash
   sentinelweb jwt eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0.
   ```

## Architecture

```
src/sentinelweb/
  scope/        scope.yaml policy + tamper-evident audit log
  utils/        rate-limited HTTP client, URL helpers, logging
  recon/        passive recon: subdomains, ports, tech, endpoints
  scanners/     OWASP-oriented detection modules (signal only)
  templates/    YAML detection-template engine (subset of nuclei DSL)
  integrations/ wrappers for nuclei, httpx, ffuf, sqlmap
  reporting/    Finding model, CVSS scorer, Jinja templates
  cli/          Click-based CLI orchestrating everything
```

Every scanner takes a `ScopePolicy` and a rate-limited `Client` — they
cannot be invoked without a policy in hand. The `Client` enforces the
per-host rate limit declared in `scope.yaml` and stamps a SentinelWeb
User-Agent on every request so target operators can identify the traffic.

## Reports

`scan` writes a Markdown and HTML report into `--report-dir` (default
`reports/`). Both render every `Finding` with severity, CVSS 3.1 score,
target, evidence, remediation, and references — copy-paste ready for a
bug-bounty submission.

For per-finding submission templates, see
`src/sentinelweb/reporting/templates/hackerone.j2` and `bugcrowd.j2`.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest -ra --cov=sentinelweb
```

PRs welcome. Please keep modules signal-only and ensure new scanners come
with unit tests that mock HTTP via `respx`.

## License

MIT — see [`LICENSE`](LICENSE).
