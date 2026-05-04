# Usage

## scope

| Command                       | Description                                                |
| ----------------------------- | ---------------------------------------------------------- |
| `sentinelweb scope init`      | Print example `scope.yaml` to stdout                       |
| `sentinelweb scope validate`  | Parse + validate a scope file                              |
| `sentinelweb scope check`     | Check if a host/URL is in scope (exit 2 if out of scope)   |
| `sentinelweb scope audit-verify` | Verify hash-chain integrity of an `audit.jsonl` log    |

## recon

| Command                          | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| `sentinelweb recon subs DOMAIN`  | Subdomain enum via crt.sh (+ optional `--wordlist`)          |
| `sentinelweb recon ports HOST`   | nmap wrapper (host must be in scope)                         |
| `sentinelweb recon tech URL`     | Tech-stack fingerprint from headers + body + cookies         |
| `sentinelweb recon endpoints URL`| Extract URLs / forms / parameters from a single page         |

## scan

```bash
sentinelweb scan \
  --scope scope.yaml \
  --audit audit.jsonl \
  --session session.yaml \
  --scanner all \
  --report-dir reports/run-N \
  --format md --format html --format sarif \
  --severity-threshold medium \
  https://example.test/ https://api.example.test/foo?id=1
```

`--scanner` may be repeated; choices are `headers`, `cors`, `redirect`,
`xss`, `sqli`, `tls`, `takeover`, `templates`, `secrets`, `graphql`,
`csp`, or `all`. The `templates` scanner runs the bundled YAML
detection templates (or a custom directory via `--templates-dir DIR`)
— see [templates](#templates) below. The `secrets` scanner inspects
response bodies and headers for accidentally-exposed credentials — see
[secrets](#secrets-in-responses) below. The `graphql` scanner probes a
GraphQL endpoint for introspection and dev-UI exposure — see
[graphql](#graphql) below. The `csp` scanner analyzes an existing
`Content-Security-Policy` header for known weaknesses — see
[csp](#csp) below.

### Severity threshold

`--severity-threshold {info,low,medium,high,critical}` (default `info`)
filters which findings are rendered into `report.md` / `report.html` /
`report.sarif` and shown on the CLI summary table. **It does not filter
`findings.json`** — that file always contains every observation so
triagers can re-render the report at any threshold via the
[`report`](#report) subcommand without re-scanning. Use `medium` to drop
informational/inventory findings (e.g. Stripe `pk_live_*`, intentionally-
public Google OAuth client ids) from a SARIF artifact uploaded to GitHub
code-scanning.

| threshold | shown in report.md / .html / .sarif / CLI |
| --- | --- |
| `info` (default) | every finding |
| `low` | LOW + MEDIUM + HIGH + CRITICAL |
| `medium` | MEDIUM + HIGH + CRITICAL |
| `high` | HIGH + CRITICAL |
| `critical` | CRITICAL only |

The CLI summary table title makes the suppression visible (e.g.
`Findings (rendered 3 of 7) — threshold: high`) so suppressed findings
aren't lost in plain sight.

## report

Re-render an existing `findings.json` into MD / HTML / SARIF without
re-scanning. Useful for tweaking templates, applying a stricter
`--severity-threshold` (e.g. for a SARIF artifact uploaded to GitHub
code-scanning), or producing a per-format file from an old run.

```bash
sentinelweb report \
  --input reports/run-N/findings.json \
  --report-dir reports/run-N-rerendered \
  --format sarif \
  --severity-threshold high
```

Notes:

- The input file is the canonical record. `report` does **not** write a
  new `findings.json` — output is `report.md` / `report.html` /
  `report.sarif` only.
- The original engagement metadata is carried over from the input file's
  `engagement` block, so the regenerated report is identical to a fresh
  `scan` rendering at the same threshold.
- A malformed input file (truncated JSON, missing `engagement` /
  `findings`, or any finding the model can't parse) yields a clean
  `ValueError` and a non-zero exit code — never a stack trace.

### Authenticated sessions

`--session FILE` loads a YAML/JSON bundle of cookies + headers for the
in-scope target. Credentials are attached **only** to in-scope hosts —
even a wildcard cookie will not be sent to a third-party domain the
target redirects you to.

```yaml
# session.yaml
cookies:
  - name: session
    value: "abc123"
    domain: "example.test"      # or "*" for any in-scope host
    path: "/"
headers:
  Authorization: "Bearer eyJ..."
host_headers:                   # optional per-host overrides
  api.example.test:
    X-Internal-Token: "..."
```

## templates

YAML detection-template engine — lets non-Python operators ship checks
without touching the framework's source.

```bash
# List the bundled built-in templates
sentinelweb templates list

# Run all built-ins against in-scope targets
sentinelweb templates run --scope scope.yaml \
  https://example.test/

# Run a custom directory of templates, restricted to two ids
sentinelweb templates run --scope scope.yaml \
  --templates-dir ./my-templates \
  --template-id exposed-env-file \
  --template-id exposed-git-config \
  https://example.test/
```

The same engine is reachable from `scan` via `--scanner templates`,
sharing the same `--templates-dir` / `--template-id` filters and the
`--session` / `--audit` flags from the rest of the suite.

### Template syntax (subset of nuclei DSL)

```yaml
id: exposed-env-file
info:
  name: "Exposed .env file"
  severity: high          # info | low | medium | high | critical
  description: "..."
  remediation: "..."
  references:
    - https://owasp.org/www-project-web-security-testing-guide/
  cwe: 200                # bare number or "CWE-200"
  category: information-disclosure
  tags: [exposure, dotfile]

requests:
  - method: GET           # GET | HEAD | POST | OPTIONS (no destructive verbs)
    path:
      - "/.env"
      - "/.env.production"
    headers:              # optional, merged on top of session headers
      X-Audit: sentinelweb
    matchers-condition: and    # default: or
    matchers:
      - type: status
        status: [200]
      - type: regex
        part: body              # body | header | response
        regex:
          - "^[A-Z][A-Z0-9_]+=.+"   # MULTILINE; ^/$ are line anchors
      - type: word
        words: ["DEBUG", "Werkzeug"]
        condition: or            # default: or
        case-insensitive: true   # default: false
        negative: false          # default: false (set true to fire on absence)
```

Safety properties of the engine:

- Every HTTP request goes through SentinelWeb's scope-enforcing client;
  templates cannot bypass `scope.yaml`.
- Paths must be relative (`/foo`); absolute URLs and protocol-relative
  paths (`//host/...`) are rejected at load time.
- Methods are restricted to `GET / HEAD / POST / OPTIONS`; `PUT /
  DELETE / PATCH` are rejected so templates can't trigger destructive
  side effects.
- Finding ids are always namespaced as `TEMPLATE-<UPPER-ID>`, so they
  can never collide with built-in scanner ids (`HDR-*`, `CORS-*`, etc.).

See [`examples/templates/`](../examples/templates/) for hand-authored
templates and [`src/sentinelweb/templates/builtin/`](../src/sentinelweb/templates/builtin/)
for the bundled set.

## Headless XSS verification

The XSS scanner is signal-only — it injects a benign canary and flags
parameters where the canary is reflected unencoded into HTML context.
Most candidates are real XSS, but some sit in contexts that look
dangerous yet aren't actually executable (e.g. inside an attribute the
browser auto-escapes). To get a *certain* signal, opt in to headless
verification:

```bash
# Install the optional extra and the system browser
pip install -e '.[headless]'
sudo dnf install firefox geckodriver       # Fedora
# sudo apt install firefox-esr firefox-geckodriver  # Debian/Ubuntu

# Run a normal scan with verification on
sentinelweb scan --scope scope.yaml --scanner xss \
  --verify-xss \
  https://example.test/search
```

For every `XSS-REFLECTED-*` finding, SentinelWeb opens the
parameter-mutated URL in headless Firefox with a benign payload that
sets `document.title` to a per-finding nonce. If the title actually
changes, the finding is **promoted** to a new `XSS-VERIFIED-<PARAM>`
finding with severity `CRITICAL` and confidence `CERTAIN`. The original
candidate is preserved alongside the verified one so triagers see both
signals.

Safety properties of the verification step:

- **No exfiltration.** The payload only writes to `document.title`. No
  `fetch`, `XMLHttpRequest`, `WebSocket`, `localStorage`,
  `sessionStorage`, cookie reads, or form submissions are issued.
- **No persistence.** A fresh browser process is created and torn down
  per scan; nothing is written to disk.
- **Scope-checked twice.** Verification URLs go through `ScopePolicy`
  before navigation, even though the scanner already filtered them.
- **Optional.** Without `--verify-xss` the framework never starts a
  browser, and without the `[headless]` extra (Selenium) the flag
  emits a clear skip message and continues.

If `firefox` or `geckodriver` aren't found on `PATH`, the scan still
runs to completion — verification is skipped with a yellow warning.

## secrets-in-responses

Inspects HTTP response bodies and headers for accidentally-exposed
credentials. Emits findings with **redacted** evidence — the full secret
is never written to the audit log, ``findings.json``, or any rendered
report.

```bash
sentinelweb scan \
  --scope scope.yaml \
  --scanner secrets \
  https://example.test/static/app.js https://example.test/api/config
```

Findings use the id namespace `SECRETS-<PATTERN>` (e.g.
`SECRETS-AWS-ACCESS-KEY-ID`, `SECRETS-GITHUB-PAT-CLASSIC`,
`SECRETS-STRIPE-SECRET-LIVE`, `SECRETS-PRIVATE-KEY-PEM`).

### Pattern catalog (curated for high precision)

The catalog is deliberately **provider-prefixed and length-bounded** —
no generic `api_key="..."` heuristics that train people to ignore the
scanner. Current providers covered:

| Family | Examples |
| --- | --- |
| AWS | `AKIA*`, `ASIA*`, `AGPA*`, `AROA*`, `AIDA*`, `ANPA*`, `ANVA*`, `AIPA*` |
| GitHub | classic PAT (`ghp_*`), fine-grained (`github_pat_*`), OAuth (`gho_*`), App (`ghs_*`), user-to-server (`ghu_*`), refresh (`ghr_*`) |
| Slack | tokens (`xox[baprs]-*`), incoming webhooks (`https://hooks.slack.com/services/...`) |
| Stripe | live secret (`sk_live_*`), live restricted (`rk_live_*`), test (`sk_test_*`), publishable (`pk_live_*`, INFO-only) |
| Google | API key (`AIza*`), OAuth client id (INFO-only) |
| npm / PyPI | `npm_*`, `pypi-AgE*` |
| Twilio / SendGrid / Mailgun | `AC<sid>`, `SG.<id>.<secret>`, `key-*` |
| Square | access (`sq0atp-*`), OAuth secret (`sq0csp-*`) |
| Crypto | PEM private-key headers, JWT-shaped strings |

### Safety properties

- **Scope-checked first.** ``ScopePolicy.assert_in_scope(url)`` runs
  before any HTTP traffic; out-of-scope targets raise.
- **Read-only.** A single `GET` per target. The scanner never sends a
  probe designed to trigger or amplify a leak.
- **Redacted evidence.** Each finding's evidence excerpt is the
  fingerprint `first4***last4` (or `***` for very short matches). The
  full secret never reaches disk.
- **Per-target dedupe + cap.** Each *distinct* secret string produces
  at most one finding, and each pattern emits at most 5 findings per
  target — so a leaked file full of test JWTs cannot drown out the
  real signal.
- **Boring-headers filter.** Standard transport headers
  (`Content-Type`, `Cache-Control`, etc.) are never scanned, to keep
  the JWT pattern from firing on tracing IDs.

### When to triage as INFO

Some matches are *intentionally* public:

- Stripe `pk_live_*` (publishable keys are designed to be embedded)
- Google OAuth client ids (`*.apps.googleusercontent.com`)

These are still surfaced (so you can inventory them), but at severity
`INFO` with remediation marked "no rotation required". Don't open a
bounty report for these.

## csp

Analyzes an existing `Content-Security-Policy` for content-level
weaknesses. Complements the `headers` scanner, which only flags a
*missing* CSP — `csp` looks at what's inside one that's present.

```bash
sentinelweb scan --scope scope.yaml \
  --scanner csp \
  https://app.example.test/
```

Detections (each with concrete remediation in the rendered report):

| Finding ID | Severity | Triggers when… |
| --- | --- | --- |
| `CSP-UNSAFE-INLINE-SCRIPT` | HIGH (CWE-79) | `script-src` includes `'unsafe-inline'` (and not `'strict-dynamic'`) |
| `CSP-UNSAFE-EVAL` | MEDIUM (CWE-79) | `script-src` includes `'unsafe-eval'` |
| `CSP-WILDCARD-SCRIPT-SRC` | HIGH (CWE-79) | `script-src` includes `*` |
| `CSP-DATA-URL-SCRIPT-SRC` | HIGH (CWE-79) | `script-src` includes `data:` |
| `CSP-MISSING-OBJECT-SRC` | MEDIUM (CWE-693) | no `object-src` and no `default-src 'none'` |
| `CSP-MISSING-FRAME-ANCESTORS` | LOW (CWE-1021) | no `frame-ancestors` directive |
| `CSP-MISSING-BASE-URI` | LOW (CWE-693) | no `base-uri` directive |
| `CSP-REPORT-ONLY-MODE` | INFO | only `Content-Security-Policy-Report-Only` is set |

The scanner mirrors browser semantics: `'strict-dynamic'` suppresses
`'unsafe-inline'` / wildcard findings, and `default-src 'none'`
satisfies the object-src guard. `script-src` falls back to
`default-src` when absent.

## graphql

Probes a GraphQL endpoint for two high-value misconfigurations:

```bash
sentinelweb scan --scope scope.yaml \
  --scanner graphql \
  https://api.example.test/graphql
```

* `GRAPHQL-INTROSPECTION-EXPOSED` (HIGH / CERTAIN, CWE-200) — the server
  answers a canonical `{__schema{queryType{name}}}` introspection query.
  Attackers gain the equivalent of internal API documentation.
* `GRAPHQL-GRAPHIQL-EXPOSED` / `GRAPHQL-PLAYGROUND-EXPOSED` /
  `GRAPHQL-APOLLO-SANDBOX-EXPOSED` (MEDIUM / FIRM, CWE-200) — a
  developer UI (GraphiQL, GraphQL Playground, or Apollo Sandbox) is
  served at the URL. These tools ship with introspection wired in and
  should never reach production.

The scanner is **signal-only**: it sends one introspection POST and one
GET for the UI check. It does not exfiltrate the schema, mutate state,
or attempt nested-query DoS. It also does not auto-discover endpoints —
pass the GraphQL URL explicitly so scope-gating stays predictable.

## takeover

Probes one or more in-scope hostnames for dangling-CNAME subdomain
takeovers (signal-only — never claims the resource):

```bash
sentinelweb takeover --scope scope.yaml \
  orphan.example.test legacy.example.test
```

Detection follows the public ``can-i-take-over-xyz`` fingerprints for
GitHub Pages, S3, Heroku, Vercel, Netlify, Azure, Bitbucket, Shopify,
and Tumblr. The same logic is also reachable via
`sentinelweb scan --scanner takeover`.

## jwt

Static analysis of a token (no network):

```bash
sentinelweb jwt --wordlist common-secrets.txt $TOKEN
```

## ssrf

Sends SSRF probes pointing at a callback URL **you** control (use an
out-of-band listener like Burp Collaborator or interactsh). The framework
records that the probe was sent — confirmation comes from your listener.

```bash
sentinelweb ssrf \
  --scope scope.yaml \
  --callback https://abcdef.oast.example/ \
  https://example.test/import?source=https://placeholder
```

## Audit log

Every command that takes `--audit PATH` appends hash-chained JSONL events
to that path. Verify any time with:

```bash
sentinelweb scope audit-verify audit.jsonl
```

A failed verification means the file has been tampered with or truncated.
