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
  https://example.test/ https://api.example.test/foo?id=1
```

`--scanner` may be repeated; choices are `headers`, `cors`, `redirect`,
`xss`, `sqli`, `tls`, `takeover`, `templates`, or `all`. The `templates`
scanner runs the bundled YAML detection templates (or a custom directory
via `--templates-dir DIR`) — see [templates](#templates) below.

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
