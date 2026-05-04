"""GraphQL information-disclosure detection.

Probes a GraphQL endpoint for two high-signal misconfigurations that
together drive a large fraction of real-world bug-bounty payouts:

* **Introspection enabled** in production — the server happily answers
  ``{__schema{queryType{name}}}``. Attackers can dump the entire type
  graph, which is the equivalent of leaked internal API documentation
  and dramatically reduces the cost of IDOR / authorization probing.
* **Developer UI exposed** in production — GraphiQL, GraphQL Playground,
  or Apollo Sandbox served at the same path. These tools ship with
  introspection wired into the UI and lower the bar for an attacker to
  iterate queries without writing any code.

The scanner is **signal-only**: it sends a single canonical introspection
``POST`` and a single ``GET`` for the UI check. It does not exfiltrate
the schema, mutate state, or attempt nested-query DoS — those probes
belong in a confirmed-exploit phase, not a detection phase.

It deliberately does not auto-discover endpoints (e.g. by guessing
``/graphql``, ``/api/graphql``, …). The caller passes the endpoint URL
explicitly, which keeps scope-gating predictable and avoids fanning out
HTTP traffic the operator did not authorize.
"""

from __future__ import annotations

from typing import Any

from ..reporting.findings import Confidence, Evidence, Finding, Severity
from ..scope.policy import ScopePolicy
from ..utils.http import Client

INTROSPECTION_QUERY = "{__schema{queryType{name}}}"

# (finding_id, marker_substring, human-readable UI name)
#
# Markers are matched **case-sensitively** against the response body.
# They use the canonical brand spellings each tool ships in its
# ``<title>`` element / landing page, which keeps false-positives low —
# unrelated marketing copy almost never includes "GraphiQL" or
# "GraphQL Playground" verbatim, and Apollo Sandbox's marker is paired
# with an additional ``graphql`` substring guard below.
_UI_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("GRAPHQL-GRAPHIQL-EXPOSED", "GraphiQL", "GraphiQL"),
    ("GRAPHQL-PLAYGROUND-EXPOSED", "GraphQL Playground", "GraphQL Playground"),
    ("GRAPHQL-APOLLO-SANDBOX-EXPOSED", "Apollo Sandbox", "Apollo Sandbox"),
)

_MAX_BODY_BYTES = 200_000


async def scan(url: str, scope: ScopePolicy, client: Client) -> list[Finding]:
    scope.assert_in_scope(url)
    findings: list[Finding] = []
    findings.extend(await _check_introspection(url, client))
    findings.extend(await _check_developer_ui(url, client))
    return findings


async def _check_introspection(url: str, client: Client) -> list[Finding]:
    try:
        resp = await client.request(
            "POST",
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
    except Exception:
        return []
    if not 200 <= resp.status_code < 300:
        return []
    try:
        payload: Any = resp.json()
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return []
    query_type = schema.get("queryType")
    if not isinstance(query_type, dict):
        return []
    type_name = query_type.get("name")
    if not isinstance(type_name, str) or not type_name:
        return []
    return [
        Finding(
            id="GRAPHQL-INTROSPECTION-EXPOSED",
            title="GraphQL introspection is exposed",
            severity=Severity.HIGH,
            confidence=Confidence.CERTAIN,
            target=url,
            category="graphql",
            cwe="200",
            description=(
                "The GraphQL endpoint responds to ``__schema`` introspection "
                "queries. Attackers can enumerate every type, query, "
                "mutation, and argument the API supports, which is "
                "equivalent to leaking internal API documentation and "
                "drastically reduces the cost of IDOR / authorization "
                "probing against the underlying resolvers."
            ),
            remediation=(
                "Disable introspection in production. Apollo Server: set "
                "``introspection: false``; graphql-yoga: ``disableIntrospection``; "
                "Hot Chocolate / .NET: ``DisableIntrospection``; Hasura: "
                "set the ``HASURA_GRAPHQL_ENABLE_TELEMETRY``-adjacent admin-only "
                "introspection role. If internal tooling truly needs it, "
                "allowlist a small set of trusted clients (mTLS or "
                "scoped service tokens) rather than leaving it open."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#introspection--graphiql",
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            detected_by="scanners.graphql",
            evidence=[
                Evidence(
                    description=(
                        "Canonical introspection query returned a queryType "
                        f"named '{type_name}'."
                    ),
                    request=(
                        f"POST {url}\n"
                        "Content-Type: application/json\n\n"
                        f'{{"query":"{INTROSPECTION_QUERY}"}}'
                    ),
                    response_excerpt=(
                        f"HTTP/{resp.http_version} {resp.status_code}\n"
                        f'data.__schema.queryType.name = "{type_name}"'
                    ),
                )
            ],
        )
    ]


async def _check_developer_ui(url: str, client: Client) -> list[Finding]:
    try:
        resp = await client.get(url, headers={"Accept": "text/html"})
    except Exception:
        return []
    if not 200 <= resp.status_code < 300:
        return []
    body = (resp.text or "")[:_MAX_BODY_BYTES]
    if not body:
        return []
    findings: list[Finding] = []
    for finding_id, marker, ui_name in _UI_MARKERS:
        if marker not in body:
            continue
        if marker == "Apollo Sandbox" and "graphql" not in body.lower():
            # Brand string can appear in unrelated marketing material;
            # require a graphql-related signal in the body to keep FPs
            # low. The other markers are specific enough on their own.
            continue
        findings.append(
            Finding(
                id=finding_id,
                title=f"{ui_name} developer UI exposed in production",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                target=url,
                category="graphql",
                cwe="200",
                description=(
                    f"The {ui_name} developer UI is reachable at this URL. "
                    "These tools ship with introspection wired into the UI "
                    "and dramatically lower the bar for an attacker to "
                    "iterate queries against the underlying GraphQL API. "
                    "They are intended for local development only."
                ),
                remediation=(
                    f"Do not serve {ui_name} in production. Disable it via "
                    "your GraphQL server configuration (e.g. Apollo Server "
                    "``ApolloServerPluginLandingPageDisabled``), or gate "
                    "the path behind authentication that is restricted to "
                    "engineers."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#introspection--graphiql",
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
                detected_by="scanners.graphql",
                evidence=[
                    Evidence(
                        description=(
                            f"Response body contains the '{marker}' "
                            "marker associated with the developer UI."
                        ),
                        request=f"GET {url}",
                        response_excerpt=(
                            f"HTTP/{resp.http_version} {resp.status_code}\n"
                            f"<...>{marker}<...>"
                        ),
                    )
                ],
            )
        )
    return findings
