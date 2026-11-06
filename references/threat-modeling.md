# Threat Modeling for Security Audits

Read this before writing `.security-audit/threat-model.md` and `.security-audit/architecture.md`.

A generic checklist produces generic findings. The threat model is what turns the audit into an
adversarial exercise: it names *who* can send *what* to *which boundary*, so every hunt
investigation attacks a concrete, reachable surface.

## Step 1 — Inventory entry points

From the recon investigations, list every place untrusted input enters privileged code:

- HTTP/GraphQL/WebSocket handlers; route params, headers, cookies, request bodies
- CLI arguments, environment variables, config files
- Job queues, message consumers, webhooks and callbacks
- File parsers (uploads, imports), archive extraction
- Deserialization points (JSON→object, YAML, pickle, protobuf, template engines)
- Every sink that interpolates input into: SQL/ORM, shell commands, file paths, URLs, HTML,
  regexes, LDAP, XML, ExpressionLanguage templates

Each entry point gets a `file:line` reference and the trust level of its caller. An entry point
without a file reference is a guess — resolve it or drop it.

## Step 2 — Inventory trust boundaries

Classify each crossing:

| Boundary type | Example | Attacker on the outside |
|---|---|---|
| network → application | public HTTP endpoint | anonymous internet user |
| user → user | cross-tenant IDs, shared documents | authenticated low-privilege user |
| application → OS | exec, file paths, sockets | anyone controlling app inputs |
| dependency → application | package install/build scripts | malicious or compromised dependency |
| build → production | CI secrets, artifact injection | anyone with repo/CI write access |
| internal → implicit | "trusted" internal services, ops endpoints | neighbor service / SSRF pivot |

A finding must name the boundary it violates. Code executed at the *same* privilege level as
the attacker is not a boundary violation — this is the single most common false positive.

## Step 3 — Define attacker profiles

For each profile, list capabilities **and non-capabilities**:

- **anonymous-remote** — arbitrary HTTP(S) requests to public endpoints; no credentials; observes public responses.
- **authenticated-low-priv** — valid session for one tenant/user; can use every feature their role grants; can attempt ID manipulation and role confusion.
- **authenticated-neighbor** — an internal service or tenant able to reach internal endpoints (enables SSRF pivots and trust re-use).
- **local-attacker** (when relevant) — shell access to a co-hosted container; malicious dependency during build.
- **malicious-dependency / supply** — controls a package the build or runtime executes.

Record every deployment claim (e.g. "behind a proxy that normalizes paths", "uploads directory is
not shared") in an explicit **Assumptions** section — these are deployment beliefs, not source
evidence, and must be labeled as such everywhere they are used.

## Step 4 — Select attack classes

Map boundaries × sensitive assets onto attack classes (playbooks: `references/attack-classes.md`):

| Signal in the repo | Hunt these classes |
|---|---|
| Input reaches SQL/shell/path/HTML/URL sinks | injection, xss, ssrf |
| Auth/session/permission code | auth-bypass, csrf, crypto |
| Parsers, template engines, object revival | deserialization, protocol-parsing |
| Shared state, queues, multi-step transactions | race-conditions |
| Error surfaces, logs, tokens, debug endpoints | info-exposure |
| Pricing, quotas, workflows, multi-step state machines | business-logic |
| Manifests, IaC, CI config | dependency-config |
| C/C++/Rust or unsafe blocks | memory-corruption |

Add **repo-specific classes** the recon trio surfaced (e.g. `template-injection`,
`graphql-batching-abuse`, `tenant-isolation`). Register them via `audit_state.py coverage-add`
so they are tracked like the standard ones.

## Step 5 — Rank

Rank classes by reachability × impact: public unauthenticated surface handling rich input ranks
above internal admin-only surface. Hunt order follows the ranking.

## Output template — threat-model.md

```markdown
# Threat model — <repo>

## Attack surface
| Entry point | file:line | Caller trust | Input types |
## Trust boundaries
| Crossing | Type | Enforced by (file:line) | Bypass candidates |
## Attacker profiles
<per profile: capabilities / explicitly cannot do>
## Selected attack classes
<ranked list, one-line rationale each; custom classes marked (repo-specific)>
## Assumptions
<deployment claims, each labeled ASSUMPTION — not evidence>
## Explicitly out of scope
<with reasons>
```

`architecture.md` consolidates the three recon reports: component map, data flows, tech stack,
secret handling, and the raw entry-point inventory. Keep the `file:line` references — hunt
investigations will consume them directly.
