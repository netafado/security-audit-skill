# Orchestration — Subagents, Isolation, and Reliability

How to run the audit across capability tiers without weakening the methodology. Roles are
model-agnostic: assign by capability, never by vendor. When two models are available, use the
second for validation (Phase 4) and reverification (Phase 7).

## Context-isolation rules (every tier)

1. One investigation = one context = one output file. Inputs go in; only the structured result
   comes out.
2. Downstream consumers (consolidation, validation, reverification) read the *files*, not the
   conversation histories. In tier C the files ARE the isolation mechanism — after finishing an
   investigation, summarize it and stop reading its full text; during validation never re-read
   hunt narratives at all.
3. The validator gets: findings.json + referenced source files (+ PoC files). Nothing else.
   This is deliberate — hunt narratives anchor the validator toward agreement.
4. Never pass one investigation's unverified guesses into another as facts.

## Investigation prompts

### Recon trio (Phase 1) — three agents in parallel (tier A/B) or sequential (tier C)

```
You are reconnaissance agent <N> for an authorized security audit of <repo>. You will NOT
attempt exploitation. Investigate ONLY your lane:
  <1: application architecture, entry points, data flows | 2: authentication, authorization,
   sessions, secrets, sensitive data, trust boundaries | 3: dependencies, external integrations,
   build/deploy config, attack surface>
Return a structured report with: every entry point as file:line with caller trust level; text
data-flow maps from entry to sink; a trust-boundary inventory; and a ranked list of attack
classes SPECIFIC to this repo (name the repo evidence for each). Write the report to
.security-audit/investigations/recon-<lane>.md.
```

### Hunt (Phase 2) — one agent per attack class, parallel where possible

```
You are hunting EXACTLY ONE attack class: <class>. Authorized audit of <repo>; you do not
execute exploits. Inputs (read nothing else): the threat-model slice below, the file list for
your area, the playbook for your class.
<threat-model slice><file list>
For every candidate finding record all six: attacker + capabilities, entry point (file:line +
function), violated trust boundary, exploit path, impact, quoted source evidence. No candidate
without all six. If the class does not apply, state exactly what you checked and why it does
not apply. Record candidates via audit_state.py add-finding (status hypothesis) and write
.security-audit/investigations/hunt/<class>.md.
```

### Validator (Phase 4) — different model when available; fresh context always

```
You are an adversarial validator for an authorized security audit. Your mandate is to DISPROVE
findings, not confirm them. You receive findings.json and the source files it references —
nothing else. For each finding check: (1) threat model realistic? (2) path reachable as
evidenced in the repo? (3) does the exploit cross a trust boundary, or is it same-privilege?
(4) does the PoC demonstrate the claimed vulnerability? (5) does the issue exist in original
source? (6) duplicate? Return verdict validated / refuted / duplicate with reasons for EVERY
finding. You must NOT add new findings to this queue — note anything new you notice for a
future hunt instead.
```

## Reliability rules

- **Retries:** transient failures (crash, timeout, provider error) retry twice with backoff,
  then mark the investigation `failed` via `audit_state.py investigation-update` and continue.
  Failed investigations are listed in the report's coverage section.
- **Suspiciously incomplete detection:** run `audit_state.py incomplete` before validation.
  Flags: hunts with zero findings and no coverage notes; investigations stuck pending/running;
  (via `verify_references.py`) evidence that doesn't resolve to real files. Any flagged hunt is
  re-run with a fresh context before its class is reported as covered.
- **Fresh model per hunt:** if a hunt re-uses a context that already did another class, findings
  blur across classes — always start fresh.
- **Concurrency:** cap parallel hunts at what the host supports (3–6 is typically safe); recon
  trio runs at its own concurrency; validation runs after ALL hunts complete.

## Resuming an interrupted audit

1. `audit_state.py stats --db .security-audit/audit.db` — findings, investigations, coverage, last event.
2. `audit_state.py incomplete` — find the truncated work.
3. Resume the first non-terminal item: finish its phase, then continue forward. Never re-run a
   completed investigation "for freshness" — its stable ids already exist and re-running creates
   merge noise.
4. If `findings.json` was regenerated more recently than `security-report.md`, regenerate the
   report (Phase 6) from the db before continuing later phases.

## Cross-repository dependency tracing (optional)

When a finding depends on a neighboring repo (shared library, service client), open a separate
scoped investigation for that repo — only with explicit user authorization. It gets its own
entry points and boundaries; findings there merge into the parent audit by stable id when the
same class+file+title pattern applies, otherwise stay scoped with a `tags: ["cross-repo"]` note.
