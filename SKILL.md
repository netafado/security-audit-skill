---
name: security-audit
description: Use when the user asks to audit a codebase for security vulnerabilities or exploitability — "security audit", "pentest this repo", "find exploitable bugs", "check for auth bypass, injection, XSS, SSRF, CSRF", "is this safe to release" — or before releasing code that handles auth, uploads, payments, or untrusted input. Runs an adversarial, evidence-based audit producing security-report.md and findings.json. Not for style-only code review.
---

# Security Audit

Adversarial, evidence-driven vulnerability discovery for software repositories. Methodology
modeled on Cloudflare's Project Glasswing: models are interchangeable components, discovery is
separated from validation, and only reproducible evidence promotes a hypothesis to a confirmed
finding. The goal is real, exploitable vulnerabilities — not generic code-review suggestions.

## Core principles

1. **Discovery ≠ validation.** The context that hunts a vulnerability never validates it.
   Validation is adversarial — its job is to *disprove*.
2. **Evidence over plausibility.** A finding without source evidence or a PoC is a hypothesis.
   Never fabricate exploit results; an unfalsifiable claim stays `unverified`.
3. **Isolated contexts.** Each investigation (recon lane, attack class, validation) runs in a
   fresh context with only the inputs it needs, so findings aren't anchored by earlier narratives.
4. **Deterministic where possible.** File existence, line numbers, schema conformance, and PoC
   execution are checked by scripts, not model judgment. Mechanical checks corroborate; they
   never prove exploitability.
5. **Model-agnostic.** Roles are described by capability, never by vendor. When a second model
   is available for validation, use it; otherwise use a fresh context of the same model and say
   so in the report.
6. **Read-only discovery.** Never modify original source or production systems during
   discovery. Patches are produced in an isolated worktree, only after human approval.

## Safety constraints (non-negotiable)

- Audit only repositories and environments the user is authorized to test. If authorization is
  unclear, ask before any active testing; static analysis can always begin.
- Active exploit testing only against instances you control (local, ephemeral containers,
  dedicated test environments). Never destructive tests against anything production-like.
- Do not exfiltrate credentials, tokens, or PII. Redact secrets in captured PoC output.
- `status: "confirmed"` requires reproducible evidence captured in the audit directory.
- Separate source-code evidence from assumptions about deployment; label every assumption.
- Remediation (Phase 8) never merges, pushes, or deploys. Human approval gates every patch.

## Capability detection — degrade gracefully

Detect capabilities up front and run the highest tier available:

| Tier | Capabilities | How to work |
|---|---|---|
| A | Subagents + a second model | Parallel recon trio and per-class hunts; validator on the different model |
| B | Subagents, one model | Same parallelism; validator = fresh subagent with minimal context; note the single-model limitation in the report |
| C | No subagents | Sequential phases in the main context; per-investigation *files* are the isolation mechanism — write results to disk, summarize, move on; during validation never re-read hunt narratives |
| C-static | No execution tools | Static analysis only; skip PoC execution and patch verification; every finding stays `unverified` with missing prerequisites listed |

A missing capability changes mechanics, not standards: evidence, validation, dedup, and
reporting rules apply in every tier.

## Output layout

All artifacts live in `<repo>/.security-audit/` (add it to `.gitignore` unless the report is
meant to be committed):

```
.security-audit/
├── audit.db                # SQLite state (scripts/audit_state.py)
├── architecture.md         # Phase 1
├── threat-model.md         # Phase 1
├── investigations/
│   ├── recon-app.md | recon-authz.md | recon-supply.md
│   └── hunt/<attack-class>.md
├── pocs/SA-<class>-<id8>/  # poc.md with exact commands + raw (redacted) output
├── findings.json
├── security-report.md
└── patches/                # Phase 8 diffs + regression tests
```

## Workflow

Run phases in order. The audit is resumable at every phase boundary: check state first
(`audit_state.py stats` / `list` / `incomplete`) and only do missing work. At the start of a
fresh audit:

```bash
python3 <skill-dir>/scripts/audit_state.py init --db .security-audit/audit.db --repo .
```

### Phase 1 — Reconnaissance

Goal: architecture, security boundaries, and a repo-specific threat model. Three independent
fresh-context investigations (in parallel subagents when the tier allows), each writing one of:

1. `investigations/recon-app.md` — application architecture, entry points (HTTP handlers, CLI,
   jobs, parsers, webhooks), data flows end to end.
2. `investigations/recon-authz.md` — authentication/authorization mechanisms, sessions, secrets,
   sensitive data, trust boundaries (every place untrusted input crosses into privileged code).
3. `investigations/recon-supply.md` — dependencies, external integrations, build/deploy
   configuration, exposed attack surface.

Each recon investigation returns: entry points with `file:line` refs, text data-flow maps, a
trust-boundary inventory, and a ranked list of attack classes **specific to this repo**. Read
`references/threat-modeling.md` before consolidating into `architecture.md` + `threat-model.md`.
The threat model defines attacker profiles (anonymous remote, authenticated low-privilege,
neighbor tenant, malicious dependency, compromised upstream), their capabilities, and which
boundaries they may cross. Register repo-specific attack classes via `coverage-add` so they are
tracked like the standard ones.

### Phase 2 — Vulnerability hunting

One independent fresh-context investigation per attack class: the standard list below **plus**
every repo-specific class recon introduced. Read `references/attack-classes.md` for per-class
playbooks and `references/orchestration.md` for the investigation prompts and isolation rules.

`injection` · `auth-bypass` · `xss` · `csrf` · `ssrf` · `deserialization` · `race-conditions` ·
`memory-corruption` · `protocol-parsing` · `crypto` · `info-exposure` · `business-logic` ·
`dependency-config`

Each hunt receives only: the relevant slice of `threat-model.md`, the file list for its area
(not the whole repo), and the class playbook. Every candidate must state all six — a missing
field means the hypothesis is not ready:

- **Attacker** and their capabilities
- **Entry point** (`file:line`, function)
- **Violated trust boundary**
- **Exploit path** (concrete steps)
- **Impact**
- **Evidence** (quoted code from the original source, not paraphrase)

Mindset: break assumptions — "this is always called after auth", "the ID is unguessable", "the
parser rejects this", "the framework escapes this". Record candidates with `audit_state.py
add-finding` (`status: hypothesis`) and write `investigations/hunt/<class>.md`. A hunt that ends
with zero findings must record what was checked and why the class does not apply — an empty hunt
with no coverage notes is flagged as suspiciously incomplete (`audit_state.py incomplete`).

### Phase 3 — Proof of concept

For each hypothesis, in severity order:

1. Build a minimal repro (unit-level harness, curl sequence, crafted file, test case) exercising
   **the original, unmodified code**.
2. Execute only in an isolated environment you control. Capture exact commands + raw output into
   `pocs/<id>/`; redact secrets.
3. Set `status`: `confirmed` (reproduced, evidence captured), `unverified` (cannot execute — list
   the missing prerequisites, e.g. no test env, needs a running service, requires credentials),
   or `refuted` (the disproof attempt succeeded).
4. Never fabricate output. Keep PoCs re-runnable — `poc.md` contains exact commands.

### Phase 4 — Adversarial validation

Independent validator: a different model when the tier allows; otherwise a fresh context given
**only** `findings.json` and the referenced source files — never the hunt narratives. The
validator's mandate is disproof. For every finding it checks:

1. Is the threat model realistic — can this attacker actually reach the entry point?
2. Is the code path reachable in the deployed configuration *as evidenced in the repo*?
3. Does the exploit cross a trust boundary, or is it a self-inflicted action at the attacker's
   own privilege level (the most common false positive)?
4. Does the PoC demonstrate the *claimed* vulnerability, not an unrelated bug?
5. Does the issue exist in the original source (not introduced by audit tooling)?
6. Is it a duplicate of an earlier finding?

Verdicts: `validated` / `refuted` / `duplicate` with reasons, written back via `audit_state.py
update <id> --validation ...`. The validator must not introduce its own findings into the
current queue — anything new it notices goes into a note for a *future* hunt.

### Phase 5 — Mechanical verification

Run the deterministic scripts; they verify *form*, not exploitability:

```bash
python3 <skill-dir>/scripts/validate_findings.py .security-audit/findings.json
python3 <skill-dir>/scripts/verify_references.py .security-audit/findings.json --repo <repo>
```

- `validate_findings.py` — schema conformance, stable-id format and duplicates, status
  invariants (e.g. `confirmed` requires `poc_ref`), contradiction detection.
- `verify_references.py` — every referenced file exists, line numbers are in range, named
  symbols appear in the referenced files, PoC/patch refs resolve.

Fix everything they flag, then (tiers A/B) re-execute PoCs where safe and parse/compile-check
proposed patches. The report states plainly that mechanical checks never prove exploitability.

### Phase 6 — Reporting

Write `.security-audit/security-report.md` and regenerate `.security-audit/findings.json` from
the db (`audit_state.py export-findings`). Follow `references/reporting.md` for the exact
structure and the severity/confidence rubric. The report must include: executive summary;
architecture overview; threat model summary; confirmed vulnerabilities with repro steps,
evidence, remediation, and production reachability; unverified findings **with** missing
prerequisites; and coverage limitations (what was *not* audited and why). `findings.json`
conforms to `schemas/findings.schema.json` (enforced by `validate_findings.py`).

### Phase 7 — Independent reverification

Fresh context, full surviving queue. Re-read the *source* and the PoC evidence on disk; do not
re-read hunt narratives. For each finding re-answer: does the evidence support every claim?
Findings that cannot be supported are rejected (`refuted`, with the reason recorded). This is
the final quality gate before remediation.

### Phase 8 — Remediation (confirmed findings only, human approval required)

1. Generate a minimal proposed patch per finding.
2. Create (or reuse) a regression test that reproduces the vulnerability.
3. Verify the test **fails** before the patch.
4. Apply the patch in an isolated working tree (`git worktree add`), never the user's working tree.
5. Verify the test passes after the patch.
6. Run the relevant regression suites.
7. Emit a reviewable diff into `patches/` and set `patch_ref` on the finding.

**Never merge, push, or deploy automatically.** Hand the diff and test results to the user.

## State, resumability, reliability

- **SQLite state** (`.security-audit/audit.db`) is the source of truth; markdown/JSON are
  derived views. After any interruption: `audit_state.py stats` shows where you are; resume the
  first non-terminal item.
- **Stable-id dedup:** `SA-<class>-<8hex>` computed from `sha1(attack_class|primary file|
  normalized title)` — the same vulnerability re-discovered by another investigation computes to
  the same id and merges instead of duplicating. `audit_state.py dedupe` re-merges.
- **Coverage tracking:** one row per (area, attack class) with status `uncovered / investigated /
  no-issues / findings`. The report's coverage section comes from here. Never mark a class
  "not applicable" without a recorded reason.
- **Retries:** transient failures (agent crash, timeout) retry twice, then the investigation is
  marked `failed` and the audit continues; the report lists failed investigations.
- **Incomplete-investigation detection:** `audit_state.py incomplete` flags hunts reporting zero
  findings with no coverage notes, stuck pending/running investigations, and — via
  `verify_references.py` — evidence quotes that don't resolve to real files.
- **Parallel agents:** hunt investigations are independent — run concurrently when the tier
  allows. Validation starts only after hunts complete. Cap concurrency to what the host permits.
- **Cross-repo tracing (optional):** when a vulnerability depends on a neighboring repo (shared
  library, service client), trace it in a separately scoped investigation, only if the user
  authorizes that repo.

## Evolution notes

This is the minimal harness (Recon → Hunt → Validate + mechanical checks), designed to grow:
append per-class playbooks to `references/attack-classes.md`, add deterministic scripts under
`scripts/`, extend the db views (coverage by commit, diff-since-last-audit, CI diff-only mode).
Extend via references/scripts; keep this file the stable entry point.

## Quick reference

| Need | Do |
|---|---|
| Start / resume | `audit_state.py init` / `stats` / `incomplete` |
| Record a candidate | `audit_state.py add-finding --file f.json` |
| Validator verdict | `audit_state.py update <id> --validation validated` |
| Validate findings JSON | `validate_findings.py findings.json` |
| Verify file/line/symbol refs | `verify_references.py findings.json --repo .` |
| Threat-model method | read `references/threat-modeling.md` |
| Per-class hunting playbooks | read `references/attack-classes.md` |
| Report format + severity rubric | read `references/reporting.md` |
| Subagent prompts, tiers, retries | read `references/orchestration.md` |
