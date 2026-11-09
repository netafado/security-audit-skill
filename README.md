# security-audit

A reusable, model-agnostic **skill** for deep, adversarial security analysis of software
repositories. Methodology modeled on Cloudflare's Project Glasswing: models are interchangeable
components, vulnerability discovery is separated from independent validation, and only
reproducible evidence promotes a hypothesis to a confirmed finding. The goal is real,
exploitable vulnerabilities — not generic code-review suggestions.

> 📖 **Read the write-up:** [Building a Model-Agnostic Security Audit Skill for AI Coding
> Agents](https://www.isaiasfsantos.com.br/blog/building-a-security-audit-skill) — how the
> methodology works, the design decisions behind it, and what to expect from an audit.

## What an audit produces

In `<repo>/.security-audit/`:

| Artifact | Phase | Purpose |
|---|---|---|
| `architecture.md`, `threat-model.md` | Recon | Entry points, trust boundaries, attacker profiles, repo-specific attack classes |
| `investigations/` | Hunt | One isolated investigation per attack class |
| `pocs/<finding-id>/` | PoC | Exact commands + raw (redacted) output |
| `findings.json` | Report | Schema-validated findings (see `schemas/findings.schema.json`) |
| `security-report.md` | Report | Executive summary through remediation workflow |
| `patches/` | Remediation | Reviewable diffs + regression tests (approval-gated, never auto-merged) |
| `audit.db` | all | SQLite state — the audit is resumable at every phase boundary |

## Install

```bash
git clone https://github.com/netafado/security-audit-skill.git
cp -R security-audit-skill ~/.agents/skills/   # ZCode; ~/.claude/skills/ for Claude Code
```

The skill is a directory; copy it to wherever your runtime discovers skills:

- **ZCode:** `~/.agents/skills/security-audit/` (or per-project `.agents/skills/`)
- **Claude Code:** `~/.claude/skills/security-audit/`
- **OpenAI Codex / ChatGPT:** copy the directory (metadata in `agents/openai.yaml`)
- **Anything else:** point the agent at `SKILL.md` — no runtime-specific behavior is assumed

The deterministic scripts need only Python 3 (stdlib only; no packages to install).

## Use

Trigger phrases: "security audit this repo", "find exploitable vulnerabilities", "pentest this
codebase", "check for auth bypass / injection / SSRF / CSRF", "is this safe to release".

**Before running:** confirm the user is authorized to test the target. The skill reads source
freely, but performs active testing only against isolated instances the user controls, and
never modifies source or production during discovery. Remediation patches are applied in an
isolated worktree only after human approval — nothing is merged, pushed, or deployed
automatically.

## Self-test the deterministic scripts

```bash
# 1. Schema + semantic validation of the example findings (expect exit 0)
python3 scripts/validate_findings.py examples/findings.example.json

# 2. Reference verification against the fixture repo (expect exit 0)
python3 scripts/verify_references.py examples/findings.example.json --repo examples/fixture-repo --audit-dir examples

# 3. State management smoke test (temporary db)
python3 scripts/audit_state.py init --db /tmp/sa-smoke.db --repo examples/fixture-repo
python3 scripts/audit_state.py add-finding --db /tmp/sa-smoke.db --file examples/findings.example.json  # per-finding, or use --file with a single finding
python3 scripts/audit_state.py list --db /tmp/sa-smoke.db
python3 scripts/audit_state.py stats --db /tmp/sa-smoke.db
```

`examples/fixture-repo/` is a fictional 3-file codebase with planted issues, plus
`examples/findings.example.json` and `examples/security-report.example.md` showing exactly what
an audit is expected to produce.

## Script reference

| Script | Deterministic check |
|---|---|
| `scripts/validate_findings.py` | Schema conformance, stable-id format/duplicates, status invariants (`confirmed` ⇒ `poc_ref`), contradiction detection, severity sanity |
| `scripts/verify_references.py` | Referenced files exist, line numbers in range, symbols present, PoC/patch refs resolve |
| `scripts/audit_state.py` | SQLite state: init, findings CRUD with stable-id dedup, coverage tracking, incomplete-investigation detection, resumable stats, findings.json export |
| `scripts/sa_common.py` | Shared helpers (stable-id computation, JSON IO) |

Mechanical checks corroborate findings — **they never prove exploitability**. Confirmation
requires a reproducible PoC plus adversarial validation.

## Degradation

| Environment | Behavior |
|---|---|
| Subagents + second model | Full tier A: parallel recon trio and hunts, independent-model validation |
| Subagents, one model | Tier B: same parallelism; fresh-context validation; single-model limitation noted in report |
| No subagents | Tier C: sequential phases; per-investigation files provide context isolation |
| No execution tools | Static-only: findings stay `unverified` with missing prerequisites documented |

## Extending

The skill ships as the minimal harness (Recon → Hunt → Validate + mechanical checks). Growth
paths: append per-class playbooks to `references/attack-classes.md`, add deterministic scripts
under `scripts/`, extend the db views (coverage by commit, diff-since-last-audit, CI diff-only
mode). Keep `SKILL.md` as the stable entry point.

## Safety summary

Operate only on authorized targets · isolated environments for active testing · no credential
exfiltration · no destructive tests against production · `confirmed` requires reproducible
evidence · source evidence separated from deployment assumptions · human approval before any
patch application.
