AI code review is good at finding style problems and missing null checks. It is terrible at answering the question that actually matters: **can an attacker break this?** Ask a model to "review this repo for security issues" and you get a checklist — generic XSS warnings on escaped output, speculative injection claims with no code path, the occasional invented line number. Worse, when you push back, it agrees with you either way.

So I built a skill that approaches the problem differently. **security-audit** is a reusable, model-agnostic skill for AI coding agents that runs deep, adversarial security analysis of a repository. It is modeled on the methodology from Cloudflare's Project Glasswing security research, and it optimizes for one thing: real, exploitable vulnerabilities backed by reproducible evidence — not code-review noise.

This post walks through how it works, the design decisions that make it reliable, and how to install it.

## The three failure modes of AI security review

Before building it, I catalogued how plain "review this for vulnerabilities" prompts fail:

1. **Speculation without evidence.** The model reports plausible vulnerabilities it cannot trace to an actual code path. "This might be vulnerable to SSRF" with no entry point, no attacker, no boundary crossed.
2. **Fabricated confirmation.** The inverse failure: the model "verifies" a finding by re-reading its own reasoning. Ask it to confirm, and it confirms — complete with hallucinated file references and line numbers that do not exist.
3. **Context contamination.** One long conversation that does reconnaissance, hunting, exploitation, and validation in sequence. By the time validation runs, the model has invested in its own narrative and rubber-stamps it.

Every design decision in the skill attacks one of these.

## The Glasswing methodology

Cloudflare's Project Glasswing research describes a pipeline for AI-driven vulnerability discovery with principles that map cleanly onto agent skills:

- **Models are interchangeable components.** Roles are defined by capability — discoverer, validator — never by vendor. The skill runs its discovery and validation on different models when available, and degrades to fresh contexts of the same model when not.
- **Discovery is separated from validation.** The context that hunts a vulnerability never validates it. Validation exists to *disprove*.
- **Evidence over plausibility.** A finding without source evidence or a proof of concept is a hypothesis, not a vulnerability. Nothing gets marked confirmed without reproducible execution evidence.

## The eight phases

An audit moves through eight phases, with all artifacts persisted under `.security-audit/` in the target repo:

| Phase | What happens |
|---|---|
| 1. Reconnaissance | Three independent investigations: application architecture & entry points; auth/authz/secrets/trust boundaries; dependencies & configuration |
| 2. Vulnerability hunting | One fresh investigation per attack class — injection, auth bypass, XSS, CSRF, SSRF, deserialization, race conditions, memory corruption, protocol parsing, crypto, info exposure, business logic, dependency/config — plus repo-specific classes recon introduces |
| 3. Proof of concept | Minimal repro against the original, unmodified code, executed only in isolated environments; raw output captured, secrets redacted |
| 4. Adversarial validation | An independent model (or fresh context) tries to **disprove** every finding |
| 5. Mechanical verification | Deterministic scripts check schema conformance, file/line/symbol references, status invariants |
| 6. Reporting | `security-report.md` for humans, `findings.json` for machines |
| 7. Reverification | Fresh context re-checks every surviving finding against the evidence |
| 8. Remediation | Minimal patches + regression tests in an isolated worktree — never merged without human approval |

### Recon: the threat model is the product

The reconnaissance phase produces a repo-specific threat model: every entry point with a `file:line` reference, the trust boundaries each caller crosses, and named attacker profiles — anonymous remote, authenticated low-privilege, neighbor tenant, malicious dependency. Deployment assumptions get labeled as assumptions, never silently treated as evidence.

This matters because hunting without a threat model produces the classic false positive: code that looks dangerous but sits behind a boundary no attacker in the model can reach.

### Hunting: one class, one fresh context

Each attack-class investigation starts with a clean context and receives only three inputs: the threat-model slice for its boundaries, the file list for its area, and the playbook for its class. It cannot see other hunts' conclusions, so it cannot inherit their biases.

Every candidate finding must state six things — attacker and capabilities, entry point, violated trust boundary, exploit path, impact, and verbatim quoted code:

> **Command injection in thumbnail generation** — `handleUpload` in `src/upload.ts:10` interpolates a public, unauthenticated query parameter into a shell command via `exec()`. Anonymous attacker, network→application boundary, `GET /upload?name=x;id` executes `id` on the server. Critical, production-reachable.

That is what a complete candidate looks like. "There might be an injection issue in the upload handler" is not one.

### Validation: the mandate to disprove

The validator gets `findings.json` and the referenced source files — **never** the hunt narratives, which would anchor it toward agreement. Its instructions are explicitly adversarial: for each finding, check whether the threat model is realistic, whether the path is reachable as evidenced in the repo, whether the exploit actually crosses a trust boundary (the most common false positive is an attacker acting at their own privilege level), whether the PoC demonstrates the claimed bug, and whether it duplicates an earlier finding.

New issues the validator notices go into a note for a *future* hunt — the validator must not inject findings into the queue it is validating.

## The deterministic layer

LLM judgment verifies *meaning*; scripts verify *mechanics*. The skill ships four dependency-free Python scripts:

- **`validate_findings.py`** — validates `findings.json` against a JSON schema and enforces semantic invariants: every `confirmed` finding must carry a PoC reference, critical severity requires an asserted production-reachability claim, contradictory statuses are flagged.
- **`verify_references.py`** — the hallucination catcher. Every file a finding cites must exist in the repo, every cited line must be in range, every named symbol must appear in the cited file, every PoC reference must resolve on disk.
- **`audit_state.py`** — SQLite-backed state that makes audits resumable: findings, investigations, coverage tracking by area and attack class, and detection of suspiciously incomplete investigations (a hunt reporting zero findings with zero coverage notes gets flagged).
- **`sa_common.py`** — shared helpers, including stable-ID computation.

Stable IDs are the dedup mechanism: a finding's identifier is `SA-<attack-class>-<8 hex of sha1(attack class | primary file | normalized title)>`. Two independent investigations that discover the same vulnerability compute the same ID and merge instead of duplicating:

```python
def finding_id(attack_class, primary_file, title):
    payload = f"{slugify(attack_class)}|{primary_file}|{normalized_title(title)}"
    digest = hashlib.sha1(payload.encode()).hexdigest()[:8]
    return f"SA-{slugify(attack_class)}-{digest}"
```

Deterministic verification corroborates findings — it never proves exploitability. That distinction is printed in every report.

## Graceful degradation

The skill adapts to what the host agent can do without weakening its standards:

| Tier | Environment | Behavior |
|---|---|---|
| A | Subagents + two models | Parallel recon and hunts; validation on the second model |
| B | Subagents, one model | Same parallelism; fresh-context validation; the single-model limitation is disclosed in the report |
| C | No subagents | Sequential phases; per-investigation *files* become the context isolation mechanism |
| C-static | No execution tools | Static analysis only; every finding stays `unverified` with missing prerequisites documented |

The markdown files each investigation writes are not just outputs — in tier C they *are* the isolation boundary. Validation reads the findings document, not the narratives.

## Safety constraints

This is a tool that constructs exploits, so the guardrails are non-negotiable and baked into the skill text:

- Operate only on repositories you are authorized to test.
- Active testing only against isolated instances you control — never production.
- No credential exfiltration; PoC output gets redacted.
- `confirmed` requires reproducible evidence; no fabricating successful exploits.
- Remediation patches are applied in an isolated `git worktree` and produce a reviewable diff. The skill never merges, pushes, or deploys anything.

## What I learned building it

Three things surprised me:

**Schema-as-prompt works.** Defining the findings JSON schema with `additionalProperties: false` and required fields did more to raise finding quality than any prose instruction. The validator script then turns every violation into a concrete, fixable error.

**The scripts catch real failures.** In testing, the reference verifier caught a fabricated `src/does_not_exist.py` citation, an out-of-range line number, and a symbol name that appeared nowhere in the cited file — exactly the hallucination class that makes AI security reports untrustworthy.

**Isolation is a file-format problem.** The single highest-leverage design decision was making each investigation write a file and treating those files as the only communication channel between phases. Context contamination essentially disappears when the validator physically cannot read the hunt narrative.

## Install and use

The skill is a plain directory — no runtime lock-in:

```bash
git clone https://github.com/netafado/security-audit-skill.git
cp -r security-audit-skill ~/.agents/skills/   # or ~/.claude/skills/ for Claude Code
```

Scripts need only Python 3 standard library. Then ask your agent: *"security audit this repo"* or *"find exploitable vulnerabilities in the auth flow"*. It ships with a fixture repository, example findings, and a complete example report so you can see the expected output shape before running it on something real.

The repo is at **[github.com/netafado/security-audit-skill](https://github.com/netafado/security-audit-skill)** — MIT licensed, PRs welcome, especially new attack-class playbooks and deterministic checks.
