# Attack-Class Hunting Playbooks

One investigation per class, fresh context. Inputs: the threat-model slice for the class's
boundaries, the file list for its area, this playbook. Output: `investigations/hunt/<class>.md`
with one entry per candidate containing all six required fields (attacker, entry point, trust
boundary, exploit path, impact, quoted-code evidence), and — when the class yields nothing —
coverage notes saying what was checked and why the class does not apply.

Mindset in every class: **break assumptions**, don't review style. For each sink ask: what does
this code assume about its caller, its input, its timing, its environment — and who can violate
that assumption from where?

## injection (SQL, command, path, template, LDAP, XPath)
- Look for: every sink that builds SQL, shell strings, file paths, templates, or query syntax
  from input that any profile controls.
- Check: string interpolation/formatting into queries; raw query APIs; `exec`/`spawn` with
  shell strings; path joins that don't contain traversal; template engines fed user templates;
  ORMs bypassed with `raw()`.
- Evidence: the sink line, the flow from entry point, the exact metacharacter that breaks the
  assumption.
- Common false positive: parameterized queries misread as concatenation; `path.join` prefix
  misread as containment (it isn't — `..` still traverses).

## auth-bypass (authentication & authorization)
- Look for: middleware/route guards; session issuance and verification; permission checks on
  object access; JWT verification (alg confusion, `none`, missing signature check, kid
  injection); password/OTP reset flows; IDOR on object IDs.
- Check: routes registered without the guard; check-after-fetch races; client-supplied roles;
  verification that checks *presence* of a token but not *validity*.
- Evidence: the guarded vs unguarded route table; the exact check that is missing or orderable.
- Common false positive: endpoint reachable only via an internal route the attacker cannot reach
  (verify reachability against the threat model first).

## xss
- Look for: HTML templating with unescaped interpolation, `dangerouslySetInnerHTML`-equivalents,
  URL/attribute injection, SVG/Markdown/CSV rendering, JSON-in-HTML.
- Check: which sinks auto-escape and which don't; attribute context vs body context; DOM sinks
  (`innerHTML`, `location`, `postMessage` handlers); file-download content types.
- Evidence: sink + the context that makes the payload executable.
- Common false positive: escaped output misread as raw; payload that only reflects into a
  response the attacker already controls (self-XSS).

## csrf
- Look for: state-changing endpoints without CSRF tokens or same-site enforcement; cookie-based
  auth with `SameSite=None`; CORS configs trusting `Origin` blindly.
- Check: which state-changing routes require a token; whether token checks can be skipped by
  content-type or method change.
- Common false positive: JSON-only APIs behind same-site cookies with proper `SameSite=Lax/Strict`.

## ssrf
- Look for: server-side fetches of any URL derived from input: webhooks, importers, avatar
  fetchers, link previewers, URL parameters passed to HTTP clients.
- Check: scheme/host/IP allowlists; redirect following (allowlist bypass via redirect);
  DNS rebinding surface; internal address space reachability (metadata 169.254.169.254,
  localhost, private ranges).
- Evidence: the fetch call, what filters exist, which internal targets the threat model says are reachable.
- Common false positive: fetches the attacker can already trigger from their own machine with
  identical effect (no new boundary crossed).

## deserialization
- Look for: YAML loading (`load` vs `safe_load`), pickle/marshal, Java/.NET object streams,
  `ObjectMapper.enableDefaultTyping`, PHP `unserialize`, user-controlled template compilation.
- Check: which format receivers accept; gadget availability in dependencies.
- Common false positive: deserializing attacker-controlled *data* into a non-polymorphic type
  without gadget exposure.

## race-conditions
- Look for: check-then-act on shared state (balance, quota, inventory, vote counting), file
  write-then-rename, token single-use enforcement, TOCTOU on permissions.
- Check: transactions/locks actually covering the whole invariant; async handlers interleaving.
- Evidence: the two code points that interleave and the invariant they violate together.
- Common false positive: races that corrupt data but cross no boundary (impact framing matters).

## memory-corruption
- Look for (only when C/C++/Rust/unsafe code exists): buffer sizing from input, integer overflow
  on length math, unsafe block invariants, FFI boundary validation, parsers reading lengths from
  the wire.
- Evidence: the allocation vs the write; the arithmetic that can overflow.
- Note: skip the class entirely (with coverage notes) if no such code exists.

## protocol-parsing
- Look for: hand-rolled parsers for HTTP headers, multipart, archive formats, JWT/cookie syntax,
  request smuggling surface (duplicate headers, chunked vs content-length), zip-slip on archive
  extraction.
- Check: what the parser does with ambiguity (duplicates, overlong encodings, null bytes);
  disagreement between any two parsers that see the same bytes (frontend proxy vs app).
- Common false positive: ambiguity that terminates the connection instead of creating divergence.

## crypto
- Look for: ECB mode, static IVs, MD5/SHA1 for security purposes, unkeyed hashes as MACs, hard-
  coded keys/secrets, `Math.random`/`rand()` for tokens, missing signature verification,
  constant-time comparison absence on secrets.
- Check: how keys are generated and stored; what an attacker who *sees* a token can forge.
- Evidence: the primitive, the key source, the verification path that consumes it.
- Common false positive: weak hash used only for non-adversarial checksums (impact framing).

## info-exposure
- Look for: stack traces/error bodies reaching clients, debug endpoints, directory listings,
  tokens/logs written to logs or responses, overly permissive CORS, source maps in production
  build config, `.env` committed.
- Check: what each error path returns per threat model; what the build ships.
- Common false positive: verbosity the attacker can only self-serve (no boundary crossed).

## business-logic
- Look for: multi-step flows where steps can be reordered/skipped (cart → payment → fulfillment),
  negative/zero/overflow quantities, currency/decimal handling, quota enforcement points,
  refund/cancellation state machines, referral/coupon abuse.
- Check: server-side enforcement of every step order and every bound the UI enforces.
- Evidence: the state machine and the transition that is not enforced server-side.
- Note: this class needs the threat model's *business* context — say what the asset is worth.

## dependency-config
- Look for: known-vulnerable versions (check a vulnerability DB offline-first; never fetch
  untrusted advisories during the audit), typosquatting risk, post-install scripts, wildcard
  version pins, overly broad container/IAM configs, secrets in IaC.
- Evidence: manifest lines; the advisory mapping; the reachable code path that uses the
  vulnerable API (a vulnerable dependency that is never invoked is `low`/`info` at most).

## Custom classes (repo-specific)
Recon may introduce classes like `template-injection`, `graphql-batching-abuse`,
`tenant-isolation`, `webhook-misuse`. Write the playbook the same way: definition, where to
look, checklist, evidence to capture, common false positive — then register the class in
coverage so it is tracked and reported like the standard ones.
