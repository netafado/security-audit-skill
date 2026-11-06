#!/usr/bin/env python3
"""SQLite-backed persistent state for a security-audit run.

State lives in <repo>/.security-audit/audit.db and is the source of truth for
resuming interrupted audits, deduplicating findings via stable ids, tracking
coverage by area and attack class, and detecting suspiciously incomplete
investigations. All artifacts (architecture.md, findings.json, ...) are
derived views; the db survives context switches.

Subcommands:
  init              --db PATH --repo R [--audit-id ID]
  log               --db PATH --phase PHASE --message MSG
  investigation-add --db PATH --id hunt/ssrf --kind hunt [--attack-class C] [--status S] [--notes N]
  investigation-update --db PATH --id ID [--status S] [--claimed-findings N] [--notes N]
  add-finding       --db PATH (--file F | --stdin)   stable id computed if missing
  update            --db PATH ID [--status S] [--validation V] [--validator NAME]
                    [--severity S] [--confidence C] [--poc-ref R] [--patch-ref R]
                    [--production-reachable {true,false}]
  list              --db PATH [--status S] [--validation V] [--format table|json]
  show              --db PATH ID
  dedupe            --db PATH    recompute stable ids, merge or rename duplicates
  coverage-add      --db PATH --area A --attack-class C --status S [--notes N]
  coverage          --db PATH
  stats             --db PATH
  incomplete        --db PATH    suspiciously incomplete investigations
  export-findings   --db PATH --out F [--repo R] [--include-refuted]

Exit codes: 0 = ok, 1 = nothing found / merge conflict, 2 = usage/IO problem.
"""
import argparse
import datetime
import json
import os
import sqlite3
import sys
import uuid

try:
    from sa_common import finding_id, primary_file, slugify
except ImportError:
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from sa_common import finding_id, primary_file, slugify

JSON_FIELDS = ("files", "functions", "evidence", "reproduction", "validation", "tags")
STATUS = ("hypothesis", "confirmed", "refuted", "unverified")
VALIDATION = ("pending", "validated", "refuted", "duplicate")
SEVERITY = ("critical", "high", "medium", "low", "info")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def connect(db):
    directory = os.path.dirname(os.path.abspath(db))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS audits(
      id TEXT PRIMARY KEY, repo TEXT, started_at TEXT, status TEXT DEFAULT 'active', note TEXT);
    CREATE TABLE IF NOT EXISTS investigations(
      id TEXT PRIMARY KEY, audit_id TEXT, kind TEXT, attack_class TEXT,
      status TEXT DEFAULT 'pending', claimed_findings INTEGER DEFAULT 0,
      notes TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS findings(
      id TEXT PRIMARY KEY, audit_id TEXT, attack_class TEXT, title TEXT, description TEXT,
      files TEXT, functions TEXT, attacker_capabilities TEXT, trust_boundary TEXT,
      exploit_path TEXT, impact TEXT, evidence TEXT, severity TEXT, confidence TEXT,
      status TEXT, reproduction TEXT, poc_ref TEXT, validation TEXT, patch_ref TEXT,
      production_reachable INTEGER, tags TEXT, first_seen TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS coverage(
      audit_id TEXT, area TEXT, attack_class TEXT, status TEXT, notes TEXT, updated_at TEXT,
      PRIMARY KEY(audit_id, area, attack_class));
    CREATE TABLE IF NOT EXISTS events(
      seq INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT, ts TEXT, phase TEXT, message TEXT);
    """)
    return conn


def active_audit_id(conn):
    row = conn.execute("SELECT id FROM audits WHERE status='active' ORDER BY started_at DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def serialize(finding):
    """Return a dict keyed by findings-table columns (id included)."""
    out = {}
    for key, val in finding.items():
        if key in JSON_FIELDS:
            out[key] = json.dumps(val, ensure_ascii=False)
        elif key == "production_reachable":
            out[key] = None if val is None else (1 if val else 0)
        else:
            out[key] = val
    return out


def deserialize(row):
    out = dict(row)
    for key in JSON_FIELDS:
        raw = out.get(key)
        out[key] = json.loads(raw) if raw else ([] if key != "validation" else {"status": "pending"})
    pr = out.get("production_reachable")
    out["production_reachable"] = None if pr is None else bool(pr)
    return out


COLUMNS = ("id", "audit_id", "attack_class", "title", "description", "files", "functions",
           "attacker_capabilities", "trust_boundary", "exploit_path", "impact", "evidence",
           "severity", "confidence", "status", "reproduction", "poc_ref", "validation",
           "patch_ref", "production_reachable", "tags", "first_seen", "updated_at")


def upsert_finding(conn, audit_id, finding):
    """Insert a finding or merge into the row its stable id already maps to."""
    if not finding.get("id"):
        cls = slugify(finding.get("attack_class", ""))
        pf = primary_file(finding)
        finding["id"] = finding_id(finding.get("attack_class", cls), pf, finding.get("title", ""))
    fid = finding["id"]
    existing = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    ts = now()
    if existing is None:
        finding = dict(finding)
        finding.setdefault("audit_id", audit_id)
        finding.setdefault("first_seen", ts)
        finding.setdefault("updated_at", ts)
        finding.setdefault("validation", {"status": "pending"})
        cols = serialize(finding)
        names = [c for c in COLUMNS if c in cols]
        conn.execute(
            f"INSERT INTO findings ({', '.join(names)}) VALUES ({', '.join('?' for _ in names)})",
            [cols[c] for c in names])
        return fid, "created"
    # merge: existing values win unless empty; richer text wins
    merged = deserialize(existing)
    for key, val in finding.items():
        if key == "id" or val in (None, "", [], {}):
            continue
        if key in ("description", "exploit_path", "impact"):
            if len(str(val)) > len(str(merged.get(key) or "")):
                merged[key] = val
        elif not merged.get(key):
            merged[key] = val
        elif key == "validation" and merged.get("validation", {}).get("status") == "pending":
            merged[key] = val
    merged["updated_at"] = ts
    cols = serialize(merged)
    sets = ", ".join(f"{c}=?" for c in cols if c != "id")
    conn.execute(f"UPDATE findings SET {sets} WHERE id=?", [cols[c] for c in cols if c != "id"] + [fid])
    return fid, "merged"


def cmd_init(a):
    conn = connect(a.db)
    audit_id = a.audit_id or f"audit-{datetime.date.today().isoformat()}-{uuid.uuid4().hex[:6]}"
    conn.execute("INSERT INTO audits (id, repo, started_at) VALUES (?,?,?)", (audit_id, a.repo, now()))
    conn.commit()
    print(f"initialized audit {audit_id} (repo: {a.repo}, db: {a.db})")
    return 0


def cmd_log(a):
    conn = connect(a.db)
    conn.execute("INSERT INTO events (audit_id, ts, phase, message) VALUES (?,?,?,?)",
                 (active_audit_id(conn), now(), a.phase, a.message))
    conn.commit()
    return 0


def cmd_investigation_add(a):
    conn = connect(a.db)
    claimed = 0 if a.claimed_findings is None else a.claimed_findings
    conn.execute(
        "INSERT INTO investigations (id, audit_id, kind, attack_class, status, claimed_findings, notes, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
        (a.id, active_audit_id(conn), a.kind, a.attack_class, a.status, claimed, a.notes, now()))
    conn.commit()
    print(f"investigation {a.id} ({a.kind}) -> {a.status}")
    return 0


def cmd_investigation_update(a):
    conn = connect(a.db)
    sets, vals = ["updated_at=?"], [now()]
    if a.status:
        sets.append("status=?"); vals.append(a.status)
    if a.claimed_findings is not None:
        sets.append("claimed_findings=?"); vals.append(a.claimed_findings)
    if a.notes is not None:
        sets.append("notes=?"); vals.append(a.notes)
    vals.append(a.id)
    cur = conn.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()
    if cur.rowcount == 0:
        print(f"ERROR: no investigation {a.id!r}", file=sys.stderr)
        return 1
    print(f"investigation {a.id} updated")
    return 0


def cmd_add_finding(a):
    if a.stdin:
        finding = json.load(sys.stdin)
    elif a.file:
        finding = json.load(open(a.file, encoding="utf-8"))
    else:
        print("ERROR: provide --file F or --stdin", file=sys.stderr)
        return 2
    conn = connect(a.db)
    fid, action = upsert_finding(conn, active_audit_id(conn), finding)
    conn.commit()
    print(f"{action}: {fid}")
    return 0


def cmd_update(a):
    conn = connect(a.db)
    row = conn.execute("SELECT * FROM findings WHERE id=?", (a.id,)).fetchone()
    if row is None:
        print(f"ERROR: no finding {a.id!r}", file=sys.stderr)
        return 1
    merged = deserialize(row)
    ts = now()
    for field in ("status", "severity", "confidence", "poc_ref", "patch_ref"):
        val = getattr(a, field.replace("-", "_"))
        if val is not None:
            merged[field] = val
    if a.production_reachable is not None:
        merged["production_reachable"] = a.production_reachable == "true"
    if a.validation or a.validator:
        v = dict(merged.get("validation") or {})
        if a.validation:
            v["status"] = a.validation
        if a.validator:
            v["validator"] = a.validator
        v.setdefault("checked_at", ts)
        merged["validation"] = v
    merged["updated_at"] = ts
    cols = serialize(merged)
    sets = ", ".join(f"{c}=?" for c in cols if c != "id")
    conn.execute(f"UPDATE findings SET {sets} WHERE id=?", [cols[c] for c in cols if c != "id"] + [a.id])
    conn.commit()
    print(f"updated {a.id}")
    return 0


def cmd_list(a):
    conn = connect(a.db)
    query, vals = "SELECT * FROM findings", []
    conds = []
    if a.status:
        conds.append("status=?"); vals.append(a.status)
    if a.validation:
        conds.append("json_extract(validation, '$.status')=?"); vals.append(a.validation)
    if conds:
        query += " WHERE " + " AND ".join(conds)
    rows = [deserialize(r) for r in conn.execute(query, vals)]
    if a.format == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    print(f"{'id':<28} {'class':<18} {'sev':<8} {'status':<12} {'valid.':<10} title")
    for r in rows:
        title = (r.get("title") or "")[:60]
        print(f"{(r.get('id') or '?'):<28} {(r.get('attack_class') or ''):<18} {(r.get('severity') or '-'):<8}"
              f" {(r.get('status') or '-'):<12} {((r.get('validation') or {}).get('status') or '-'):<10} {title}")
    return 0


def cmd_show(a):
    conn = connect(a.db)
    row = conn.execute("SELECT * FROM findings WHERE id=?", (a.id,)).fetchone()
    if row is None:
        print(f"ERROR: no finding {a.id!r}", file=sys.stderr)
        return 1
    print(json.dumps(deserialize(row), indent=2, ensure_ascii=False))
    return 0


def cmd_dedupe(a):
    conn = connect(a.db)
    rows = conn.execute("SELECT * FROM findings").fetchall()
    actions = 0
    for row in rows:
        f = deserialize(row)
        expected = finding_id(f.get("attack_class", ""), primary_file(f), f.get("title", ""))
        if expected == f["id"]:
            continue
        clash = conn.execute("SELECT id FROM findings WHERE id=?", (expected,)).fetchone()
        if clash:
            f["id"] = expected
            upsert_finding(conn, f.get("audit_id"), f)
            conn.execute("DELETE FROM findings WHERE id=?", (row["id"],))
            print(f"merged {row['id']} -> {expected}")
        else:
            conn.execute("UPDATE findings SET id=? WHERE id=?", (expected, row["id"]))
            print(f"renamed {row['id']} -> {expected}")
        actions += 1
    conn.commit()
    print(f"dedupe complete: {actions} change(s)")
    return 0


def cmd_coverage_add(a):
    conn = connect(a.db)
    conn.execute(
        "INSERT INTO coverage (audit_id, area, attack_class, status, notes, updated_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(audit_id, area, attack_class)"
        " DO UPDATE SET status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at",
        (active_audit_id(conn), a.area, slugify(a.attack_class), a.status, a.notes, now()))
    conn.commit()
    print(f"coverage {a.area} x {slugify(a.attack_class)} -> {a.status}")
    return 0


def cmd_coverage(a):
    conn = connect(a.db)
    rows = conn.execute("SELECT area, attack_class, status, notes FROM coverage ORDER BY area, attack_class").fetchall()
    print(f"{'area':<24} {'attack_class':<20} {'status':<14} notes")
    for r in rows:
        print(f"{r['area']:<24} {r['attack_class']:<20} {r['status']:<14} {(r['notes'] or '')[:50]}")
    return 0


def cmd_stats(a):
    conn = connect(a.db)
    for row in conn.execute("SELECT status, COUNT(*) c FROM findings GROUP BY status"):
        print(f"  {row['status']}: {row['c']}")
    for row in conn.execute("SELECT json_extract(validation,'$.status') v, COUNT(*) c FROM findings GROUP BY v"):
        print(f"  validation={row['v']}: {row['c']}")
    for row in conn.execute("SELECT status, COUNT(*) c FROM investigations GROUP BY status"):
        print(f"  investigation {row['status']}: {row['c']}")
    for row in conn.execute("SELECT status, COUNT(*) c FROM coverage GROUP BY status"):
        print(f"  coverage {row['status']}: {row['c']}")
    last = conn.execute("SELECT ts, phase, message FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    print(f"  last event: {last['ts']} [{last['phase']}] {last['message']}" if last else "  no events logged")
    return 0


def cmd_incomplete(a):
    """Flag suspiciously incomplete investigations — a corruption signal.

    Hunts that ended with zero findings but recorded no coverage notes, and
    investigations stuck in pending/running, are exactly the shape of a
    truncated or lazily-executed investigation.
    """
    conn = connect(a.db)
    flagged = 0
    for r in conn.execute(
            "SELECT id, kind, status, updated_at FROM investigations"
            " WHERE status IN ('pending','running') ORDER BY updated_at"):
        print(f"non-terminal: {r['id']} ({r['kind']}, {r['status']}, updated {r['updated_at']})")
        flagged += 1
    for r in conn.execute(
            "SELECT id, attack_class, claimed_findings, updated_at FROM investigations"
            " WHERE kind='hunt' AND status='complete' AND claimed_findings=0"
            "   AND (notes IS NULL OR notes='')"):
        print(f"suspicious: {r['id']} reports zero findings with no coverage notes ({r['updated_at']})")
        flagged += 1
    print(f"{flagged} item(s) flagged" if flagged else "nothing suspicious: all investigations accounted for.")
    return 0


def cmd_export_findings(a):
    conn = connect(a.db)
    audit_id = active_audit_id(conn)
    if not audit_id:
        print("ERROR: no active audit (run init first)", file=sys.stderr)
        return 2
    where = "" if a.include_refuted else " WHERE status != 'refuted'"
    # Exported findings conform to schemas/findings.schema.json: strip internal
    # bookkeeping columns and NULL optionals.
    internal = ("audit_id", "first_seen", "updated_at")
    findings = []
    for r in conn.execute(f"SELECT * FROM findings{where}"):
        findings.append({k: v for k, v in deserialize(r).items() if k not in internal and v is not None})
    coverage = [dict(r) for r in conn.execute("SELECT area, attack_class, status, notes FROM coverage")]
    doc = {
        "audit_id": audit_id,
        "repo": a.repo or (conn.execute("SELECT repo FROM audits WHERE id=?", (audit_id,)).fetchone()["repo"]),
        "generated_at": now(),
        "coverage": coverage,
        "findings": findings,
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {a.out}: {len(findings)} finding(s), {len(coverage)} coverage row(s)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def dbarg(p):
        p.add_argument("--db", required=True, help="path to audit.db")

    p = sub.add_parser("init"); dbarg(p)
    p.add_argument("--repo", required=True); p.add_argument("--audit-id")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("log"); dbarg(p)
    p.add_argument("--phase", required=True); p.add_argument("--message", required=True)
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("investigation-add"); dbarg(p)
    p.add_argument("--id", required=True); p.add_argument("--kind", required=True,
        choices=["recon", "hunt", "validation", "poc", "remediation"])
    p.add_argument("--attack-class"); p.add_argument("--status", default="pending")
    p.add_argument("--claimed-findings", type=int); p.add_argument("--notes")
    p.set_defaults(fn=cmd_investigation_add)

    p = sub.add_parser("investigation-update"); dbarg(p)
    p.add_argument("--id", required=True); p.add_argument("--status")
    p.add_argument("--claimed-findings", type=int); p.add_argument("--notes")
    p.set_defaults(fn=cmd_investigation_update)

    p = sub.add_parser("add-finding"); dbarg(p)
    p.add_argument("--file"); p.add_argument("--stdin", action="store_true")
    p.set_defaults(fn=cmd_add_finding)

    p = sub.add_parser("update"); dbarg(p)
    p.add_argument("id")
    p.add_argument("--status", choices=STATUS); p.add_argument("--validation", choices=VALIDATION)
    p.add_argument("--validator"); p.add_argument("--severity", choices=SEVERITY)
    p.add_argument("--confidence", choices=["high", "medium", "low"])
    p.add_argument("--poc-ref"); p.add_argument("--patch-ref")
    p.add_argument("--production-reachable", choices=["true", "false"])
    p.set_defaults(fn=cmd_update)

    p = sub.add_parser("list"); dbarg(p)
    p.add_argument("--status", choices=STATUS); p.add_argument("--validation", choices=VALIDATION)
    p.add_argument("--format", choices=["table", "json"], default="table")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show"); dbarg(p); p.add_argument("id")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("dedupe"); dbarg(p)
    p.set_defaults(fn=cmd_dedupe)

    p = sub.add_parser("coverage-add"); dbarg(p)
    p.add_argument("--area", required=True); p.add_argument("--attack-class", required=True)
    p.add_argument("--status", required=True, choices=["uncovered", "investigated", "no-issues", "findings"])
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_coverage_add)

    p = sub.add_parser("coverage"); dbarg(p)
    p.set_defaults(fn=cmd_coverage)

    p = sub.add_parser("stats"); dbarg(p)
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("incomplete"); dbarg(p)
    p.set_defaults(fn=cmd_incomplete)

    p = sub.add_parser("export-findings"); dbarg(p)
    p.add_argument("--out", required=True); p.add_argument("--repo")
    p.add_argument("--include-refuted", action="store_true")
    p.set_defaults(fn=cmd_export_findings)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
