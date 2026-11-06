#!/usr/bin/env python3
"""Verify that file/line/symbol references in findings.json exist in the repo.

Per finding:
  - every files[].path resolves to a real file under --repo
  - every files[].lines[n] is within the file's actual line count
  - files[].function and finding.functions symbols appear in the referenced
    file (word-boundary text search — language-agnostic, deliberately simple)
  - poc_ref / patch_ref resolve under --audit-dir (default <repo>/.security-audit)

This catches hallucinated references: a finding citing a file, line, or
function that does not exist in the original source cannot be trusted.
Mechanical checks corroborate findings; they never prove exploitability.

Usage:
  python3 verify_references.py findings.json --repo <repo-root> [--audit-dir DIR] [--json]

Exit codes: 0 = no errors, 1 = errors found, 2 = usage/IO problem.
"""
import argparse
import json
import os
import re
import sys

try:
    from sa_common import load_json
except ImportError:
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from sa_common import load_json


def symbol_present(content, symbol):
    """Word-boundary search with a plain substring fallback for exotic names."""
    if not symbol:
        return True
    try:
        if re.search(r"\b" + re.escape(symbol) + r"\b", content):
            return True
    except re.error:
        pass
    return symbol in content


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", help="path to findings.json")
    ap.add_argument("--repo", required=True, help="repository root the file paths are relative to")
    ap.add_argument("--audit-dir", default=None, help="audit output dir (default: <repo>/.security-audit)")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args(argv)

    try:
        doc = load_json(args.findings)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {args.findings}: {exc}", file=sys.stderr)
        return 2

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"ERROR: --repo {repo} is not a directory", file=sys.stderr)
        return 2
    audit_dir = os.path.abspath(args.audit_dir or os.path.join(repo, ".security-audit"))

    errors, checked_files = [], []
    findings = doc.get("findings") or []
    for i, f in enumerate(findings):
        label = f"findings[{i}] ({f.get('id', '<no-id>')})"
        file_entries = f.get("files") or []
        if not file_entries:
            errors.append(f"{label}: no file references")
            continue
        for entry in file_entries:
            rel = entry.get("path", "")
            full = os.path.normpath(os.path.join(repo, rel))
            try:
                if os.path.exists(full) and os.path.commonpath([repo, full]) != repo:
                    errors.append(f"{label}: path {rel!r} escapes --repo")
                    continue
            except ValueError:  # e.g. absolute path on another drive
                errors.append(f"{label}: path {rel!r} escapes --repo")
                continue
            if not os.path.isfile(full):
                errors.append(f"{label}: file does not exist in repo: {rel}")
                continue
            checked_files.append(rel)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                line_count = len(content.splitlines())
            except OSError as exc:
                errors.append(f"{label}: cannot read {rel}: {exc}")
                continue
            for ln in entry.get("lines", []):
                if not isinstance(ln, int) or ln < 1:
                    errors.append(f"{label}: {rel}: invalid line number {ln!r}")
                elif ln > line_count:
                    errors.append(f"{label}: {rel}: line {ln} out of range (file has {line_count} lines)")
            symbols = []
            for sym in [entry.get("function", "")] + list(f.get("functions", [])):
                if sym and sym not in symbols:
                    symbols.append(sym)
            for sym in symbols:
                if not symbol_present(content, sym):
                    errors.append(f"{label}: symbol {sym!r} not found in {rel}")
        for ref_field in ("poc_ref", "patch_ref"):
            ref = f.get(ref_field)
            if ref:
                full_ref = ref if os.path.isabs(ref) else os.path.join(audit_dir, ref)
                if not os.path.exists(full_ref):
                    kind = "PoC" if ref_field == "poc_ref" else "patch"
                    errors.append(f"{label}: {kind} reference not found: {ref}")

    if args.json:
        print(json.dumps({
            "file": args.findings,
            "repo": repo,
            "findings": len(findings),
            "files_checked": sorted(set(checked_files)),
            "errors": errors,
            "exit": 1 if errors else 0,
        }, indent=2))
    else:
        print(f"security-audit reference verification — {args.findings} against {repo}")
        print(f"  findings: {len(findings)}, files resolved: {len(set(checked_files))}")
        for e in errors:
            print(f"  ERROR   {e}")
        if not errors:
            print("  all referenced files, lines, and symbols resolve in the original source.")
        print(f"  {len(errors)} error(s)")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
