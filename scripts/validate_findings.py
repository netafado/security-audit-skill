#!/usr/bin/env python3
"""Validate a findings.json document for a security-audit run.

Checks, in order:
  1. Schema conformance against schemas/findings.schema.json (stdlib-only
     validator implementing the JSON Schema subset that file uses: type,
     enum, const, required, properties, additionalProperties, items,
     min/maxItems, uniqueItems, min/maxLength, pattern, minimum/maximum,
     internal $ref).
  2. Semantic consistency: unique ids, stable-id recomputation, status
     invariants (confirmed requires poc_ref), validation/status agreement,
     possible duplicates, severity sanity.

Mechanical validation corroborates findings; it never proves exploitability.

Usage:
  python3 validate_findings.py findings.json [--schema PATH] [--strict] [--json]

Exit codes: 0 = no errors, 1 = errors found, 2 = usage/IO problem.
"""
import argparse
import json
import re
import sys

try:
    from sa_common import finding_id, primary_file, normalized_title
except ImportError:  # allow running from repo root
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from sa_common import finding_id, primary_file, normalized_title

DEFAULT_SCHEMA = __file__.rsplit("/", 1)[0] + "/../schemas/findings.schema.json"


class SchemaError(Exception):
    pass


def _resolve_ref(root, ref):
    if not ref.startswith("#/"):
        raise SchemaError(f"only internal $ref is supported: {ref}")
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise SchemaError(f"unresolvable $ref: {ref}")
    return node


def _type_ok(value, types):
    for t in types:
        if t == "object" and isinstance(value, dict):
            return True
        if t == "array" and isinstance(value, list):
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if t == "boolean" and isinstance(value, bool):
            return True
        if t == "null" and value is None:
            return True
    return False


def schema_errors(instance, schema, root, path="$"):
    """Yield human-readable schema violation strings."""
    if "$ref" in schema:
        yield from schema_errors(instance, _resolve_ref(root, schema["$ref"]), root, path)
        return
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not _type_ok(instance, types):
            yield f"{path}: expected type {'/'.join(types)}, got {type(instance).__name__}"
            return
    if "enum" in schema and instance not in schema["enum"]:
        yield f"{path}: {instance!r} is not one of {schema['enum']}"
    if "const" in schema and instance != schema["const"]:
        yield f"{path}: {instance!r} != const {schema['const']!r}"
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            yield f"{path}: shorter than minLength {schema['minLength']}"
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            yield f"{path}: longer than maxLength {schema['maxLength']}"
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            yield f"{path}: {instance!r} does not match pattern {schema['pattern']!r}"
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            yield f"{path}: {instance} < minimum {schema['minimum']}"
        if "maximum" in schema and instance > schema["maximum"]:
            yield f"{path}: {instance} > maximum {schema['maximum']}"
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            yield f"{path}: fewer than minItems {schema['minItems']}"
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            yield f"{path}: more than maxItems {schema['maxItems']}"
        if schema.get("uniqueItems") and len(instance) > 1:
            seen = [json.dumps(v, sort_keys=True) for v in instance]
            if len(set(seen)) != len(seen):
                yield f"{path}: items are not unique"
        items = schema.get("items")
        if isinstance(items, dict):
            for i, v in enumerate(instance):
                yield from schema_errors(v, items, root, f"{path}[{i}]")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                yield f"{path}: missing required property {req!r}"
        props = schema.get("properties", {})
        for name, sub in props.items():
            if name in instance:
                yield from schema_errors(instance[name], sub, root, f"{path}.{name}")
        extra = schema.get("additionalProperties", True)
        if extra is False:
            for name in instance:
                if name not in props:
                    yield f"{path}: unexpected property {name!r}"
        elif isinstance(extra, dict):
            for name in instance:
                if name not in props:
                    yield from schema_errors(instance[name], extra, f"{path}.{name}")


def semantic_errors_and_warnings(doc):
    """Return (errors, warnings) beyond pure schema conformance."""
    errors, warnings = [], []
    findings = doc.get("findings") or []
    seen_id = {}
    seen_key = {}
    seen_pair_keys = {}
    for i, f in enumerate(findings):
        fid = f.get("id", "<no-id>")
        label = f"findings[{i}] ({fid})"
        if fid in seen_id:
            errors.append(f"{label}: duplicate id, first seen at findings[{seen_id[fid]}]")
        else:
            seen_id[fid] = i
        cls, pf = f.get("attack_class", ""), primary_file(f)
        if cls and pf and f.get("title"):
            expected = finding_id(cls, pf, f["title"])
            if expected != fid:
                warnings.append(f"{label}: stable-id recomputes to {expected} — rerun audit_state.py add-finding/dedupe")
            key = (cls, pf, normalized_title(f["title"]))
            if key in seen_key:
                errors.append(f"{label}: exact duplicate of findings[{seen_key[key]}] (same class/file/title)")
            else:
                seen_key[key] = i
            pair = (cls, pf)
            if pair in seen_pair_keys and fid not in seen_pair_keys[pair]:
                other = seen_pair_keys[pair][0]
                warnings.append(f"{label}: shares attack_class+file with findings[{other}] — verify it is not a duplicate")
            seen_pair_keys.setdefault(pair, []).append(i)
        status = f.get("status")
        vstatus = (f.get("validation") or {}).get("status")
        if status == "confirmed":
            if not f.get("poc_ref"):
                errors.append(f"{label}: status 'confirmed' requires poc_ref")
            if not f.get("evidence"):
                warnings.append(f"{label}: status 'confirmed' has no evidence references")
            if vstatus != "validated":
                warnings.append(f"{label}: status 'confirmed' but validation is {vstatus!r} — confirmed findings must pass adversarial validation first")
            if f.get("severity") == "critical" and f.get("production_reachable") is not True:
                warnings.append(f"{label}: critical severity but production_reachable is not asserted")
        if status == "unverified":
            text = " ".join(f.get("reproduction", []) + [f.get("description", "")]).lower()
            if not any(k in text for k in ("cannot", "couldn", "could not", "missing", "requires", "prerequisite", "not available", "unavailable")):
                warnings.append(f"{label}: status 'unverified' must state the missing prerequisites")
        if status == "refuted" and vstatus == "validated":
            warnings.append(f"{label}: status 'refuted' but validation says 'validated' — contradictory")
    return errors, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", help="path to findings.json")
    ap.add_argument("--schema", default=DEFAULT_SCHEMA, help="path to findings schema (default: bundled)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--json", action="store_true", help="emit machine-readable summary")
    args = ap.parse_args(argv)

    try:
        doc = json.load(open(args.findings, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {args.findings}: {exc}", file=sys.stderr)
        return 2
    try:
        schema = json.load(open(args.schema, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read schema {args.schema}: {exc}", file=sys.stderr)
        return 2

    errors = list(schema_errors(doc, schema, schema))
    sem_errors, warnings = semantic_errors_and_warnings(doc)
    errors.extend(sem_errors)
    if args.strict:
        errors.extend(warnings)
        warnings = []

    findings = doc.get("findings") or []
    counts = {}
    for f in findings:
        counts[f.get("status", "?")] = counts.get(f.get("status", "?"), 0) + 1

    if args.json:
        print(json.dumps({
            "file": args.findings,
            "findings": len(findings),
            "by_status": counts,
            "errors": errors,
            "warnings": warnings,
            "exit": 1 if errors else 0,
        }, indent=2))
    else:
        print(f"security-audit findings validation — {args.findings}")
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "empty"
        print(f"  findings: {len(findings)} ({summary})")
        for e in errors:
            print(f"  ERROR   {e}")
        for w in warnings:
            print(f"  WARNING {w}")
        print(f"  {len(errors)} error(s), {len(warnings)} warning(s)"
              f"{' [strict]' if args.strict else ''}")
        print("  note: mechanical validation corroborates findings; it never proves exploitability.")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
