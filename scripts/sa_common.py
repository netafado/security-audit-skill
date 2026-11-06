#!/usr/bin/env python3
"""Shared helpers for security-audit scripts (stdlib only).

Keep this module dependency-free so every script runs on a bare Python 3
interpreter, on any machine the skill is installed on.
"""
import hashlib
import json
import re


def slugify(value):
    """Normalize an attack class into a kebab-case slug."""
    s = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return s or "class"


def normalized_title(title):
    """Whitespace-collapsed, lowercased title used for stable-id hashing."""
    return " ".join(str(title).lower().split())


def finding_id(attack_class, primary_file, title):
    """Stable finding id: SA-<class>-<8 hex of sha1(class|file|title)>.

    Two independent investigations that discover the same issue compute the
    same id even if they run on different models at different times — this is
    what makes dedup deterministic instead of model-judgment-based.
    """
    payload = f"{slugify(attack_class)}|{primary_file}|{normalized_title(title)}"
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
    return f"SA-{slugify(attack_class)}-{digest}"


def primary_file(finding):
    """First (primary) file path of a finding, for stable-id computation."""
    files = finding.get("files") or []
    if files and isinstance(files[0], dict):
        return files[0].get("path", "")
    return ""


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
