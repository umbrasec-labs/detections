"""Advisory static checks on upstream Sigma rules. Lint never fails a run."""

from __future__ import annotations

import re

from .pack import RuleFile, titled_doc

UNESCAPED_WILDCARD = re.compile(r"(?<!\\)[*?]")


def _walk(node, path):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def lint(rf: RuleFile) -> list[dict]:
    if rf.engine != "sigma":
        return []
    findings = []
    for doc in rf.docs:
        if not isinstance(doc, dict):
            continue
        det = doc.get("detection")
        if not isinstance(det, dict):
            continue
        for name, block in det.items():
            if name == "condition":
                continue
            for path, value in _walk(block, str(name)):
                if UNESCAPED_WILDCARD.search(value):
                    findings.append({
                        "code": "unescaped-wildcard",
                        "path": path,
                        "value": value,
                        "message": "a bare * or ? is a Sigma wildcard; escape it as \\* or \\? to match the character",
                    })
    doc = titled_doc(rf)
    if doc is not None and "falsepositives" not in doc:
        findings.append({
            "code": "no-falsepositives",
            "path": "falsepositives",
            "value": None,
            "message": "the rule states no false-positive profile",
        })
    return findings
