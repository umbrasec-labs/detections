"""Fail if this repo ever contains detection rule text.

python -m harness.guard [ROOT]

The canonical rules live in umbrasec.dev/tools/sigma-pack. This repo holds
claims about them, never copies. The guard fails on any Kusto file (.kql,
.kusto, .csl, or a name holding .kql such as x.kql.txt), on any YAML or JSON
document that has a detection, logsource or correlation key at any depth, and
on any such file it cannot parse (fail closed). YAML here means any name that
holds .yml or .yaml, so x.yml.txt is read too.

When ROOT is the top of a git work tree, the guard reads the files git tracks
or would add (`git ls-files --cached --others --exclude-standard`), so a file
force-added under an ignored folder is still checked and no folder is skipped.
Without git it walks the tree and skips the folders listed in SKIP_DIRS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "out", "_upstream", ".venv", "node_modules", "__pycache__"}  # fallback walk only
RULE_KEYS = {"detection", "logsource", "correlation"}
KUSTO_SUFFIXES = (".kql", ".kusto", ".csl")


def _keys(node, depth=0):
    if depth > 100:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _keys(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _keys(v, depth + 1)


def git_files(root: Path) -> list[str] | None:
    """Paths git tracks or would add under root, or None when root is not the top of a work tree."""
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        if not top or Path(top).resolve() != Path(root).resolve():
            return None
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return sorted({p for p in out.decode("utf-8", "surrogateescape").split("\0") if p})


def walk_files(root: Path) -> list[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            files.append((Path(dirpath) / name).relative_to(root).as_posix())
    return files


def _docs(path: Path, as_json: bool) -> list:
    text = path.read_text(encoding="utf-8")
    if as_json:
        try:
            return [json.loads(text)]
        except ValueError:
            pass  # fall through: YAML is a superset of most JSON
    return list(yaml.safe_load_all(text))


def check_file(root: Path, rel: str) -> list[str]:
    p = root / rel
    if not p.is_file():
        return []  # deleted from the work tree, a submodule, or a dangling link
    low = Path(rel).name.lower()
    if low.endswith(KUSTO_SUFFIXES) or ".kql." in low:
        return [f"{rel}: a Kusto file is rule text"]
    is_json = low.endswith(".json")
    if not (is_json or ".yml" in low or ".yaml" in low):
        return []
    try:
        docs = _docs(p, is_json)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return [f"{rel}: cannot parse it, so it cannot be cleared ({exc.__class__.__name__})"]
    problems = []
    for n, doc in enumerate(docs):
        hits = sorted({k for k in _keys(doc) if isinstance(k, str) and k in RULE_KEYS})
        if hits:
            problems.append(f"{rel}: document {n} has rule keys {hits}")
    return problems


def scan(root: Path, use_git: bool | None = None) -> list[str]:
    """use_git: None picks git when root is a work tree; False always walks."""
    root = Path(root)
    files = git_files(root) if use_git is not False else None
    if files is None:
        if use_git:
            raise RuntimeError(f"{root} is not the top of a git work tree")
        files = walk_files(root)
    problems = []
    for rel in files:
        problems += check_file(root, rel)
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]) if argv else ROOT
    mode = "git file list" if git_files(root) is not None else "directory walk"
    problems = scan(root)
    for p in problems:
        print(f"guard: {p}")
    if problems:
        print(f"guard: FAILED, {len(problems)} problem(s). This repo must not hold rule text.")
        return 1
    print(f"guard: ok, no rule text under {root} ({mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
