"""Regenerate requirements.txt from PyPI JSON, with a hash for every published file.

Pins come from requirements.in (direct) and the current requirements.txt
(transitive). Use --pin NAME==VERSION to add or bump one. The lock fails when:

- any file of a pin was uploaded less than --cooldown-days ago (default 14).
  PyPI lets a maintainer add wheels to an old release, so the check uses
  the newest file;
- a pin, or one of its files, is yanked;
- a pin needs a dependency that is not pinned (extras are ignored).

requirements.in may exclude a transitive dependency with a comment line
`# lock: exclude NAME - REASON`. An excluded package is left out of the lock
and skipped by the dependency check, so `pip install --no-deps` never
installs it. Use this only for code the harness provably never imports, and
say why in REASON; the lock header lists every exclusion.

A comment line `# lock: allow-young NAME==VERSION sha256:HASH[,HASH...] - REASON`
exempts the listed files of that one exact pin from the cooldown, for a
security fix that cannot wait 14 days. REASON should name the advisory. Only
the listed files are waived: a file added to the release later must still
clear the cooldown. The lock fails if the pinned version is not VERSION, or
once every file is old enough that the waiver is no longer needed, so a stale
waiver never lingers. The lock header lists each one.

Stdlib only, so it runs before anything is installed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\#]+)")
REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
EXCLUDE_RE = re.compile(r"^\s*#\s*lock:\s*exclude\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+-\s+(\S.*?)\s*$")
ALLOW_YOUNG_RE = re.compile(
    r"^\s*#\s*lock:\s*allow-young\s+([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)"
    r"\s+sha256:([0-9a-f]{64}(?:,[0-9a-f]{64})*)\s+-\s+(\S.*?)\s*$")


def canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(path: Path) -> dict[str, tuple[str, str]]:
    pins: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return pins
    for line in path.read_text(encoding="utf-8").splitlines():
        m = PIN_RE.match(line)
        if m:
            pins[canon(m.group(1))] = (m.group(1), m.group(2))
    return pins


def read_excludes(path: Path) -> dict[str, tuple[str, str]]:
    """`# lock: exclude NAME - REASON` lines, keyed by canonical name."""
    excludes: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return excludes
    for line in path.read_text(encoding="utf-8").splitlines():
        m = EXCLUDE_RE.match(line)
        if m:
            excludes[canon(m.group(1))] = (m.group(1), m.group(2))
    return excludes


def read_allow_young(path: Path) -> dict[str, tuple[str, str, frozenset[str], str]]:
    """`# lock: allow-young NAME==VERSION sha256:HASH,... - REASON` lines, keyed by canonical name."""
    allowed: dict[str, tuple[str, str, frozenset[str], str]] = {}
    if not path.exists():
        return allowed
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ALLOW_YOUNG_RE.match(line)
        if m:
            allowed[canon(m.group(1))] = (m.group(1), m.group(2), frozenset(m.group(3).split(",")), m.group(4))
    return allowed


def fetch(name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


def runtime_deps(info: dict) -> set[str]:
    deps = set()
    for req in info.get("requires_dist") or []:
        marker = req.split(";", 1)[1] if ";" in req else ""
        if re.search(r"\bextra\s*==", marker):
            continue
        m = REQ_NAME_RE.match(req)
        if m:
            deps.add(canon(m.group(1)))
    return deps


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness.lock", description=__doc__.splitlines()[0])
    ap.add_argument("--cooldown-days", type=int, default=14)
    ap.add_argument("--pin", action="append", default=[], metavar="NAME==VERSION")
    ap.add_argument("--in", dest="infile", default=str(ROOT / "requirements.in"))
    ap.add_argument("--out", default=str(ROOT / "requirements.txt"))
    args = ap.parse_args(argv)

    excludes = read_excludes(Path(args.infile))
    allow_young = read_allow_young(Path(args.infile))
    pins = read_pins(Path(args.out))
    pins.update(read_pins(Path(args.infile)))
    for p in args.pin:
        m = PIN_RE.match(p)
        if not m:
            ap.error(f"--pin must be NAME==VERSION, got {p!r}")
        pins[canon(m.group(1))] = (m.group(1), m.group(2))
    for key in excludes:
        pins.pop(key, None)
    if not pins:
        ap.error("no pins found")

    now = dt.datetime.now(dt.timezone.utc)
    problems: list[str] = []
    for key, (name, version, _, _) in sorted(allow_young.items()):
        if key not in pins:
            problems.append(f"allow-young {name}=={version}: {name} is not pinned; remove the line")
        elif pins[key][1] != version:
            problems.append(f"allow-young {name}=={version}: the pin is {pins[key][0]}=={pins[key][1]}; "
                            "remove or update the line")
    blocks: list[str] = []
    needed: dict[str, set[str]] = {}
    for key in sorted(pins):
        name, version = pins[key]
        try:
            data = fetch(name, version)
        except Exception as exc:  # network or 404
            problems.append(f"{name}=={version}: cannot fetch PyPI metadata ({exc})")
            continue
        files = data.get("urls") or []
        if not files:
            problems.append(f"{name}=={version}: no published files")
            continue
        if data["info"].get("yanked") or any(f.get("yanked") for f in files):
            problems.append(f"{name}=={version}: yanked on PyPI")
        uploaded = [(dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")), f.get("filename", "?"))
                    for f in files]
        newest, newest_name = max(uploaded)
        age = now - newest
        young = age < dt.timedelta(days=args.cooldown_days)
        exempt = key in allow_young and allow_young[key][1] == version
        if exempt and not young:
            problems.append(f"allow-young {name}=={version}: every file is now at least "
                            f"{args.cooldown_days} days old; remove the line from requirements.in")
        elif exempt:
            waived = allow_young[key][2]
            for f in files:
                when = dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                if now - when < dt.timedelta(days=args.cooldown_days) and f["digests"]["sha256"] not in waived:
                    problems.append(
                        f"{name}=={version}: {f.get('filename', '?')} was uploaded {when:%Y-%m-%d %H:%M}Z and its "
                        f"sha256 is not listed in the allow-young waiver; every other file must be at least "
                        f"{args.cooldown_days} days old"
                    )
        elif young:
            problems.append(
                f"{name}=={version}: {newest_name} was uploaded {newest:%Y-%m-%d %H:%M}Z, {age.days} days ago; "
                f"every file must be at least {args.cooldown_days} days old"
            )
        needed[key] = runtime_deps(data["info"])
        hashes = sorted({f["digests"]["sha256"] for f in files})
        lines = [f"{name}=={version} \\"]
        lines += [f"    --hash=sha256:{h} \\" for h in hashes[:-1]]
        lines.append(f"    --hash=sha256:{hashes[-1]}")
        blocks.append("\n".join(lines))

    for key, deps in sorted(needed.items()):
        for dep in sorted(deps - set(pins) - set(excludes)):
            problems.append(f"{pins[key][0]} needs {dep}, which is not pinned; add --pin {dep}==<version>")

    if problems:
        for p in problems:
            print(f"lock: {p}", file=sys.stderr)
        print("lock: requirements.txt was not changed", file=sys.stderr)
        return 1

    header = (
        f"# Generated by `python -m harness.lock --cooldown-days {args.cooldown_days}` on {now:%Y-%m-%d}.\n"
        "# Do not edit by hand. Every pin carries a hash for every file PyPI publishes for it\n"
        "# (all wheels and the sdist), so one lock installs on any interpreter and platform.\n"
        "# Install: python -m pip install --require-hashes --no-deps -r requirements.txt\n"
    )
    for _, (name, reason) in sorted(excludes.items()):
        header += f"# Excluded (see requirements.in): {name} - {reason}\n"
    for _, (name, version, _, reason) in sorted(allow_young.items()):
        header += f"# Cooldown waived (see requirements.in): {name}=={version} - {reason}\n"
    Path(args.out).write_text(header + "\n".join(blocks) + "\n", encoding="utf-8")
    print(f"lock: wrote {len(blocks)} pins to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
