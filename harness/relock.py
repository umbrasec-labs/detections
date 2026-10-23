"""Re-pin rule_sha256 after a human has re-read the claims for a changed rule.

python -m harness.relock --upstream PATH --i-reviewed STEM [STEM ...] [--date YYYY-MM-DD]

Rewrites only the rule_sha256: and reviewed: lines of each claims file, with a
regex, so comments and layout stay as they are. Run it only after you have read
the upstream diff and the claims, and fixed any claim the change broke.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

from . import pack

ROOT = Path(__file__).resolve().parents[1]
SHA_LINE = re.compile(r"^(rule_sha256:[ \t]*)([^\s#]+)(.*)$", re.M)
REVIEWED_LINE = re.compile(r"^(reviewed:[ \t]*)([^\s#]+)(.*)$", re.M)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness.relock", description=__doc__.splitlines()[0])
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--i-reviewed", nargs="+", required=True, metavar="STEM", dest="stems")
    ap.add_argument("--claims", default=str(ROOT / "claims"))
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    args = ap.parse_args(argv)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        ap.error("--date must be YYYY-MM-DD")

    files = {rf.id: rf for rf in pack.discover(Path(args.upstream))}
    if not files:
        ap.error(f"no sigma-pack files under {args.upstream}")
    rc = 0
    for stem in args.stems:
        rf = files.get(stem)
        cp = Path(args.claims) / f"{stem}.yml"
        if rf is None or not cp.is_file():
            print(f"relock: {stem}: no such rule or claims file", file=sys.stderr)
            rc = 2
            continue
        text = cp.read_text(encoding="utf-8")
        if len(SHA_LINE.findall(text)) != 1 or len(REVIEWED_LINE.findall(text)) != 1:
            print(f"relock: {stem}: expected exactly one rule_sha256: and one reviewed: line", file=sys.stderr)
            rc = 2
            continue
        old = SHA_LINE.search(text).group(2)
        text = SHA_LINE.sub(lambda m: m.group(1) + rf.sha256 + m.group(3), text)
        text = REVIEWED_LINE.sub(lambda m: m.group(1) + args.date + m.group(3), text)
        cp.write_text(text, encoding="utf-8")
        print(f"relock: {stem}: {old[:12]} -> {rf.sha256[:12]}, reviewed {args.date}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
