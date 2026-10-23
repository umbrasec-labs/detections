"""Fail the job unless the record says every rule is verified or not-executed.

python -m harness.gate out/claims.json

Runs last in CI, after the record is attested and uploaded, so a red run still
leaves evidence behind. Exit 0 when ok, 1 when not, 2 when the record is missing
or unreadable.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PASSING = {"verified", "not-executed"}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m harness.gate out/claims.json", file=sys.stderr)
        return 2
    try:
        rec = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        rules = rec["rules"]
        summary = rec["summary"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"gate: cannot read {argv[0]}: {exc}", file=sys.stderr)
        return 2

    bad = {stem: r for stem, r in sorted(rules.items()) if r.get("status") not in PASSING}
    orphans = rec.get("orphans") or {}
    ledger_errors = {slug: w for slug, w in (rec.get("writeups") or {}).items() if w.get("errors")}
    ok = bool(rec.get("ok")) and bool(summary.get("ok")) and bool(rules) and not bad and not orphans and not ledger_errors

    for stem, r in bad.items():
        codes = Counter(e.get("code") for e in r.get("errors") or [])
        if r.get("stale"):
            codes["stale"] += 1
        listed = ", ".join(f"{c} x{n}" if n > 1 else c for c, n in sorted(codes.items()))
        print(f"gate: {stem}: {r.get('status')} ({listed or 'no error codes'})")
        for e in (r.get("errors") or [])[:5]:
            print(f"        {e.get('code')}: {e.get('message')}")
    for stem in sorted(orphans):
        print(f"gate: {stem}: orphan claims file")
    for slug in sorted(ledger_errors):
        if not ledger_errors[slug].get("rules"):
            print(f"gate: ledger {slug}: " + ", ".join(e.get("code") for e in ledger_errors[slug]["errors"]))

    print(f"gate: {'ok' if ok else 'FAILED'}: {summary.get('verified', 0)} verified, "
          f"{summary.get('not_executed', 0)} not-executed, {len(bad)} other, of {len(rules)} rules")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
