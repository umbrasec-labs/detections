"""Prove every claim against an upstream checkout and write the record.

python -m harness.run --upstream PATH [--out out] [--exit-zero] [--only STEM ...]
                      [--claims DIR] [--print-sentences research/x.html]

Exit codes: 0 when every rule is verified or not-executed, 1 otherwise,
2 for a usage error. --exit-zero always exits 0 after writing the outputs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from . import __version__, claims, engine, pack

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_REPO = "umbrasec-labs/umbrasec.dev"
PREDICATE_SCHEMA = "umbrasec.claims-predicate/v1"
PROVES = (
    "This run proves rule logic under Sigma reference semantics (pySigma to SQLite), "
    "on labelled synthetic events, with assumed field shapes. It does not prove your SIEM's "
    "field mappings or your telemetry, and case folding is ASCII only."
)


def _git(args: list[str]) -> str | None:
    try:
        res = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                             check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout


def harness_info() -> dict:
    head = (_git(["rev-parse", "HEAD"]) or "").strip() or None
    status = _git(["status", "--porcelain", "--untracked-files=no"])
    return {
        "repo": claims.REPO,
        "commit": head,
        "dirty": bool(status.strip()) if status is not None else None,
        "version": __version__,
    }


def dump(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def build_record(result: dict, upstream: Path) -> dict:
    s = result["summary"]
    return {
        "schema": claims.SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": s["ok"],
        "harness": harness_info(),
        "engine": engine.versions(),
        "sigma_pack": {"repo": UPSTREAM_REPO, "path": pack.PACK_PATH, "commit": pack.commit(upstream)},
        "summary": s,
        "rules": result["rules"],
        "orphans": result["orphans"],
        "writeups": result["writeups"],
    }


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_report(rec: dict) -> str:
    s = rec["summary"]
    e = rec["engine"]
    h = rec["harness"]
    sp = rec["sigma_pack"]
    fp = s["falsepositives"]
    ws = s["writeup_sentences"]
    lines = [
        "# Claims Ledger report",
        "",
        f"- Result: **{'OK' if rec['ok'] else 'NOT OK'}**. {s['verified']} verified, {s['not_executed']} not executed (KQL), "
        f"{s['stale']} stale, {s['failing']} failing, {s['unclaimed']} unclaimed, {s['orphan']} orphan.",
        f"- Claims: {s['claims']} in total, {s['executed']} executed, {s['passed']} passed, {s['failed']} failed, "
        f"{s['not_executed_claims']} not executed.",
        f"- falsepositives bullets: {fp['total']} in total, {fp['proved']} proved, {fp['dispositioned']} dispositioned, "
        f"{fp['failed']} quoted only by claims that did not pass, {fp['not_executed']} quoted by KQL claims "
        f"(not executed), {fp['uncovered']} uncovered.",
        f"- Honest limitations sentences: {ws['total']} in total, {ws['tested']} tested, {ws['dispositioned']} dispositioned, "
        f"{ws['failed']} tested by claims that did not pass, {ws['unaccounted']} unaccounted.",
        f"- sigma-pack: `{sp['repo']}` at `{sp['commit'] or 'unknown'}` (`{sp['path']}`)",
        f"- Harness: `{h['repo']}` at `{h['commit'] or 'uncommitted'}`{' (dirty tree)' if h.get('dirty') else ''}, "
        f"version {h['version']}",
        f"- Engine: pySigma {e['pysigma']}, {e['backend']}, SQLite {e['sqlite']}, Python {e['python']}",
        f"- Generated: {rec['generated_at']}",
        "",
        f"> {PROVES}",
        "",
        "## Rules",
        "",
        "| Rule | Status | catches | false-positive | blind-spot | excluded | near-miss | undocumented | FP bullets proved | Mapper |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for stem, r in sorted(rec["rules"].items()):
        c = r["counts"]
        cov = r["coverage"]["falsepositives"]
        extra = [f"+{cov['dispositioned']} dispositioned"] if cov["dispositioned"] else []
        extra += [f"{cov['failed']} failed"] if cov["failed"] else []
        extra += [f"{cov['not_executed']} not executed"] if cov.get("not_executed") else []
        fp_cell = f"{cov['proved']}/{cov['total']}" + (f" ({', '.join(extra)})" if extra else "")
        if cov["total"] == 0:
            fp_cell = "none stated"
        lines.append(
            f"| [{stem}]({r['claims_url'] or r['file']}) | {r['status']} | {c['catches']} | {c['false-positive']} | "
            f"{c['blind-spot']} | {c['excluded']} | {c['near-miss']} | {c['undocumented']} | {fp_cell} | "
            f"[view]({r['mapper_url']}) |"
        )

    problems = [(stem, x) for stem, r in sorted(rec["rules"].items()) for x in r["errors"]]
    problems += [(stem, x) for stem, o in sorted(rec["orphans"].items()) for x in o["errors"]]
    stale = [stem for stem, r in sorted(rec["rules"].items()) if r.get("stale")]
    if problems or stale:
        lines += ["", "## Problems", ""]
        for stem in stale:
            r = rec["rules"][stem]
            lines.append(f"- `{stem}`: **stale**. The rule bytes are `{r['sha256'][:12]}`, the claims were "
                         f"reviewed against `{(r['pinned_sha256'] or '?')[:12]}`. Re-read the claims, then run harness.relock.")
        for stem, x in problems:
            lines.append(f"- `{stem}`: `{x['code']}` {_cell(x['message'])}")

    lines += ["", "## Findings (for upstream)", ""]
    findings = [(stem, f) for stem, r in sorted(rec["rules"].items()) for f in r["findings"]]
    if findings:
        lines += ["| Rule | Claim | Confidence | Finding | Upstream |", "|---|---|---|---|---|"]
        for stem, f in findings:
            lines.append(f"| {stem} | `{f['claim']}` | {f['confidence']} | {_cell(f['summary'])} | {f['upstream']} |")
    else:
        lines.append("None.")

    lines += ["", "## Lint (advisory)", ""]
    lints = [(stem, x) for stem, r in sorted(rec["rules"].items()) for x in r["lint"]]
    if lints:
        lines += ["| Rule | Code | Path | Value |", "|---|---|---|---|"]
        for stem, x in lints:
            val = "" if x["value"] is None else f"`{_cell(x['value'])}`"
            lines.append(f"| {stem} | `{x['code']}` | `{_cell(x['path'])}` | {val} |")
    else:
        lines.append("None.")

    lines += ["", "## Writeup ledgers", "",
              "| Writeup | Rules | Sentences | Tested | Failed | Dispositioned | Unaccounted |", "|---|---|---|---|---|---|---|"]
    for slug, w in sorted(rec["writeups"].items()):
        c = w["counts"]
        lines.append(f"| {slug} | {', '.join(w['rules']) or '-'} | {c['total']} | {c['tested']} | {c['failed']} | "
                     f"{c['dispositioned']} | {c['unaccounted']} |")
    return "\n".join(lines) + "\n"


def subjects(files: list[pack.RuleFile], claims_json_bytes: bytes) -> str:
    rows = [f"{rf.sha256}  {rf.upstream_rel}" for rf in sorted(files, key=lambda f: f.upstream_rel)]
    rows.append(f"{hashlib.sha256(claims_json_bytes).hexdigest()}  claims.json")
    return "\n".join(rows) + "\n"


def predicate(rec: dict, claims_json_bytes: bytes) -> dict:
    return {
        "schema": PREDICATE_SCHEMA,
        "generated_at": rec["generated_at"],
        "claims_json_sha256": hashlib.sha256(claims_json_bytes).hexdigest(),
        "ok": rec["ok"],
        "sigma_pack": rec["sigma_pack"],
        "harness": rec["harness"],
        "engine": rec["engine"],
        "summary": rec["summary"],
        "rules": {stem: {"sha256": r["sha256"], "status": r["status"], "counts": r["counts"]}
                  for stem, r in rec["rules"].items()},
        "writeups": {slug: {"writeup": w["writeup"], "sha256": w.get("sha256")} for slug, w in rec["writeups"].items()},
    }


def print_console(rec: dict) -> None:
    s = rec["summary"]
    for stem, r in sorted(rec["rules"].items()):
        n = len(r["claims"])
        passed = sum(1 for c in r["claims"] if c["result"] == "pass")
        print(f"{r['status']:<13} {stem:<40} {passed}/{n} claims passed")
        for x in r["errors"]:
            print(f"    {x['code']}: {x['message']}")
    for stem, o in sorted(rec["orphans"].items()):
        print(f"{'orphan':<13} {stem}")
        for x in o["errors"]:
            print(f"    {x['code']}: {x['message']}")
    for slug, w in sorted(rec["writeups"].items()):
        if w["errors"] and not w["rules"]:
            for x in w["errors"]:
                print(f"{'ledger':<13} {slug}: {x['code']}: {x['message']}")
    print(
        f"\n{'OK' if rec['ok'] else 'NOT OK'}: {s['verified']} verified, {s['not_executed']} not-executed, "
        f"{s['stale']} stale, {s['failing']} failing, {s['unclaimed']} unclaimed, {s['orphan']} orphan; "
        f"{s['executed']} claims executed, {s['passed']} passed, {s['failed']} failed; "
        f"falsepositives {s['falsepositives']['proved']}+{s['falsepositives']['dispositioned']}/{s['falsepositives']['total']}; "
        f"sentences {s['writeup_sentences']['tested']}+{s['writeup_sentences']['dispositioned']}/{s['writeup_sentences']['total']}"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness.run", description="Prove every claim against the sigma-pack.")
    ap.add_argument("--upstream", required=True, help="checkout of umbrasec-labs/umbrasec.dev")
    ap.add_argument("--out", default="out")
    ap.add_argument("--claims", default=str(ROOT / "claims"), help="claims directory (default: this repo's)")
    ap.add_argument("--exit-zero", action="store_true", help="exit 0 after writing outputs")
    ap.add_argument("--only", nargs="+", metavar="STEM")
    ap.add_argument("--print-sentences", metavar="research/x.html")
    args = ap.parse_args(argv)

    upstream = Path(args.upstream)
    if not (upstream / pack.PACK_PATH).is_dir():
        print(f"run: {upstream} has no {pack.PACK_PATH}", file=sys.stderr)
        return 2
    if args.print_sentences:
        path = upstream / args.print_sentences
        if not path.is_file():
            print(f"run: {path} does not exist", file=sys.stderr)
            return 2
        section = pack.writeup_section(path)
        if section is None:
            print(f"run: {path} has no Honest limitations section", file=sys.stderr)
            return 1
        for s in pack.split_sentences(section):
            print(s)
        return 0
    if not Path(args.claims).is_dir():
        print(f"run: claims directory {args.claims} does not exist", file=sys.stderr)
        return 2

    result = claims.evaluate_all(upstream, Path(args.claims), args.only)
    rec = build_record(result, upstream)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cj = dump(rec).encode("utf-8")
    (out / "claims.json").write_bytes(cj)
    (out / "REPORT.md").write_text(render_report(rec), encoding="utf-8")
    (out / "subjects.sha256").write_text(subjects(result["files"], cj), encoding="utf-8")
    (out / "predicate.json").write_text(dump(predicate(rec, cj)), encoding="utf-8")
    print_console(rec)
    if args.exit_zero:
        return 0
    return 0 if rec["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
