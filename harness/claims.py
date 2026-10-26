"""Load and validate claims, check quotes and coverage, execute claims, assign verdicts."""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from pathlib import Path

import yaml

from . import engine, lint, pack

SCHEMA = "umbrasec.claims/v1"
WRITEUP_SCHEMA = "umbrasec.claims-writeup/v1"
REPO = "umbrasec-labs/detections"
CLAIMS_URL = "https://github.com/umbrasec-labs/detections/blob/main/claims/{stem}.yml"
MAPPER_URL = "https://umbrasec-labs.github.io/BlueTeamMapper/detections?focus={stem}"
KUSTO_REASON = "no Kusto engine in CI yet"

KINDS = {
    # kind: (allowed expect values, quote rule)
    "catches": ({"match"}, "required"),
    "false-positive": ({"match"}, "required"),
    "blind-spot": ({"no-match"}, "required"),
    "excluded": ({"no-match"}, "required"),
    "near-miss": ({"no-match"}, "optional"),
    "undocumented": ({"match", "no-match"}, "forbidden"),
}
KIND_ORDER = list(KINDS)
FILE_REQUIRED = {"schema", "rule", "rule_id", "rule_sha256", "engine", "writeup", "reviewed", "claims"}
FILE_OPTIONAL = {"event_defaults", "fp_dispositions"}
CLAIM_KEYS = {
    "id", "kind", "quote", "expect", "events", "generate", "mode", "telemetry",
    "rationale", "summary", "confidence", "upstream", "table",
}
GENERATE_KEYS = {"count", "start", "step_seconds", "template"}
FP_DISPOSITIONS = {"advice", "lifecycle", "not-an-event"}
SENTENCE_DISPOSITIONS = {"tested", "context", "prerequisite", "not-reproduced"}
CONFIDENCE = {"confirmed", "needs-telemetry"}
UPSTREAM_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ISO_Z = "%Y-%m-%dT%H:%M:%SZ"


# --------------------------------------------------------------------------- YAML


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""


def _no_dupes(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dupes)


def load_yaml(path: Path):
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass


# --------------------------------------------------------------------------- helpers


def err(code: str, message: str, claim: str | None = None) -> dict:
    e = {"code": code, "message": message}
    if claim:
        e["claim"] = claim
    return e


def _date_str(v) -> str | None:
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return v
    return None


def _valid_value(v, key: str = "") -> bool:
    """Inserted fields are str, int or null. Metadata keys (leading _) may also be booleans."""
    if key.startswith("_") and isinstance(v, bool):
        return True
    return v is None or isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool))


def _verdict(b: bool) -> str:
    return "match" if b else "no-match"


class Context:
    """Caches upstream text that several claims files share."""

    def __init__(self, upstream: Path):
        self.upstream = Path(upstream)
        self._writeups: dict[str, str | None] = {}

    def writeup_text(self, rel: str) -> str | None:
        if rel not in self._writeups:
            p = self.upstream / rel
            self._writeups[rel] = pack.writeup_text(p) if p.is_file() else None
        return self._writeups[rel]


# --------------------------------------------------------------------------- events


def build_events(claim: dict, defaults: dict, errors: list, cid: str) -> list[dict]:
    events = []
    raw = claim.get("events")
    if raw is not None and not isinstance(raw, list):
        errors.append(err("schema", "events must be a list of flat mappings", cid))
        raw = []
    for e in raw or []:
        if not isinstance(e, dict):
            errors.append(err("schema", "every event must be a flat mapping", cid))
            continue
        events.append({**defaults, **e})
    gen = claim.get("generate")
    if gen is not None:
        if not isinstance(gen, dict) or set(gen) - GENERATE_KEYS or not GENERATE_KEYS <= set(gen):
            errors.append(err("schema", f"generate needs exactly {sorted(GENERATE_KEYS)}", cid))
            return events
        count, step, tmpl = gen["count"], gen["step_seconds"], gen["template"]
        try:
            start = dt.datetime.strptime(str(gen["start"]), ISO_Z)
        except ValueError:
            errors.append(err("schema", "generate.start must look like 2026-10-23T10:00:00Z", cid))
            return events
        if (not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 1000
                or not isinstance(step, int) or isinstance(step, bool) or step < 0
                or not isinstance(tmpl, dict)):
            errors.append(err("schema", "generate: count 1-1000, step_seconds >= 0, template a mapping", cid))
            return events
        for i in range(count):
            ev = {}
            for k, v in tmpl.items():
                if isinstance(v, str):
                    try:
                        v = v.format(i=i)
                    except (KeyError, IndexError, ValueError) as exc:
                        errors.append(err("schema", f"generate template {k!r}: {exc}", cid))
                        return events
                ev[k] = v
            ev["timestamp"] = (start + dt.timedelta(seconds=i * step)).strftime(ISO_Z)
            events.append({**defaults, **ev})
    return events


def kql_body(text: str) -> str:
    """The query text without its // comment lines."""
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("//"))


BAD_KEY_RE = re.compile(r'["\x00-\x1f\x7f]')


def check_events(events, fields, numeric, rf, errors, cid):
    lower_fields = {f.lower(): f for f in fields}
    body = kql_body(rf.text) if rf.engine == "kusto" else None
    unlabelled = [n for n, e in enumerate(events) if e.get("_synthetic") is not True]
    if unlabelled:
        errors.append(err("not-synthetic", f"events {unlabelled} lack _synthetic: true", cid))
    # SQLite column names are case-insensitive, and sequence mode puts every event in one
    # table, so two keys of one claim that differ only in case would clash.
    claim_keys: dict[str, str] = {}
    for n, e in enumerate(events):
        for k, v in e.items():
            if not isinstance(k, str) or not k:
                errors.append(err("schema", f"event {n} has a non-string key", cid))
                continue
            if not _valid_value(v, k):
                errors.append(err("schema", f"event {n} field {k!r}: values must be str, int or null", cid))
            if k.startswith("_"):
                continue
            if BAD_KEY_RE.search(k):
                errors.append(err("schema", f"event {n} key {k!r} contains a double quote or a control character", cid))
            seen = claim_keys.setdefault(k.lower(), k)
            if seen != k:
                errors.append(err("schema", f"event {n} key {k!r} differs only in case from key {seen!r} in this claim", cid))
            if k in numeric and isinstance(v, str):
                errors.append(err("numeric-field-as-string",
                                  f"event {n} field {k!r} is compared to a number by the rule; give an int, not {v!r}", cid))
            if (rf.engine == "sigma" and k not in numeric and isinstance(v, int) and not isinstance(v, bool)):
                errors.append(err("string-field-as-int",
                                  f"event {n} field {k!r} is not compared to a number by the rule, so the int {v!r} "
                                  f"can never equal a rule value; quote it (YAML reads unquoted 0x17 as 23)", cid))
            twin = lower_fields.get(k.lower())
            if twin is not None and twin != k:
                errors.append(err("schema", f"event {n} key {k!r} differs only in case from rule field {twin!r}", cid))
            if body is not None and not re.search(rf"\b{re.escape(k)}\b", body):
                errors.append(err("schema", f"event {n} key {k!r} does not appear in the query", cid))


# --------------------------------------------------------------------------- one rule


def check_rule(rf: pack.RuleFile, claims_path: Path, ctx: Context) -> dict:
    """Validate and execute one claims file. Returns the per-rule record (status set later)."""
    errors: list[dict] = []
    rec = {
        "file": rf.rel,
        "engine": rf.engine,
        "sha256": rf.sha256,
        "pinned_sha256": None,
        "stale": False,
        "status": None,
        "errors": errors,
        "counts": {k: 0 for k in KIND_ORDER},
        "coverage": {"falsepositives": {"total": 0, "proved": 0, "dispositioned": 0, "failed": 0,
                                        "not_executed": 0, "bullets": []}},
        "lint": lint.lint(rf),
        "findings": [],
        "claims": [],
        "writeup": None,
        "reviewed": None,
        "claims_url": CLAIMS_URL.format(stem=rf.id),
        "mapper_url": MAPPER_URL.format(stem=rf.id),
    }
    try:
        data = load_yaml(claims_path)
    except (OSError, yaml.YAMLError) as exc:
        errors.append(err("schema", f"cannot parse {claims_path.name}: {exc}"))
        return rec
    if not isinstance(data, dict):
        errors.append(err("schema", "claims file must be a mapping"))
        return rec

    unknown = set(data) - FILE_REQUIRED - FILE_OPTIONAL
    missing = FILE_REQUIRED - set(data)
    if unknown:
        errors.append(err("schema", f"unknown keys {sorted(unknown)}"))
    if missing:
        errors.append(err("schema", f"missing keys {sorted(missing)}"))
    if data.get("schema") != SCHEMA:
        errors.append(err("schema", f"schema must be {SCHEMA}"))
    if data.get("rule") != rf.rel:
        errors.append(err("schema", f"rule must be {rf.rel!r}, got {data.get('rule')!r}"))
    if data.get("engine") != rf.engine:
        errors.append(err("schema", f"engine must be {rf.engine!r} for this file"))

    # rule id
    if rf.engine == "sigma":
        doc = pack.titled_doc(rf)
        want_id = str(doc.get("id")) if doc and doc.get("id") is not None else None
    else:
        want_id = None
    if data.get("rule_id") != want_id:
        errors.append(err("rule-id-mismatch", f"rule_id is {data.get('rule_id')!r}; the rule's id is {want_id!r}"))

    # digest pin
    pinned = data.get("rule_sha256")
    rec["pinned_sha256"] = pinned if isinstance(pinned, str) else None
    if not isinstance(pinned, str) or not SHA_RE.match(pinned):
        errors.append(err("schema", "rule_sha256 must be 64 lowercase hex characters"))
    elif pinned != rf.sha256:
        rec["stale"] = True

    rec["reviewed"] = _date_str(data.get("reviewed"))
    if rec["reviewed"] is None:
        errors.append(err("schema", "reviewed must be a YYYY-MM-DD date"))

    # writeup binding
    writeup = data.get("writeup")
    refs = pack.writeup_refs(rf)
    rec["writeup"] = writeup if isinstance(writeup, str) else None
    if writeup is None:
        if refs:
            errors.append(err("writeup-mismatch", f"the rule references {sorted(refs)}; writeup must name it"))
    elif not isinstance(writeup, str) or writeup not in refs:
        errors.append(err("writeup-mismatch", f"writeup {writeup!r} is not referenced by the rule (references: {sorted(refs)})"))
    elif ctx.writeup_text(writeup) is None:
        errors.append(err("writeup-mismatch", f"{writeup} does not exist upstream"))

    defaults = data.get("event_defaults") or {}
    if not isinstance(defaults, dict) or not all(isinstance(k, str) and _valid_value(v, k) for k, v in defaults.items()):
        errors.append(err("schema", "event_defaults must be a flat mapping of str, int or null"))
        defaults = {}

    # compile once
    sql = None
    fields, numeric, is_corr = set(), set(), False
    if rf.engine == "sigma":
        try:
            sql, fields, numeric, is_corr = engine.compile_rule(rf.text)
        except engine.Unsupported as exc:
            errors.append(err("unsupported", str(exc)))

    rule_hay = pack.rule_haystacks(rf)
    bullets = pack.falsepositive_bullets(rf)
    claims = data.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append(err("schema", "claims must be a non-empty list"))
        claims = []

    seen_ids = set()
    fp_quotes: list[tuple[str, str, str]] = []  # (claim id, normalized quote, result)
    for idx, c in enumerate(claims):
        if not isinstance(c, dict):
            errors.append(err("schema", f"claim {idx} must be a mapping"))
            continue
        cid = c.get("id") if isinstance(c.get("id"), str) else f"#{idx}"
        kind = c.get("kind")
        expect = c.get("expect")

        bad_keys = set(c) - CLAIM_KEYS
        if bad_keys:
            errors.append(err("schema", f"unknown keys {sorted(bad_keys)}", cid))
        if cid in seen_ids:
            errors.append(err("schema", "duplicate claim id", cid))
        seen_ids.add(cid)
        if kind not in KINDS:
            errors.append(err("schema", f"unknown kind {kind!r}", cid))
            continue
        if not re.fullmatch(rf"{re.escape(kind)}/[a-z0-9][a-z0-9-]*", cid):
            errors.append(err("schema", f"id must look like {kind}/<slug>", cid))
        allowed_expect, quote_rule = KINDS[kind]
        if expect not in allowed_expect:
            errors.append(err("schema", f"kind {kind} requires expect {sorted(allowed_expect)}, got {expect!r}", cid))
        rec["counts"][kind] += 1

        # per-kind fields
        if kind == "near-miss" and not isinstance(c.get("rationale"), str):
            errors.append(err("schema", "near-miss needs a rationale", cid))
        if "rationale" in c and not isinstance(c.get("rationale"), str):
            errors.append(err("schema", "rationale must be a string", cid))
        if kind == "undocumented":
            if not isinstance(c.get("summary"), str):
                errors.append(err("schema", "undocumented needs a summary", cid))
            if c.get("confidence") not in CONFIDENCE:
                errors.append(err("schema", f"confidence must be one of {sorted(CONFIDENCE)}", cid))
            up = c.get("upstream")
            if not (up == "pending" or (isinstance(up, str) and UPSTREAM_RE.match(up))):
                errors.append(err("schema", "upstream must be an issue URL or the string pending", cid))
        else:
            for k in ("summary", "confidence", "upstream"):
                if k in c:
                    errors.append(err("schema", f"{k} is only for undocumented claims", cid))
        mode = c.get("mode", "sequence" if is_corr else "each")
        if mode not in ("each", "sequence"):
            errors.append(err("schema", "mode must be each or sequence", cid))
        telemetry = c.get("telemetry", {"shape": "assumed"})
        if (not isinstance(telemetry, dict) or set(telemetry) - {"shape", "source"}
                or telemetry.get("shape") not in ("assumed", "documented")
                or (telemetry.get("shape") == "documented"
                    and not str(telemetry.get("source", "")).startswith("https://"))):
            errors.append(err("schema", "telemetry is {shape: assumed} or {shape: documented, source: https://...}", cid))
        if rf.engine == "kusto":
            table = c.get("table")
            if not isinstance(table, str) or not re.search(rf"\b{re.escape(table)}\b", kql_body(rf.text)):
                errors.append(err("schema", "kusto claims need a table that the query reads", cid))
        elif "table" in c:
            errors.append(err("schema", "table is only for kusto claims", cid))

        # quote
        quote = c.get("quote")
        qtext, qsrc = None, None
        if quote_rule == "forbidden" and quote is not None:
            errors.append(err("schema", "undocumented claims carry no quote", cid))
        elif quote is None:
            if quote_rule == "required":
                errors.append(err("schema", f"{kind} needs a quote", cid))
        elif (not isinstance(quote, dict) or set(quote) != {"source", "text"}
              or quote.get("source") not in ("rule", "writeup") or not isinstance(quote.get("text"), str)):
            errors.append(err("schema", "quote is {source: rule|writeup, text: ...}", cid))
        else:
            qsrc, qtext = quote["source"], pack.normalize(quote["text"])
            if not qtext:
                errors.append(err("schema", "empty quote", cid))
            elif kind == "false-positive":
                if qsrc != "rule":
                    errors.append(err("schema", "false-positive quotes must have source: rule", cid))
                elif not any(qtext in b for b in bullets):
                    errors.append(err("quote-not-found", f"not in any falsepositives bullet: {qtext!r}", cid))
            elif qsrc == "rule":
                if not any(qtext in h for h in rule_hay):
                    errors.append(err("quote-not-found", f"source rule: {qtext!r}", cid))
            else:
                if not isinstance(writeup, str):
                    errors.append(err("schema", "source: writeup needs the file's writeup to be set", cid))
                else:
                    hay = ctx.writeup_text(writeup)
                    if hay is not None and qtext not in hay:
                        errors.append(err("quote-not-found", f"source {writeup}: {qtext!r}", cid))

        # events; a quote or kind error does not stop execution, an event error does
        ev_before = len(errors)
        events = build_events(c, defaults, errors, cid)
        if not events:
            errors.append(err("schema", "a claim needs at least one event", cid))
        check_events(events, fields, numeric, rf, errors, cid)
        events_ok = len(errors) == ev_before

        out = {
            "id": cid,
            "kind": kind,
            "expect": expect,
            "mode": mode,
            "quote": qtext,
            "quote_source": qsrc,
            "telemetry": telemetry if isinstance(telemetry, dict) else None,
            "events": [{**defaults, **e} for e in (c.get("events") if isinstance(c.get("events"), list) else [])
                       if isinstance(e, dict)],
            "generated": c.get("generate"),
            "result": None,
            "actual": None,
        }
        for k in ("rationale", "summary", "confidence", "upstream", "table"):
            if k in c:
                out[k] = c[k]

        # execute
        if rf.engine == "kusto":
            out["result"] = "not-executed"
            out["reason"] = KUSTO_REASON
        elif sql is None or not events_ok or expect not in ("match", "no-match") or mode not in ("each", "sequence"):
            out["result"] = "error"
        else:
            want = expect == "match"
            try:
                if mode == "sequence":
                    got = [engine.evaluate(sql, fields, events)]
                    offenders = [] if got[0] == want else [0]
                    out["actual"] = _verdict(got[0])
                else:
                    got = [engine.evaluate(sql, fields, [e]) for e in events]
                    offenders = [i for i, g in enumerate(got) if g != want]
                    out["actual"] = [_verdict(g) for g in got]
            except sqlite3.Error as exc:  # a backstop; check_events should have caught the cause
                out["result"] = "error"
                out["actual"] = None
                errors.append(err("engine-error", f"{cid}: SQLite could not evaluate the events: {exc}", cid))
            else:
                out["result"] = "fail" if offenders else "pass"
            if out["result"] == "fail":
                first = events[offenders[0]] if mode == "each" else events[0]
                note = first.get("_note") or "(no _note)"
                where = f"event {offenders[0]}" if mode == "each" else "event set"
                errors.append(err(
                    "claim-failed",
                    f"{cid}: expected {expect}, got {_verdict(not want)} on {where}; first offending event: {note}",
                    cid,
                ))
        if kind == "false-positive" and qtext:
            fp_quotes.append((cid, qtext, out["result"]))
        if kind == "undocumented":
            rec["findings"].append({
                "claim": cid,
                "summary": c.get("summary"),
                "confidence": c.get("confidence"),
                "upstream": c.get("upstream"),
                "expect": expect,
                "result": out["result"],
            })
        rec["claims"].append(out)

    # falsepositives coverage: a Sigma rule's falsepositives bullets, or a KQL query's
    # `// False positive:` comment lines (pack.falsepositive_bullets)
    disps = data.get("fp_dispositions") or []
    if not isinstance(disps, list):
        errors.append(err("schema", "fp_dispositions must be a list"))
        disps = []
    norm_disps = []
    for d in disps:
        if (not isinstance(d, dict) or set(d) != {"bullet", "disposition", "reason"}
                or d.get("disposition") not in FP_DISPOSITIONS
                or not isinstance(d.get("bullet"), str) or not isinstance(d.get("reason"), str)):
            errors.append(err("schema", f"fp_dispositions entries are {{bullet, disposition ({'|'.join(sorted(FP_DISPOSITIONS))}), reason}}"))
            continue
        norm_disps.append((pack.normalize(d["bullet"]), d))

    # Each quote and each disposition must pick out exactly one bullet, so a new upstream
    # bullet that repeats an old one's words cannot inherit its proof or disposition.
    for cid, q, _ in fp_quotes:
        n = sum(1 for b in bullets if q in b)
        if n > 1:
            errors.append(err("ambiguous-entry", f"quote is in {n} falsepositives bullets, it must pick out one: {q!r}", cid))
    for nb, _ in norm_disps:
        n = sum(1 for b in bullets if nb and b.startswith(nb))
        if n == 0:
            errors.append(err("schema", f"fp_disposition matches no falsepositives bullet: {nb!r}"))
        elif n > 1:
            errors.append(err("ambiguous-entry", f"fp_disposition starts {n} falsepositives bullets, it must pick out one: {nb!r}"))

    cov = rec["coverage"]["falsepositives"]
    for b in bullets:
        quoted = [(cid, res) for cid, q, res in fp_quotes if q in b]
        proved_by = [cid for cid, res in quoted if res == "pass"]
        # A KQL claim is never executed, so it neither proves nor fails its bullet.
        not_executed_by = [cid for cid, res in quoted if res == "not-executed"]
        failed_by = [cid for cid, res in quoted if res not in ("pass", "not-executed")]
        disps_here = [d for nb, d in norm_disps if nb and b.startswith(nb)]
        disp = disps_here[0] if disps_here else None
        if len(disps_here) > 1:
            errors.append(err("schema", f"{len(disps_here)} fp_dispositions match one bullet: {b!r}"))
        entry = {"text": b, "proved_by": proved_by, "failed_by": failed_by,
                 "not_executed_by": not_executed_by, "disposition": None}
        cov["total"] += 1
        if proved_by:
            cov["proved"] += 1
        elif disp is not None:
            cov["dispositioned"] += 1
            entry["disposition"] = {"disposition": disp["disposition"], "reason": disp["reason"]}
        elif failed_by:
            # claim-failed (or the claim's own error) already makes the rule failing
            cov["failed"] += 1
        elif not_executed_by:
            cov["not_executed"] += 1
        else:
            errors.append(err("fp-uncovered", f"no false-positive claim or disposition covers: {b!r}"))
        cov["bullets"].append(entry)
    return rec


# --------------------------------------------------------------------------- writeup ledgers


def check_ledger(rel: str, ledger_path: Path, ctx: Context, claim_index: dict) -> dict:
    errors: list[dict] = []
    path = ctx.upstream / rel
    rec = {
        "writeup": rel,
        "sha256": pack.sha256_file(path) if path.is_file() else None,
        "ledger": f"claims/_writeups/{Path(rel).stem}.yml",
        "section": "Honest limitations",
        "sentences": [],
        "counts": {"total": 0, "tested": 0, "failed": 0, "dispositioned": 0, "unaccounted": 0},
        "errors": errors,
    }
    if not path.is_file():
        errors.append(err("writeup-mismatch", f"{rel} does not exist upstream"))
        return rec

    data, entries = None, []
    if not ledger_path.is_file():
        errors.append(err("schema", f"no writeup ledger at {rec['ledger']}"))
    else:
        try:
            data = load_yaml(ledger_path)
        except (OSError, yaml.YAMLError) as exc:
            errors.append(err("schema", f"cannot parse {ledger_path.name}: {exc}"))
        if data is not None:
            if not isinstance(data, dict) or set(data) != {"schema", "writeup", "section", "sentences"}:
                errors.append(err("schema", "a ledger has exactly: schema, writeup, section, sentences"))
                data = data if isinstance(data, dict) else {}
            if data.get("schema") != WRITEUP_SCHEMA:
                errors.append(err("schema", f"schema must be {WRITEUP_SCHEMA}"))
            if data.get("writeup") != rel:
                errors.append(err("writeup-mismatch", f"ledger writeup must be {rel!r}"))
            if isinstance(data.get("section"), str):
                rec["section"] = data["section"]
            entries = data.get("sentences") if isinstance(data.get("sentences"), list) else []

    section = pack.writeup_section(path, rec["section"])
    if section is None:
        errors.append(err("writeup-mismatch", f"{rel} has no h2-h4 section titled {rec['section']!r}"))
        return rec
    sentences = pack.split_sentences(section)
    matches: list[list[int]] = [[] for _ in sentences]
    proven: set[int] = set()  # tested entries whose claims all exist, quote this writeup and pass

    for n, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("starts"), str):
            errors.append(err("schema", f"ledger entry {n} needs starts"))
            continue
        starts = pack.normalize(e["starts"])
        disp = e.get("disposition")
        allowed = {"starts", "disposition", "claims", "reason"}
        if set(e) - allowed:
            errors.append(err("schema", f"ledger entry {starts!r}: unknown keys {sorted(set(e) - allowed)}"))
        if disp not in SENTENCE_DISPOSITIONS:
            errors.append(err("schema", f"ledger entry {starts!r}: disposition must be one of {sorted(SENTENCE_DISPOSITIONS)}"))
        hit = [i for i, s in enumerate(sentences) if starts and s.startswith(starts)]
        if not hit:
            errors.append(err("writeup-entry-stale", f"no sentence in {rel} starts with {starts!r}"))
        elif len(hit) > 1:
            # A new sentence that begins like an old one must not inherit the old disposition.
            errors.append(err("ambiguous-entry", f"{len(hit)} sentences in {rel} start with {starts!r}; "
                                                 f"lengthen starts so it picks out one"))
        for i in hit:
            matches[i].append(n)
        if disp == "tested":
            ids = e.get("claims")
            ok = bool(hit)
            if not isinstance(ids, list) or not ids:
                errors.append(err("schema", f"tested entry {starts!r} must list claims"))
                ids, ok = [], False
            for gid in ids:
                c = claim_index.get(gid)
                if c is None:
                    errors.append(err("schema", f"tested entry {starts!r} names unknown claim {gid!r}"))
                    ok = False
                    continue
                if c["quote_source"] != "writeup" or c["writeup"] != rel:
                    errors.append(err("schema", f"claim {gid} must quote {rel} to test this sentence"))
                    ok = False
                elif not any(c["quote"] in sentences[i] or sentences[i] in c["quote"] for i in hit):
                    errors.append(err("schema", f"claim {gid} quotes a different sentence"))
                    ok = False
                if c["result"] != "pass":
                    errors.append(err("claim-failed", f"tested entry {starts!r} relies on claim {gid}, which did not pass", gid))
                    ok = False
            if ok:
                proven.add(n)
            if "reason" in e and not isinstance(e["reason"], str):
                errors.append(err("schema", f"ledger entry {starts!r}: reason must be a string"))
        elif disp in SENTENCE_DISPOSITIONS:
            if not isinstance(e.get("reason"), str) or not e["reason"].strip():
                errors.append(err("schema", f"ledger entry {starts!r}: {disp} needs a reason"))
            if "claims" in e:
                errors.append(err("schema", f"ledger entry {starts!r}: only tested entries list claims"))

    for i, s in enumerate(sentences):
        rec["counts"]["total"] += 1
        hit = matches[i]
        row = {"text": s, "disposition": None, "claims": [], "reason": None, "proved": None}
        if not hit:
            rec["counts"]["unaccounted"] += 1
            errors.append(err("writeup-sentence-unaccounted", f"{rel}: {s!r}"))
        elif len(hit) > 1:
            errors.append(err("schema", f"{rel}: sentence matched by {len(hit)} entries: {s!r}"))
        if hit:
            e = entries[hit[0]]
            row["disposition"] = e.get("disposition")
            row["claims"] = list(e.get("claims") or [])
            row["reason"] = e.get("reason")
            if row["disposition"] == "tested":
                row["proved"] = hit[0] in proven
                rec["counts"]["tested" if row["proved"] else "failed"] += 1
            else:
                rec["counts"]["dispositioned"] += 1
        rec["sentences"].append(row)
    return rec


# --------------------------------------------------------------------------- whole ledger


def status_of(rec: dict) -> str:
    if any(e["code"] == "no-claims-file" for e in rec["errors"]):
        return "unclaimed"
    if rec.get("stale"):
        return "stale"
    if rec["errors"]:
        return "failing"
    if rec["engine"] == "kusto":
        return "not-executed"
    return "verified"


def evaluate_all(upstream: Path, claims_dir: Path, only: list[str] | None = None) -> dict:
    ctx = Context(upstream)
    files = pack.discover(upstream)
    by_id = {rf.id: rf for rf in files}
    claim_files = {p.stem: p for p in sorted(Path(claims_dir).glob("*.yml"))}
    claim_files.update({p.stem: p for p in sorted(Path(claims_dir).glob("*.yaml"))})

    rules: dict[str, dict] = {}
    for rf in files:
        if rf.id in rules:
            rules[rf.id]["errors"].append(err("schema", f"two upstream files share the id {rf.id}: {rf.rel}"))
            continue
        cp = claim_files.get(rf.id)
        if cp is None:
            rules[rf.id] = {
                "file": rf.rel, "engine": rf.engine, "sha256": rf.sha256, "pinned_sha256": None,
                "stale": False, "status": None, "errors": [err("no-claims-file", f"claims/{rf.id}.yml is missing")],
                "counts": {k: 0 for k in KIND_ORDER},
                "coverage": {"falsepositives": {"total": len(pack.falsepositive_bullets(rf)), "proved": 0,
                                                "dispositioned": 0, "failed": 0, "not_executed": 0,
                                                "bullets": []}},
                "lint": lint.lint(rf), "findings": [], "claims": [], "writeup": None, "reviewed": None,
                "claims_url": None, "mapper_url": MAPPER_URL.format(stem=rf.id),
            }
        else:
            rules[rf.id] = check_rule(rf, cp, ctx)

    orphans = {}
    for stem, cp in claim_files.items():
        if stem not in by_id:
            orphans[stem] = {"claims_file": f"claims/{cp.name}",
                             "errors": [err("orphan-claims-file", f"no upstream rule named {stem}")]}

    # claim index for ledgers: "<stem>/<claim id>"
    index = {}
    for stem, rec in rules.items():
        for c in rec["claims"]:
            index[f"{stem}/{c['id']}"] = {**c, "writeup": rec["writeup"]}

    referenced: dict[str, list[str]] = {}
    for stem, rec in rules.items():
        if rec["writeup"]:
            referenced.setdefault(rec["writeup"], []).append(stem)
    writeups = {}
    for rel in sorted(referenced):
        slug = Path(rel).stem
        wrec = check_ledger(rel, Path(claims_dir) / "_writeups" / f"{slug}.yml", ctx, index)
        wrec["rules"] = sorted(referenced[rel])
        writeups[slug] = wrec
        for stem in referenced[rel]:
            for e in wrec["errors"]:
                rules[stem]["errors"].append({**e, "ledger": wrec["ledger"]})
    wdir = Path(claims_dir) / "_writeups"
    for p in sorted(wdir.glob("*.yml")) if wdir.is_dir() else []:
        if p.stem not in writeups:
            writeups[p.stem] = {
                "writeup": None, "ledger": f"claims/_writeups/{p.name}", "sentences": [], "rules": [],
                "counts": {"total": 0, "tested": 0, "failed": 0, "dispositioned": 0, "unaccounted": 0},
                "errors": [err("orphan-claims-file", "no claims file references this writeup")],
            }

    for rec in rules.values():
        rec["status"] = status_of(rec)

    if only:
        keep = set(only)
        rules = {k: v for k, v in rules.items() if k in keep}
        orphans = {k: v for k, v in orphans.items() if k in keep}
        writeups = {k: v for k, v in writeups.items() if set(v["rules"]) & keep}

    return {"files": files, "rules": rules, "orphans": orphans, "writeups": writeups,
            "summary": summarize(rules, orphans, writeups)}


def summarize(rules: dict, orphans: dict, writeups: dict) -> dict:
    statuses = [r["status"] for r in rules.values()]
    claims = [c for r in rules.values() for c in r["claims"]]
    by_kind = {k: sum(r["counts"][k] for r in rules.values()) for k in KIND_ORDER}
    fp = {k: sum(r["coverage"]["falsepositives"][k] for r in rules.values())
          for k in ("total", "proved", "dispositioned", "failed", "not_executed")}
    fp["uncovered"] = fp["total"] - fp["proved"] - fp["dispositioned"] - fp["failed"] - fp["not_executed"]
    ws = {k: sum(w["counts"][k] for w in writeups.values())
          for k in ("total", "tested", "failed", "dispositioned", "unaccounted")}
    writeup_errors = sum(1 for w in writeups.values() if w["errors"])
    summary = {
        "rules": len(rules),
        "verified": statuses.count("verified"),
        "not_executed": statuses.count("not-executed"),
        "stale": statuses.count("stale"),
        "failing": statuses.count("failing"),
        "unclaimed": statuses.count("unclaimed"),
        "orphan": len(orphans),
        "claims": len(claims),
        "executed": sum(1 for c in claims if c["result"] in ("pass", "fail")),
        "passed": sum(1 for c in claims if c["result"] == "pass"),
        "failed": sum(1 for c in claims if c["result"] == "fail"),
        "not_executed_claims": sum(1 for c in claims if c["result"] == "not-executed"),
        "by_kind": by_kind,
        "falsepositives": fp,
        "writeup_sentences": ws,
    }
    summary["ok"] = (
        bool(rules)
        and all(s in ("verified", "not-executed") for s in statuses)
        and not orphans
        and writeup_errors == 0
    )
    return summary
