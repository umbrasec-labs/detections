"""Self-tests for the claims harness.

Toy rules are Python dicts written to temporary directories at runtime, laid out
like tools/sigma-pack and research/. No rule YAML is committed (see harness.guard).
Test 12 runs only when UMBRASEC_UPSTREAM points at an umbrasec.dev checkout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness import claims as C  # noqa: E402
from harness import engine, guard, lint, pack  # noqa: E402

TOY_ID = "11111111-1111-4111-8111-111111111111"
TOY_REL = "rules/proxy/toy.yml"
WRITEUP_HTML = """<!doctype html>
<html><body><article>
<h2>How it works</h2>
<p>The toy rule watches requests to the toy host.</p>
<h2>Honest limitations</h2>
<p>The toy rule sees only the host header. A request without one sails past it.</p>
<pre>not prose, never split</pre>
<h2>References</h2>
<p>None.</p>
</article></body></html>
"""


def toy_rule(**over) -> dict:
    rule = {
        "title": "Toy host rule",
        "id": TOY_ID,
        "status": "test",
        "description": "A request to the toy host example.test. It is a test fixture.",
        "references": ["https://umbrasec.dev/research/toy.html"],
        "author": "tests",
        "logsource": {"category": "proxy"},
        "detection": {"selection": {"cs-host": "example.test"}, "condition": "selection"},
        "falsepositives": ["Health checks from the load balancer"],
    }
    rule.update(over)
    return rule


def toy_claims(sha: str, **over) -> dict:
    doc = {
        "schema": C.SCHEMA,
        "rule": TOY_REL,
        "rule_id": TOY_ID,
        "rule_sha256": sha,
        "engine": "sigma",
        "writeup": "research/toy.html",
        "reviewed": "2026-10-23",
        "event_defaults": {"_synthetic": True},
        "fp_dispositions": [],
        "claims": [
            {"id": "catches/toy-host", "kind": "catches", "expect": "match",
             "quote": {"source": "rule", "text": "A request to the toy host example.test."},
             "events": [{"_note": "plain request", "cs-host": "example.test"}]},
            {"id": "false-positive/health-check", "kind": "false-positive", "expect": "match",
             "quote": {"source": "rule", "text": "Health checks from the load balancer"},
             "events": [{"_note": "load balancer probe", "cs-host": "example.test"}]},
            {"id": "blind-spot/no-host-header", "kind": "blind-spot", "expect": "no-match",
             "quote": {"source": "writeup", "text": "A request without one sails past it."},
             "events": [{"_note": "no host header logged", "cs-host": None, "c-uri": "http://example.test/"}]},
            {"id": "near-miss/other-host", "kind": "near-miss", "expect": "no-match",
             "rationale": "A different host", "events": [{"_note": "other host", "cs-host": "other.test"}]},
        ],
    }
    doc.update(over)
    return doc


def toy_ledger(**over) -> dict:
    doc = {
        "schema": C.WRITEUP_SCHEMA,
        "writeup": "research/toy.html",
        "section": "Honest limitations",
        "sentences": [
            {"starts": "The toy rule sees only the host header.", "disposition": "context", "reason": "Scope"},
            {"starts": "A request without one", "disposition": "tested", "claims": ["toy/blind-spot/no-host-header"]},
        ],
    }
    doc.update(over)
    return doc


class Toy:
    """A temporary upstream checkout plus a claims directory."""

    def __init__(self, rule=None, claims=None, ledger=None):
        self.tmp = Path(tempfile.mkdtemp(prefix="claims-test-"))
        self.upstream = self.tmp / "upstream"
        self.claims_dir = self.tmp / "claims"
        self.out = self.tmp / "out"
        self.rule_path = self.upstream / pack.PACK_PATH / TOY_REL
        self.rule_path.parent.mkdir(parents=True)
        (self.upstream / "research").mkdir()
        (self.upstream / "research" / "toy.html").write_text(WRITEUP_HTML, encoding="utf-8")
        (self.claims_dir / "_writeups").mkdir(parents=True)
        self.write_rule(rule or toy_rule())
        self.write_claims(claims or toy_claims(self.sha))
        self.write_ledger(ledger or toy_ledger())

    @property
    def sha(self) -> str:
        return pack.sha256_file(self.rule_path)

    def write_rule(self, rule) -> None:
        text = rule if isinstance(rule, str) else yaml.safe_dump(rule, sort_keys=False)
        self.rule_path.write_text(text, encoding="utf-8")

    def write_claims(self, doc: dict) -> None:
        (self.claims_dir / "toy.yml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    def write_ledger(self, doc: dict) -> None:
        (self.claims_dir / "_writeups" / "toy.yml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    def evaluate(self) -> dict:
        return C.evaluate_all(self.upstream, self.claims_dir)

    def run(self, *extra):
        proc = subprocess.run(
            [sys.executable, "-m", "harness.run", "--upstream", str(self.upstream), "--claims", str(self.claims_dir),
             "--out", str(self.out), *extra],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        record = None
        if (self.out / "claims.json").exists():
            record = json.loads((self.out / "claims.json").read_text(encoding="utf-8"))
        return proc.returncode, proc.stdout + proc.stderr, record

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


def codes(result: dict, stem: str = "toy") -> set[str]:
    return {e["code"] for e in result["rules"][stem]["errors"]}


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.toy = Toy()

    def tearDown(self):
        self.toy.cleanup()

    def test_01_wrong_expect_fails_and_names_claim(self):
        rc, out, rec = self.toy.run()
        self.assertEqual(rc, 0, out)
        self.assertEqual(rec["rules"]["toy"]["status"], "verified")
        doc = toy_claims(self.toy.sha)
        doc["claims"][0]["expect"] = "no-match"
        self.toy.write_claims(doc)
        rc, out, rec = self.toy.run()
        self.assertEqual(rc, 1)
        self.assertIn("claim-failed", out)
        self.assertIn("catches/toy-host", out)
        self.assertEqual(rec["rules"]["toy"]["status"], "failing")
        failed = [e for e in rec["rules"]["toy"]["errors"] if e["code"] == "claim-failed"]
        self.assertEqual(failed[0]["claim"], "catches/toy-host")
        self.assertIn("plain request", failed[0]["message"])

    def test_02_sha_mismatch_is_stale(self):
        self.toy.write_claims(toy_claims("0" * 64))
        rc, out, rec = self.toy.run()
        self.assertEqual(rc, 1)
        r = rec["rules"]["toy"]
        self.assertEqual(r["status"], "stale")
        self.assertEqual(r["pinned_sha256"], "0" * 64)
        # Claims are still executed and shown while stale.
        self.assertTrue(all(c["result"] == "pass" for c in r["claims"]))
        self.assertEqual(rec["summary"]["stale"], 1)

    def test_03_missing_quote(self):
        doc = toy_claims(self.toy.sha)
        doc["claims"][0]["quote"]["text"] = "A sentence the rule never says."
        doc["claims"][2]["quote"]["text"] = "A sentence the writeup never says."
        doc["claims"][3]["events"][0]["_synthetic"] = False
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        errs = res["rules"]["toy"]["errors"]
        missing = [e for e in errs if e["code"] == "quote-not-found"]
        self.assertEqual({e["claim"] for e in missing}, {"catches/toy-host", "blind-spot/no-host-header"})
        self.assertTrue(any("research/toy.html" in e["message"] for e in missing))
        self.assertIn("not-synthetic", codes(res))
        self.assertEqual(res["rules"]["toy"]["status"], "failing")

    def test_04_fp_uncovered_and_disposition(self):
        doc = toy_claims(self.toy.sha)
        doc["claims"] = [c for c in doc["claims"] if c["kind"] != "false-positive"]
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        self.assertIn("fp-uncovered", codes(res))
        doc["fp_dispositions"] = [{"bullet": "Health checks from the load balancer", "disposition": "not-an-event",
                                   "reason": "A test disposition"}]
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        self.assertNotIn("fp-uncovered", codes(res))
        self.assertEqual(res["rules"]["toy"]["status"], "verified")
        self.assertEqual(res["rules"]["toy"]["coverage"]["falsepositives"]["dispositioned"], 1)
        # A false-positive claim that fails proves nothing, so its bullet is not counted as proved.
        doc = toy_claims(self.toy.sha)
        doc["claims"][1]["events"][0]["cs-host"] = "other.test"
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        cov = res["rules"]["toy"]["coverage"]["falsepositives"]
        self.assertIn("claim-failed", codes(res))
        self.assertEqual((cov["proved"], cov["failed"]), (0, 1))
        self.assertEqual((cov["bullets"][0]["proved_by"], cov["bullets"][0]["failed_by"]),
                         ([], ["false-positive/health-check"]))
        self.assertEqual(res["summary"]["falsepositives"]["uncovered"], 0)
        # A quote or a disposition that fits two bullets is ambiguous, so a new bullet
        # cannot inherit an old one's proof or disposition.
        self.toy.write_rule(toy_rule(falsepositives=["Health checks from the load balancer",
                                                     "Health checks from the load balancer pool in staging"]))
        doc = toy_claims(self.toy.sha)
        self.toy.write_claims(doc)
        self.assertIn("ambiguous-entry", codes(self.toy.evaluate()))
        doc["claims"] = [c for c in doc["claims"] if c["kind"] != "false-positive"]
        doc["fp_dispositions"] = [{"bullet": "Health checks", "disposition": "advice", "reason": "A test disposition"}]
        self.toy.write_claims(doc)
        self.assertIn("ambiguous-entry", codes(self.toy.evaluate()))

    def test_05_unaccounted_writeup_sentence(self):
        led = toy_ledger()
        led["sentences"] = led["sentences"][1:] + [
            {"starts": "A sentence that was edited away", "disposition": "context", "reason": "Gone"}]
        self.toy.write_ledger(led)
        res = self.toy.evaluate()
        self.assertIn("writeup-sentence-unaccounted", codes(res))
        self.assertIn("writeup-entry-stale", codes(res))
        self.assertEqual(res["rules"]["toy"]["status"], "failing")
        # The <pre> block is skipped and the section ends at the next heading.
        self.assertEqual(res["writeups"]["toy"]["counts"]["total"], 2)
        # A tested entry whose claim fails is counted as failed, never as tested.
        self.toy.write_ledger(toy_ledger())
        doc = toy_claims(self.toy.sha)
        doc["claims"][2]["events"][0]["cs-host"] = "example.test"
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        self.assertEqual((res["writeups"]["toy"]["counts"]["tested"], res["writeups"]["toy"]["counts"]["failed"]), (0, 1))
        self.assertEqual(res["summary"]["writeup_sentences"]["failed"], 1)
        # A new sentence that starts like an old one makes that entry ambiguous.
        self.toy.write_claims(toy_claims(self.toy.sha))
        html = WRITEUP_HTML.replace("sails past it.", "sails past it. A request without one is rare behind the load balancer.")
        (self.toy.upstream / "research" / "toy.html").write_text(html, encoding="utf-8")
        res = self.toy.evaluate()
        self.assertEqual(res["writeups"]["toy"]["counts"]["total"], 3)
        self.assertIn("ambiguous-entry", codes(res))
        self.assertEqual(res["rules"]["toy"]["status"], "failing")

    def test_06_case_insensitive_equality_and_numeric_fields(self):
        sql, fields, numeric, _ = engine.compile_rule(yaml.safe_dump(toy_rule()))
        self.assertTrue(engine.evaluate(sql, fields, [{"cs-host": "EXAMPLE.test"}]))
        self.assertFalse(engine.evaluate(sql, fields, [{"cs-host": "example.testx"}]))
        num_rule = toy_rule(detection={"selection": {"EventID": 4769, "cs-host": "example.test"}, "condition": "selection"})
        sql, fields, numeric, _ = engine.compile_rule(yaml.safe_dump(num_rule))
        self.assertEqual(numeric, {"EventID"})
        self.assertTrue(engine.evaluate(sql, fields, [{"EventID": 4769, "cs-host": "example.test"}]))
        self.assertFalse(engine.evaluate(sql, fields, [{"EventID": "4769", "cs-host": "example.test"}]))
        # The harness rejects the string form before it can silently miss.
        self.toy.write_rule(num_rule)
        doc = toy_claims(self.toy.sha)
        doc["event_defaults"] = {"_synthetic": True, "EventID": "4769"}
        self.toy.write_claims(doc)
        self.assertIn("numeric-field-as-string", codes(self.toy.evaluate()))
        # The reverse: an int where the rule compares a string can never match, so a
        # no-match claim would pass for the wrong reason. YAML reads unquoted 0x17 as 23.
        self.toy.write_rule(toy_rule())
        doc = toy_claims(self.toy.sha)
        doc["claims"][3]["events"][0]["cs-host"] = yaml.safe_load("0x17")
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        self.assertIn("string-field-as-int", codes(res))
        self.assertEqual(res["rules"]["toy"]["claims"][3]["result"], "error")
        # Two keys of one claim that differ only in case would clash as SQLite columns.
        # The claim is an error, and the run goes on.
        doc = toy_claims(self.toy.sha)
        doc["claims"][3]["events"] = [{"cs-host": "other.test", "X-Test": "a"}, {"cs-host": "other.test", "x-test": "b"}]
        doc["claims"][3]["mode"] = "sequence"
        self.toy.write_claims(doc)
        res = self.toy.evaluate()
        self.assertIn("schema", codes(res))
        self.assertEqual(res["rules"]["toy"]["claims"][3]["result"], "error")
        self.assertEqual(res["rules"]["toy"]["claims"][0]["result"], "pass")

    def test_07_absent_rule_field_still_evaluates(self):
        rule = toy_rule(detection={
            "selection_host": {"cs-host": "example.test"},
            "selection_uri": {"c-uri|contains": "//example.test"},
            "filter_agent": {"cs-user-agent|contains": "healthcheck"},
            "condition": "1 of selection_* and not 1 of filter_*",
        })
        sql, fields, _, _ = engine.compile_rule(yaml.safe_dump(rule))
        self.assertTrue({"c-uri", "cs-user-agent"} <= fields)
        # No c-uri and no cs-user-agent in the event: no "no such column", and the
        # negated filter on an absent field behaves as Sigma says (it does not match).
        self.assertTrue(engine.evaluate(sql, fields, [{"cs-host": "example.test"}]))
        self.assertFalse(engine.evaluate(sql, fields, [{"cs-host": "example.test", "cs-user-agent": "HealthCheck/1"}]))

    def test_08_value_count_correlation(self):
        text = yaml.safe_dump_all([
            {"title": "Toy fan-out", "id": "22222222-2222-4222-8222-222222222222", "status": "test",
             "correlation": {"type": "value_count", "rules": ["toy_base"], "group-by": ["user"],
                             "timespan": "1m", "condition": {"gte": 3, "field": "target"}}},
            {"title": "Toy base", "id": "33333333-3333-4333-8333-333333333333", "name": "toy_base", "status": "test",
             "logsource": {"category": "proxy"},
             "detection": {"selection": {"action": "request"}, "condition": "selection"}},
        ], sort_keys=False)
        sql, fields, _, is_corr = engine.compile_rule(text)
        self.assertTrue(is_corr)

        def events(n, step):
            return [{"action": "request", "user": "alice", "target": f"t{i}",
                     "timestamp": f"2026-10-23T10:{(i * step) // 60:02d}:{(i * step) % 60:02d}Z"} for i in range(n)]

        self.assertTrue(engine.evaluate(sql, fields, events(3, 10)))
        self.assertFalse(engine.evaluate(sql, fields, events(2, 10)))
        self.assertFalse(engine.evaluate(sql, fields, events(3, 40)))

    def test_09_re_modifier_is_unsupported(self):
        rule = toy_rule(detection={"selection": {"cs-host|re": "^example\\.test$"}, "condition": "selection"})
        with self.assertRaises(engine.Unsupported):
            engine.compile_rule(yaml.safe_dump(rule))
        # The backend would compile these, with string values, so only the modifier allowlist stops them.
        for field, value in (("cs-host|windash", "-x"), ("cs-host|contains|all", ["a", "b"]), ("cs-host|cased", "Example")):
            other = toy_rule(detection={"selection": {field: value}, "condition": "selection"})
            with self.subTest(field=field), self.assertRaisesRegex(engine.Unsupported, "modifier"):
                engine.compile_rule(yaml.safe_dump(other))
        self.toy.write_rule(rule)
        self.toy.write_claims(toy_claims(self.toy.sha))
        res = self.toy.evaluate()
        self.assertIn("unsupported", codes(res))
        self.assertTrue(all(c["result"] == "error" for c in res["rules"]["toy"]["claims"]))

    def test_10_lint_flags_bare_wildcard_only(self):
        rule = toy_rule(detection={"selection": {"cs-uri-query|contains": ["/*", "/\\*", "a?b"]}, "condition": "selection"})
        self.toy.write_rule(rule)
        rf = next(f for f in pack.discover(self.toy.upstream) if f.id == "toy")
        found = [x for x in lint.lint(rf) if x["code"] == "unescaped-wildcard"]
        self.assertEqual([(x["path"], x["value"]) for x in found],
                         [("selection.cs-uri-query|contains[0]", "/*"), ("selection.cs-uri-query|contains[2]", "a?b")])
        no_fp = toy_rule()
        del no_fp["falsepositives"]
        self.toy.write_rule(no_fp)
        rf = next(f for f in pack.discover(self.toy.upstream) if f.id == "toy")
        self.assertIn("no-falsepositives", [x["code"] for x in lint.lint(rf)])

    def test_11_guard_rejects_rule_text(self):
        root = self.toy.tmp / "repo"
        (root / "docs").mkdir(parents=True)
        (root / "claims.yml").write_text(yaml.safe_dump({"claims": [{"id": "x"}]}), encoding="utf-8")
        self.assertEqual(guard.scan(root, use_git=False), [])
        (root / "docs" / "rule.yaml").write_text(yaml.safe_dump({"a": [{"b": {"detection": {}}}]}), encoding="utf-8")
        self.assertEqual(len(guard.scan(root, use_git=False)), 1)
        (root / "docs" / "rule.yaml").unlink()
        (root / "q.kql").write_text("AuditLogs | take 1\n", encoding="utf-8")
        self.assertEqual(len(guard.scan(root, use_git=False)), 1)
        (root / "q.kql").unlink()
        # Without git, the walk skips build and checkout folders.
        (root / "out").mkdir()
        (root / "out" / "x.kql").write_text("x\n", encoding="utf-8")
        self.assertEqual(guard.scan(root, use_git=False), [])
        # Rule text in other names and formats.
        rule_doc = yaml.safe_dump({"logsource": {"category": "proxy"}})
        (root / "node_modules").mkdir()
        (root / "node_modules" / "x.yml").write_text(rule_doc, encoding="utf-8")
        (root / "docs" / "x.json").write_text(json.dumps({"detection": {"condition": "selection"}}), encoding="utf-8")
        (root / "docs" / "x.yml.txt").write_text(rule_doc, encoding="utf-8")
        (root / "docs" / "q.kusto").write_text("AuditLogs | take 1\n", encoding="utf-8")
        self.assertEqual(sorted(p.split(":")[0] for p in guard.scan(root, use_git=False)),
                         ["docs/q.kusto", "docs/x.json", "docs/x.yml.txt"])
        # In a git work tree the guard reads git's file list instead, so no folder is
        # skipped by name, and an ignored path is checked once it is force-added.
        if shutil.which("git"):
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            (root / ".gitignore").write_text("out/\n", encoding="utf-8")
            self.assertEqual(sorted(p.split(":")[0] for p in guard.scan(root)),
                             ["docs/q.kusto", "docs/x.json", "docs/x.yml.txt", "node_modules/x.yml"])
            subprocess.run(["git", "-C", str(root), "add", "-f", "out/x.kql"], check=True, capture_output=True)
            self.assertIn("out/x.kql", [p.split(":")[0] for p in guard.scan(root)])
        # And this repo itself is clean.
        self.assertEqual(guard.scan(ROOT), [])

    @unittest.skipUnless(os.environ.get("UMBRASEC_UPSTREAM"), "set UMBRASEC_UPSTREAM to an umbrasec.dev checkout")
    def test_12_real_pack_one_byte_change_is_stale(self):
        # Compares against a baseline run on the same copy, so upstream drift that has
        # already made some rules stale or failing does not fail this test.
        src = Path(os.environ["UMBRASEC_UPSTREAM"])
        dst = self.toy.tmp / "pack-copy"
        shutil.copytree(src / pack.PACK_PATH, dst / pack.PACK_PATH)
        shutil.copytree(src / "research", dst / "research")

        def run(name):
            out = self.toy.tmp / name
            proc = subprocess.run([sys.executable, "-m", "harness.run", "--upstream", str(dst), "--out", str(out)],
                                  cwd=ROOT, capture_output=True, text=True, timeout=300)
            rec = json.loads((out / "claims.json").read_text(encoding="utf-8"))
            return proc, rec, {k: v["status"] for k, v in rec["rules"].items()}

        _, _, before = run("pack-base")
        files = {rf.id: rf for rf in pack.discover(dst)}
        # Prefer a verified rule; any claimed rule that is not already stale will do.
        candidates = sorted(k for k, s in before.items() if s == "verified") or \
            sorted(k for k, s in before.items() if s in ("failing", "not-executed"))
        if not candidates:
            self.skipTest(f"no claimed, non-stale rule to mutate: {before}")
        stem = candidates[0]
        target = files[stem].path
        raw = target.read_bytes()
        # Change exactly one byte, chosen by offset: the last one.
        changed = raw[:-1] + (b" " if raw[-1:] == b"\n" else b"\n")
        self.assertEqual(len(changed), len(raw))
        self.assertEqual(sum(a != b for a, b in zip(raw, changed)), 1)
        target.write_bytes(changed)

        proc, rec, after = run("pack-out")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(after[stem], "stale")
        self.assertEqual({k: v for k, v in after.items() if k != stem},
                         {k: v for k, v in before.items() if k != stem})
        self.assertFalse(rec["ok"])

    def test_13_claims_json_shape_and_determinism(self):
        rc, out, first = self.toy.run()
        self.assertEqual(rc, 0, out)
        for key in ("schema", "generated_at", "ok", "harness", "engine", "sigma_pack", "summary", "rules"):
            self.assertIn(key, first)
        for key in ("repo", "commit", "version"):
            self.assertIn(key, first["harness"])
        for key in ("pysigma", "backend", "sqlite", "python", "semantics"):
            self.assertIn(key, first["engine"])
        for key in ("rules", "verified", "not_executed", "stale", "failing", "unclaimed", "claims", "passed",
                    "by_kind", "falsepositives", "writeup_sentences"):
            self.assertIn(key, first["summary"])
        for name in ("claims.json", "REPORT.md", "subjects.sha256", "predicate.json"):
            self.assertTrue((self.toy.out / name).is_file(), name)
        subjects = (self.toy.out / "subjects.sha256").read_text(encoding="utf-8").splitlines()
        self.assertEqual(subjects[0], f"{self.toy.sha}  {pack.PACK_PATH}/{TOY_REL}")
        self.assertTrue(subjects[-1].endswith("  claims.json"))
        rc, out, second = self.toy.run()
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
