# Principles

1. **No rule text.** The canonical rules live in umbrasec.dev. `python -m harness.guard` reads every file git tracks or would add. It fails CI on a Kusto file, or on a YAML or JSON document with a `detection`, `logsource` or `correlation` key. It reads YAML under any name that holds `.yml` or `.yaml`. It cannot see rule text pasted into prose or code, so review still matters.
2. **Every event is synthetic and labelled.** Each event carries `_synthetic: true`. Never ship evtx, packet captures or anything that could pass as real evidence.
3. **Every claim quotes the prose it tests.** A near-miss may give a rationale instead. An `undocumented` claim carries an upstream issue link, or `pending` until someone files the issue.
4. **Never fabricate a citation.** A telemetry source must be a document someone actually opened. Without one, the claim's field shape is `assumed`.
5. **Defensive only.** Events hold the minimum fields the rule needs. A limitation that only an evasion payload could show is `not-reproduced`.
6. **Findings go upstream.** This repo records them and never edits a rule.
7. **A rule change makes its claims stale** until a human re-reads them and runs `harness.relock`.
8. **Every result names its engine and semantics.** The record states the pySigma, backend, SQLite and Python versions, and what the run does not prove.
