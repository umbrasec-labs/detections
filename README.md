# detections: the Claims Ledger

This repo holds no detection rules. It holds *claims* about the canonical UMBRASEC sigma-pack rules, which live in [umbrasec.dev/tools/sigma-pack](https://github.com/umbrasec-labs/umbrasec.dev/tree/master/tools/sigma-pack). Each claim is a sentence the rule or its writeup says about itself: what it catches, what harmless activity trips it, what it cannot see. CI re-proves every claim, using labelled synthetic events, against the live sigma-pack bytes. The resulting record is signed for the exact rule digests.

## What a claim is

Each upstream rule has one claims file in `claims/`, with the same file stem. A claim has a kind, an expected verdict and one or more synthetic events. Catches, false-positive, blind-spot and excluded claims also carry a quote from the canonical prose. A near-miss claim carries a `rationale` instead (a quote is optional), and an undocumented claim carries `summary`, `confidence` and `upstream` and never a quote.

| Kind | Expect | What it shows |
|---|---|---|
| `catches` | match | The rule fires on the activity it says it detects. |
| `false-positive` | match | A harmless activity from the rule's `falsepositives` list trips the rule. |
| `blind-spot` | no-match | A limitation that the rule or its writeup admits is real. |
| `excluded` | no-match | A deliberate exclusion holds, as the rule's prose or an inline comment explains it. |
| `near-miss` | no-match | Activity close to the selection stays quiet. |
| `undocumented` | match or no-match | Behaviour the prose does not mention. It pins today's verdict and links an upstream issue. |

A false-positive claim must fire. The rule's own notes say this harmless activity trips it, so a quiet result would mean the note is wrong or the event does not show the activity. A blind-spot claim must stay quiet. If it fired, the limitation would be gone and the prose would be out of date.

Quotes bind each claim to the canonical prose. The harness checks that every quote appears, after whitespace is collapsed, in the rule file or in its writeup. A false-positive quote must come from one of the rule's `falsepositives` bullets; a KQL query has no such field, so its false-positive quotes come from its `// False positive:` comment lines (each with its indented continuation lines is one bullet). When upstream rewords a sentence, the quote stops matching and the rule fails until someone updates the claim.

## The coverage gate

Every `falsepositives` bullet in every Sigma rule, and every `// False positive:` line in a KQL query, is either quoted by a false-positive claim or given a disposition with a reason (`advice`, `lifecycle` or `not-an-event`). A Sigma claim proves its bullet only when it passes; a KQL claim is counted as not executed.

Every sentence in a referenced writeup's "Honest limitations" section has one entry in `claims/_writeups/<slug>.yml`. The entry is either `tested` by a passing claim that quotes that sentence, or dispositioned as `context`, `prerequisite` or `not-reproduced` with a reason. A new bullet or a new sentence upstream fails the gate until someone accounts for it. An entry whose sentence has gone also fails, so prose drift shows up. Each quote, disposition and ledger entry must pick out exactly one bullet or sentence, so a new one cannot inherit an old one's disposition. A bullet or sentence counts as proved only while the claim that tests it passes.

## What this proves and what it does not

- It proves rule logic under Sigma reference semantics, as pySigma compiles each rule to SQLite, on labelled synthetic events. Field shapes are assumed unless a claim cites a source.
- It does not test your SIEM's field mappings or your telemetry. A rule can pass here and still miss in your environment if your sensor names or formats a field differently.
- Case folding is ASCII only. SQLite `NOCASE` and `LIKE` fold A to Z and nothing else.
- The same author writes the rules and the claims, so confirmation bias is possible. Outside claims are welcome.
- A claims file binds one writeup. When two writeups carry the same limitation sentence, only the first writeup's ledger proves it; the second marks its copy `context` with a reason that names the claims, and nothing checks that the two copies stay the same.
- The KQL queries get schema and quote checks and show as `not-executed`. There is no Kusto engine in CI yet.

## Status

The latest results are on the [claims workflow page](https://github.com/umbrasec-labs/detections/actions/workflows/claims.yml). Each run writes `REPORT.md` to its job summary and uploads an artifact named `claims` with `claims.json`, `REPORT.md`, `subjects.sha256` and `predicate.json`.

## Run it locally

```
python3 -m venv .venv && .venv/bin/pip install --require-hashes --no-deps -r requirements.txt
git clone --depth 1 https://github.com/umbrasec-labs/umbrasec.dev _upstream
.venv/bin/python -m harness.run --upstream _upstream --out out
```

Exit 0 means every rule is `verified` or `not-executed`. Read `out/REPORT.md` for the summary. Run the self-tests with `UMBRASEC_UPSTREAM=_upstream .venv/bin/python -m unittest discover -s tests -v`.

## Verify an attestation

On push to main, every Monday and on manual runs from main, CI signs the record as a GitHub artifact attestation. Its subjects are the sha256 digests of the sigma-pack files and of `claims.json`. You can check a rule file you hold against it:

```
gh attestation verify metabase-reset-password-sqli.yml --repo umbrasec-labs/detections \
  --signer-workflow umbrasec-labs/detections/.github/workflows/claims.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners \
  --predicate-type https://umbrasec.dev/attestations/claims/v1
```

Always pass `--predicate-type`. By default `gh attestation verify` looks only for SLSA provenance, and this record uses its own predicate type. `--signer-workflow` and `--source-ref` accept only records that this repo's claims workflow signed on main.

A pass does not mean the rule is verified. Failing and stale runs are signed too. Read the status in the predicate, and use the newest attestation. [docs/verify.md](docs/verify.md) shows how, and how to reproduce a run.

## When an upstream rule changes

The next daily run marks that rule `stale`. Its claims still run and show, but it cannot be `verified` until a human re-reads them. Read the upstream diff, fix any claim the change broke, then re-pin the digest:

```
.venv/bin/python -m harness.relock --upstream _upstream --i-reviewed <stem>
```

`relock` rewrites only the `rule_sha256:` and `reviewed:` lines and keeps comments.

## Consumers

- BlueTeamMapper, in its Detections view.
- umbra-blue (planned).
- The sigma-pack README (planned).

## Findings policy

Findings go upstream as issues on umbrasec.dev. This repo never fixes a rule. An `undocumented` claim pins the current verdict so CI stays green, and its `upstream:` field links the issue, or says `pending` until someone files one.

## Defensive only

Events carry the fewest fields the rule's selection needs, such as a single quote character. They hold no payloads, exploit strings or tool command lines. A limitation that only an evasion payload could show is dispositioned `not-reproduced`.

## Layout

```
claims/<stem>.yml             one claims file per upstream rule or query
claims/_writeups/<slug>.yml   one ledger per referenced writeup
harness/                      the harness: stdlib, PyYAML and pySigma only
tests/test_harness.py         self-tests; toy rules go to temp dirs at runtime
docs/verify.md                outsider verification and reproduction
```

`requirements.txt` pins the full dependency set with a hash for every file PyPI publishes. `python -m harness.lock` regenerates it and refuses a pin if any of its files was uploaded less than 14 days ago.

A `# lock: exclude NAME - REASON` line in `requirements.in` leaves a dependency out of the lock. CI then never installs it. pySigma requires `diskcache`, which has an advisory with no patched release, but only pySigma's MITRE data cache uses it, and the harness never loads that cache. It is excluded, and self-test 14 blocks the import and runs the harness, so any code path that starts needing it fails CI.

A `# lock: allow-young NAME==VERSION sha256:HASH,... - REASON` line waives the cooldown for the listed files of that one exact pin, for a security fix that cannot wait 14 days. A file added to the release later is not covered and still has to clear the cooldown. The lock fails if the pin moves to another version, and again once the release is 14 days old, so the line has to be removed rather than lingering. `certifi==2026.10.19` uses it for GHSA-6q48-6c7w-9gw2, which removes the emSign root CA whose intermediate CA keys were compromised. The harness never uses certifi: only `python -m harness.lock` goes online (PyPI, through stdlib urllib and the system trust store). certifi is installed only because `requests` declares it.

Dependabot (`.github/dependabot.yml`) proposes pip and GitHub Actions updates weekly, grouped into one PR each, with the same 14-day cooldown. Its pip PRs edit `requirements.txt` directly. CI installs with `--require-hashes` and re-proves every claim, so merge one only when CI is green. Security updates skip the cooldown.

## License

MIT. See [LICENSE](LICENSE).
