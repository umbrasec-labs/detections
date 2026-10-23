# Verify the record

There are two ways to check what this repo says about a rule. You can verify the signed attestation, or you can re-run the harness yourself and compare.

## 1. Verify an attestation

CI signs `out/predicate.json` with `actions/attest` on every push to main, every Monday and on manual runs from main. A separate attest job does the signing, so the job that installs packages and runs the harness holds no signing permission. The attestation's subjects are the sha256 digests of every file in `tools/sigma-pack` plus the digest of `claims.json`. You need the GitHub CLI.

Fetch the rule file you want to check, then verify it:

```
curl -sSLO https://raw.githubusercontent.com/umbrasec-labs/umbrasec.dev/master/tools/sigma-pack/rules/web/metabase-reset-password-sqli.yml
gh attestation verify metabase-reset-password-sqli.yml \
  --repo umbrasec-labs/detections \
  --signer-workflow umbrasec-labs/detections/.github/workflows/claims.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners \
  --predicate-type https://umbrasec.dev/attestations/claims/v1
```

Always pass `--predicate-type`. By default `gh attestation verify` looks only for SLSA provenance, and this record uses its own predicate type. Always pass `--signer-workflow` and `--source-ref` too. With `--repo` alone, a record that any workflow in this repo signed, from any branch, would also pass.

A pass tells you that the claims workflow on main signed a record naming this exact file digest. The predicate holds the run summary, each rule's status and claim counts, the engine versions, both commits, and `claims_json_sha256`.

A pass does not mean the rule is verified. Failing and stale runs are signed too. Read the status, and use the newest attestation. A rule's digest stays the same across runs, so one file can match several records, for example an older `verified` one and a newer `failing` one after a writeup changed. This prints the newest record's status for the rule:

```
gh attestation verify metabase-reset-password-sqli.yml \
  --repo umbrasec-labs/detections \
  --signer-workflow umbrasec-labs/detections/.github/workflows/claims.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners \
  --predicate-type https://umbrasec.dev/attestations/claims/v1 \
  --format json \
  --jq '[.[].verificationResult.statement.predicate | {generated_at, ok, status: .rules["metabase-reset-password-sqli"].status}] | sort_by(.generated_at) | last'
```

A pass does not re-run anything. It says what the harness found when it signed. If the rule file changed since that run, its digest changed too, and verification fails until a newer run signs the new bytes.

## 2. Reproduce a run

Pick the run you want to reproduce and download its artifact:

```
gh run list --repo umbrasec-labs/detections --workflow claims.yml --branch main --limit 5
gh run download <run-id> --repo umbrasec-labs/detections --name claims --dir published
```

Check out both repos at the commits the record names (`harness.commit` and `sigma_pack.commit` in `published/claims.json`), then run the same steps as CI:

```
git clone https://github.com/umbrasec-labs/detections && cd detections
git checkout <harness.commit>
git clone https://github.com/umbrasec-labs/umbrasec.dev _upstream
git -C _upstream checkout <sigma_pack.commit>
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
.venv/bin/python -m harness.guard
UMBRASEC_UPSTREAM=_upstream .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m harness.run --upstream _upstream --out out
```

Check that the rule bytes match the published subjects. The `claims.json` line has no file here, so `--ignore-missing` skips it. The second command checks the published `claims.json` against the same list:

```
(cd _upstream && sha256sum --check --ignore-missing ../../published/subjects.sha256)
(cd ../published && sha256sum --check --ignore-missing subjects.sha256)
```

Compare your record with the published one. The output is deterministic: only `generated_at` varies, plus `engine.python` if your patch version differs.

```
python3 - <<'EOF'
import json
a, b = (json.load(open(p)) for p in ("out/claims.json", "../published/claims.json"))
for d in (a, b):
    d.pop("generated_at")
    d["engine"].pop("python")
print("same" if a == b else "different")
EOF
```

## What the harness checks

A rule is `verified` only when its pinned `rule_sha256` matches the live bytes, every claim passes, every `falsepositives` bullet is covered and every sentence of its writeup's "Honest limitations" section is accounted for. A bullet or sentence counts as proved only while the claim that tests it passes. Any of these error codes makes a rule `failing`:

| Code | Meaning |
|---|---|
| `no-claims-file` | An upstream rule has no claims file. The rule shows as `unclaimed`. |
| `orphan-claims-file` | A claims file or ledger names nothing upstream. |
| `rule-id-mismatch` | `rule_id` differs from the rule's Sigma `id`. |
| `writeup-mismatch` | `writeup` differs from the umbrasec.dev writeup the rule references, or the writeup is missing. |
| `schema` | An unknown or missing key, a kind and expect pair the format does not allow, or a duplicate id. |
| `quote-not-found` | A quote is absent from its source. |
| `fp-uncovered` | A `falsepositives` bullet has no claim and no disposition. |
| `writeup-sentence-unaccounted` | A limitation sentence has no ledger entry. |
| `writeup-entry-stale` | A ledger entry matches no sentence, so the prose changed. |
| `ambiguous-entry` | A ledger entry starts more than one sentence, or a false-positive quote or `fp_dispositions` entry fits more than one bullet. Each must pick out one, so a new sentence or bullet cannot inherit an old disposition. |
| `not-synthetic` | An event lacks `_synthetic: true`. |
| `numeric-field-as-string` | An event gives a string where the rule compares a number. |
| `string-field-as-int` | An event gives an int for a field the rule never compares to a number. |
| `engine-error` | SQLite could not evaluate a claim's events. |
| `unsupported` | The rule uses a feature outside the engine's allowlist. |
| `claim-failed` | A claim's verdict differs from its `expect`. The message names the claim and the first offending event's `_note`. |

A rule whose bytes changed since review is `stale`. Its claims still run, and any errors still show, but it cannot be `verified` until `harness.relock` re-pins it.

## Engine notes

- pySigma compiles each Sigma file to one SQLite query. The harness never evaluates a condition itself.
- The engine fails closed. It accepts the `contains`, `startswith` and `endswith` modifiers, string and number values, and `value_count` correlations. Anything else is `unsupported`.
- Every column is declared `COLLATE NOCASE` with no type name, so equality is case-insensitive as Sigma requires. `LIKE` already is. Both fold ASCII only.
- The table gets a column for every field the rule names, so an event that omits a field still evaluates. The backend wraps negations in `COALESCE(..., 0)`, so an absent field under `not` behaves as Sigma says. Self-test 7 pins this.
- A rule that compares a field to a number needs an int in the event. The string `"4769"` would silently miss, so the harness rejects it.
- The reverse holds too. An int can never equal a string value, so a no-match claim would pass for the wrong reason. The harness rejects an int on any field the rule does not compare to a number. YAML reads unquoted `0x17` as the int 23, so quote hex values.
- SQLite column names ignore case. Two keys in one claim that differ only in case, or a key with a double quote, are a `schema` error.
- A correlation query can return several rows, one per sliding window. A match means at least one row.
- Locally, the verdicts were also checked under pySigma 2.0.1 with pySigma-backend-sqlite 2.1.1, and they agree.
