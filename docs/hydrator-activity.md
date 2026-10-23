# OpenShell policy adherence output

The opt-in `openshell.behavior.activity` signal sends a numeric policy-adherence
score directly to the Trust Index reference implementation
(`agent-trust-discovery`). The existing `openshell.policyViolationRate` and
`openshell.protocolAdherence` outputs retain their formats and counting rules.

The new path separates connection checks, initial HTTP checks, checks after
middleware changes a request, and WebSocket message checks. For each group it
calculates `100 × allowed / (allowed + denied + audited)` and rounds the lowest
eligible rate to an integer. An audit violation is a violation even when OpenShell
allows the request through. Connection failures, supervisor sessions, and health
reports do not become allowed or denied policy decisions.

`activity.min_decisions` defaults to 1. An allowed-only group below the minimum
is ignored; a group with a denied or audited decision below the minimum prevents
a score. For example, 50 allowed HTTP checks over one allowed connection can
score 100 at minimum 10, but a low-sample denial cannot disappear behind that
score. This measures adherence to the configured policy, not content safety.

## Configure the reference implementation first

Merge [the score registration](../deploy/examples/trust-index-score-signals.yaml)
into the deployment's signal registration file and point its runtime configuration
at that file:

```yaml
signals:
  path: score-signals.yaml
```

In each profile that will inspect this signal, add the following entry without
changing the profile's existing weights:

```yaml
signalWeights:
  openshell.behavior.activity: 0
```

Register the agent before importing its observations. An unknown agent, unknown
signal, or invalid value causes the reference implementation to reject the whole
batch. The output uses its existing `{score, explanation}` value; provider risk
codes are omitted or empty. The registration's `threshold: 0` also disables the
generic low-score risk code.

Keep the signal at weight 0: its score is visible but does not affect trust
decisions. **Do not use it in real trust decisions until the consumer can expire
or otherwise invalidate old scores.** If the hydrator sends no new score, the
reference implementation retains its previous score indefinitely, including 100.
A later clean measurement window can replace an earlier low score. This producer
change adds neither consumer expiry nor a new scoreless-report API.

## Enable the new producer output

Start with [hydrator-activity.yaml](../deploy/examples/hydrator-activity.yaml), set
the import URL and sandbox-to-agent mappings, and configure the existing import
route's admin key. Disable both legacy outputs explicitly when migrating; leaving
them enabled sends their legacy values in the same batch, which requires their
own compatible registrations. A missing or empty `signals.activity` disables the
new output.

```sh
./bin/ans-ocsf-hydrator \
  --config deploy/examples/hydrator-activity.yaml \
  --input supervisor-ocsf.jsonl \
  --window-last 24h \
  --evidence-output activity-evidence.jsonl
```

The existing `--window-last` flag, or Helm `hydrator.window`, selects the period
to measure. It may be longer than the run schedule, provided source logs are
retained for that period. The reference implementation reads only the latest
observation for each agent/signal, so it does not add overlapping snapshots.

## Keep structured evidence

`--evidence-output` writes one JSON object per agent as JSONL. It retains decision
counts, reported status, finding origins and match counts, policy context, and
diagnostics independently of the imported score. Findings do not change the score;
eligible score explanations summarize them. Finding-only windows stay in this
local output without inventing a numeric score.

Unknown policy syntax, incomplete interpretation, and exhausted deduplication
budgets suppress the affected agent's new score and record the reason. Other
agents continue. Bound and size `activity.max_uids_per_agent` and
`activity.max_uids` for the deployment's volume; their defaults are 100,000 and
1,000,000 respectively. Duplicate event IDs are removed only from the new path,
leaving legacy behavior unchanged.

When the aggregate UID budget fills, the hydrator marks the largest existing
UID owner unavailable and releases its set; ties use agent ID order. This lets
later agents proceed within the same memory budget. A budget too small for the
whole deployment can still make several agents unavailable.

DNS refusals are retained separately from TCP policy checks. The hydrator checks
that denied TCP counts cover the DNS refusals for each sandbox and destination;
otherwise it withholds the score. This is a conservative consistency check, not
proof that two records came from the same request.

Policy context records the first observed load for each sandbox/hash/version,
not every activation or reload. Missing applicable context is marked unknown.
The first and last event timestamps describe the records received; they do not
prove uninterrupted log coverage for the selected window.

Evidence files are created with private permissions and must not already exist.
This prevents accidental truncation of input or configuration, including symlink
or hard-link aliases. Choose a new filename for another run, or use
`--evidence-output -` to send JSONL to stdout. Stdout evidence cannot be combined
with `--dry-run`, which reserves stdout for the import request. With all three
signal IDs set to `""`, evidence output works without a Trust Index URL or server.

For scheduled Helm jobs, use `hydrator.evidenceOutput: "-"` so the log collector
retains each run's evidence. A fixed filename on a persistent volume works only
once: later jobs fail because evidence files are create-only. File output needs
a different filename for every run, supplied outside this chart.

The existing `provenance.evidence_url` is one static URL reused for every
observation. It does not create immutable evidence storage for each agent/window;
the example leaves it unset.
