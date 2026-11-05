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
A later clean measurement window can replace an earlier low score. Each
observation is stamped with its window end, and the reference implementation
ignores a repeat for the same agent, signal, and timestamp, so rerunning the same
window (for example after a configuration fix) does not replace the stored score;
only a later window does. This producer
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

Policy context lists each policy hash and version seen for the agent's
sandboxes. `policyChanged` is true when a sandbox loaded a policy after its
first counted decision, so the counts may span more than one policy; the score
is still sent. Score explanations name up to four policies by their first 12
hash characters and say when a policy changed, so scores are compared only under
the same policy. OpenShell's reload record carries a hash but no version.

Unknown policy syntax, incomplete interpretation, and exhausted deduplication
budgets suppress the affected agent's new score and record the reason. Other
agents continue. A record whose message states a policy decision but that is
not counted as one (for example because it also carries a coverage or
operational-failure status) also counts as incomplete, so a conflicting record
cannot hide a denial. The first recorded reason is kept; later problems appear
only as diagnostics. Bound and size `activity.max_uids_per_agent` and
`activity.max_uids` for the deployment's volume; their defaults are 100,000 and
1,000,000 respectively. Duplicate event IDs are removed only from the new path,
leaving legacy behavior unchanged.

When the aggregate UID budget fills, the hydrator marks the largest existing
UID owner unavailable and releases its set; ties use agent ID order. This lets
later agents proceed within the same memory budget. A budget too small for the
whole deployment can still make several agents unavailable.

An audit-shaped line that cannot be decoded or exceeds 1 MiB (a JSON object,
or a line in the supervisor's `{ts} OCSF-JSON ` framing whose marker is
followed by an object or by nothing) cannot be attributed to a sandbox. Scores
are still sent; the count is recorded as `unreadable_audit_records` in every
agent's diagnostics, the run logs one warning, and the job exits non-zero after
posting unless `--allow-unmapped` is set. The marker must be a whole token
with no `[` before it, which rejects shorthand copies preceded by a bracketed
severity tag. The parser does not validate timestamp text before the marker,
so an ordinary log line such as `INFO received OCSF-JSON {broken` still counts
as unreadable. Such a line has no readable timestamp, so the window cannot
exclude it: it is reported on every run until the input file rotates.
Keep the input to OpenShell audit records only; JSON logs from other programs
whose fields do not match the OCSF types count as unreadable.

A final line without a trailing newline is treated as a record still being
written: it is counted as `truncated_final_line` and does not withhold scores.
The next run counts it only if its timestamp falls inside that run's window, so
set the window longer than the schedule interval (for example `window: 1h` with
a 15-minute schedule).

DNS refusals of names outside the policy are retained separately from TCP
policy checks and do not change the score. When DNS refusals outnumber denied
TCP checks for a sandbox and destination, all of that pair's DNS refusals are
added to `unrepresented_dns_refusals`. For example, two DNS refusals and one
TCP denial contribute 2. Refusals with a missing destination also contribute
their full count. This is common: OpenShell answers a refused name without an
address, so no TCP attempt may follow, and with IPv6 egress a dual-stack client
is refused once per address family. DNS resolver and mapping-publication
failures for names the policy allows are recorded as `dns_failure` and are
not policy denials.

When every agent's score is withheld (for example by unknown policy formats),
the run logs a warning and the job exits non-zero unless `--allow-unmapped` is
set. Agents without eligible decisions do not count as withheld.

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
retains each run's evidence. The chart refuses to render any other value: a fixed
filename would make every run after the first fail before posting, including the
legacy outputs, because evidence files are create-only.

The existing `provenance.evidence_url` is one static URL reused for every
observation. It does not create immutable evidence storage for each agent/window;
the example leaves it unset.

## Known limits before raising the weight

- A sandbox writes its own audit records, so an agent that can emit an
  unrecognized or conflicting decision record can withhold its own new score.
  Together with the consumer retaining the last score, a previously clean agent
  can keep 100 after later violations. This is one more reason the weight stays
  at 0 until scores expire.
- An unreadable or oversized audit line is left out of every count, so if it
  was a denial the affected agent's score is higher than it should be. The
  run reports the line and exits non-zero rather than withholding scores.
- DNS refusals of names outside the policy do not lower the score, so an agent
  that only probes names by DNS, without a TCP attempt, can still score 100.
  The evidence output keeps the refusal counts.
- The score is rounded, so a single violation among 200 or more decisions still
  reports 100. The evidence output keeps the exact counts.
- Rollout behavior (weight 0 has no effect on trust decisions, retained scores,
  whole-batch rejection) belongs to the consumer and is not tested in this
  repository. Verify it against the deployed `agent-trust-discovery` before
  changing the weight.
