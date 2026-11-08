# shellcheck shell=bash
# Sourced by smoke.sh under --with-trust-index. Adds the behavior path to the
# run: the gateway's OCSF JSON export is switched on, the approved sandbox's
# supervisor records are collected, the hydrator scores them and imports the
# score into a pinned agent-trust-discovery that this file starts, and the
# score is read back from the agent's trust evaluation. The functions below
# are called from smoke.sh at the points marked there; nothing here runs on
# its own.
#
# Checks added, continuing smoke.sh's numbering:
#   6. OCSF JSON export is live for the sandbox before the first request;
#   7. a request the policy does not allow is denied by the supervisor and
#      never reaches the callee;
#   8. the collected records all carry the gateway-issued sandbox id and hold
#      exactly the policy decisions the run made;
#   9. the hydrator computes the expected score from them and imports it;
#  10. the Trust Index lists the score on the agent at weight 0.
#
# Requires from smoke.sh: ROOT, EXAMPLE_DIR, WORK, BIN, LOG_DIR, CLI,
#   DOCKER_SANDBOX_LABEL, SANDBOX_NAME, SANDBOX_ID, AGENT_ID, ANS_NAME,
#   IDENTITY, TRUST_INDEX_PORT, the request journal $LOG_DIR/requests.log,
#   and the functions fail, check, step, run_bounded, wait_for_http,
#   sandbox_curl, response_status, response_body.
# Provides to smoke.sh: TRUST_INDEX_PID, TRUST_INDEX_VERSION, TRUST_INDEX_ASSET,
#   TRUST_INDEX_SHA, and the trust_index_* functions it calls.

# shellcheck source=examples/openshell-smoke/trust-index-release.env
source "$EXAMPLE_DIR/trust-index-release.env"

TRUST_INDEX_PID=""
TRUST_INDEX_PORT=""
TRUST_INDEX_DIR=""
TRUST_INDEX_URL=""
SUPERVISOR_CONTAINER=""
EXPECTED_SCORE=""

# The checksum variables are assigned by trust-index-release.env; smoke.sh
# passes the asset name and digest chosen here to fetch_release_asset.
# shellcheck disable=SC2154,SC2034
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TRUST_INDEX_ASSET="agent-trust-discovery_${TRUST_INDEX_VERSION#v}_linux_amd64"; TRUST_INDEX_SHA="$TRUST_INDEX_SHA256_linux_amd64" ;;
  Linux-aarch64 | Linux-arm64) TRUST_INDEX_ASSET="agent-trust-discovery_${TRUST_INDEX_VERSION#v}_linux_arm64"; TRUST_INDEX_SHA="$TRUST_INDEX_SHA256_linux_arm64" ;;
  Darwin-arm64) TRUST_INDEX_ASSET="agent-trust-discovery_${TRUST_INDEX_VERSION#v}_darwin_arm64"; TRUST_INDEX_SHA="$TRUST_INDEX_SHA256_darwin_arm64" ;;
  *) echo "FAIL unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# trust_index_prepare: called once the run directory and ports exist. Mints the
# admin key the import route requires and writes the Trust Index's own
# configuration. The key reaches the server through its environment and the
# hydrator and curl through files, so no command line and no log carries it.
trust_index_prepare() {
  TRUST_INDEX_DIR="$WORK/trust-index"
  TRUST_INDEX_URL="http://127.0.0.1:$TRUST_INDEX_PORT"
  mkdir -p "$TRUST_INDEX_DIR/profiles"
  (
    umask 077
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"$TRUST_INDEX_DIR/admin-key"
    printf 'Authorization: Bearer %s\n' "$(<"$TRUST_INDEX_DIR/admin-key")" >"$TRUST_INDEX_DIR/auth-header"
  )
  # The signal registration under test is the file this repository ships for
  # operators; the profile names only that signal, so a Trust Index release
  # that renames a built-in signal cannot stop the server from starting.
  cat >"$TRUST_INDEX_DIR/runtime.yaml" <<YAML
listen:
  addr: "127.0.0.1:$TRUST_INDEX_PORT"
db:
  path: $TRUST_INDEX_DIR/trust-index.db
admin:
  requireKey: true
log:
  level: ${ANS_SMOKE_TRUST_INDEX_LOG_LEVEL:-info}
signals:
  path: $ROOT/deploy/examples/trust-index-score-signals.yaml
YAML
  cat >"$TRUST_INDEX_DIR/default-profile.yaml" <<YAML
name: default
dimensionWeights:
  behavior: 1
signalWeights:
  openshell.behavior.activity: 0
YAML
}

# write_hydrator_config SANDBOX_UID: the hydrator maps records to the agent by
# the gateway-issued sandbox id, which only exists once the sandbox does.
write_hydrator_config() {
  cat >"$WORK/hydrator.yaml" <<YAML
trust_index:
  base_url: $TRUST_INDEX_URL
  admin_key_file: $TRUST_INDEX_DIR/admin-key
provenance:
  aim_id: ans://v1.0.0.smoke-collector.example.com
signals:
  policy_violation_rate: ""
  protocol_adherence: ""
  activity: openshell.behavior.activity
activity:
  min_decisions: 1
agents:
  - agent_id: $AGENT_ID
    ans_name: $ANS_NAME
    sandbox_uids: [$1]
YAML
}

# authorized_decisions: how many requests the approved sandbox has made, each
# of which the supervisor logged as one L7 policy decision whatever the
# verdict. smoke.sh journals every sandbox_curl in requests.log, so the count
# never depends on which checks ran or how often check 1 retried.
authorized_decisions() {
  grep -c "^$SANDBOX_NAME " "$LOG_DIR/requests.log" 2>/dev/null || printf '0'
}

trust_index_print_config() {
  cat "$TRUST_INDEX_DIR/runtime.yaml" "$TRUST_INDEX_DIR/default-profile.yaml" "$WORK/hydrator.yaml"
}

# trust_index_retain_configs: copies the rendered configuration next to the
# logs so a failed run's artifact explains what the processes were given.
# Neither file holds a secret; the admin key travels by environment and by
# files that are removed with the other key material.
trust_index_retain_configs() {
  cp "$TRUST_INDEX_DIR/runtime.yaml" "$LOG_DIR/trust-index-runtime.yaml"
  cp "$TRUST_INDEX_DIR/default-profile.yaml" "$LOG_DIR/trust-index-default-profile.yaml"
  cp "$WORK/hydrator.yaml" "$LOG_DIR/hydrator.yaml"
}

# trust_index_start: starts the server on the loopback port and registers the
# fixture agent. The server logs JSON to stdout. The registration curl is
# called directly, not through step, which would echo its arguments into
# setup.log; the key travels in a header file instead.
trust_index_start() {
  printf 'INFO starting agent-trust-discovery %s on %s\n' "$TRUST_INDEX_VERSION" "$TRUST_INDEX_URL"
  ANS_ADMIN_KEY="$(<"$TRUST_INDEX_DIR/admin-key")" "$BIN/agent-trust-discovery" \
    -config "$TRUST_INDEX_DIR/runtime.yaml" >"$LOG_DIR/trust-index.log" 2>&1 &
  TRUST_INDEX_PID=$!
  wait_for_http "trust index" "$TRUST_INDEX_URL/health" "$TRUST_INDEX_PID" 30
  local now status
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  status="$(run_bounded 30 curl -sS -o "$LOG_DIR/agent-import.out" -w '%{http_code}' --max-time 20 \
    -H @"$TRUST_INDEX_DIR/auth-header" -H 'content-type: application/json' \
    -X POST "$TRUST_INDEX_URL/v1/internal/agents/import" \
    --data "$(jq -n --arg id "$AGENT_ID" --arg name "$ANS_NAME" --arg display "$IDENTITY" --arg now "$now" \
      '{agents: [{agentId: $id, dnsName: $name, displayName: $display, status: "ACTIVE", firstSeen: $now, lastUpdated: $now}]}')")" \
    || fail "agent import request did not complete"
  [[ "$status" == 200 ]] || fail "agent import: status $status, body: $(cat "$LOG_DIR/agent-import.out")"
  printf 'INFO agent %s registered with the trust index\n' "$AGENT_ID"
}

trust_index_enable_export() {
  step "enabling OCSF JSON export" run_bounded 60 "${CLI[@]}" settings set --global --key ocsf_json_enabled --value true --yes
}

# supervisor_container NAME: the one container of the sandbox that runs the
# supervisor, whose stderr carries the OCSF JSON records.
supervisor_container() {
  run_bounded 30 docker ps -aq --filter "label=openshell.ai/sandbox-namespace=$DOCKER_SANDBOX_LABEL" \
    --filter "label=openshell.ai/sandbox-name=$1" --filter "label=openshell.ai/isolation-role=supervisor" 2>/dev/null | head -n 1
}

# ocsf_records CONTAINER: the OCSF JSON lines of the container's log, framing
# intact, so the hydrator later parses exactly what a log collector would hand
# it: a timestamp, the OCSF-JSON marker, then the record. Everything else the
# supervisor writes to stderr is left out here. A docker logs failure is an
# error, not an empty log.
ocsf_records() {
  local lines
  lines="$(run_bounded 30 docker logs "$1" 2>&1)" || fail "docker logs $1 failed: $(tail -n 3 <<<"$lines" | tr '\n' ';')"
  grep -E '^[^ ]+ OCSF-JSON \{' <<<"$lines" || true
}

# ocsf_payloads FILE: the JSON records in FILE without their framing.
ocsf_payloads() {
  sed -E 's/^[^ ]+ OCSF-JSON //' "$1"
}

# l7_decisions FILE: the L7 policy decisions among the records in FILE. A
# record may carry no message at all, so the field is defaulted before the
# prefix test.
l7_decisions() {
  ocsf_payloads "$1" | jq -r 'select((.message // "") | startswith("L7_REQUEST ")) | .message'
}

# 6. The supervisor applies ocsf_json_enabled on its first settings poll, so a
# sandbox created after the global set exports from its first request. This
# proves it before any request is made: records the sandbox exec produces
# (SSH activity, no HTTP decision) must appear in the supervisor's log.
trust_index_check_export_live() {
  local container count deadline=$((SECONDS + 60))
  container="$(supervisor_container "$SANDBOX_NAME")"
  [[ -n "$container" ]] || fail "no supervisor container for $SANDBOX_NAME"
  SUPERVISOR_CONTAINER="$container"
  while ((SECONDS < deadline)); do
    run_bounded 30 "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- true >>"$LOG_DIR/setup.log" 2>&1 || true
    count="$(ocsf_records "$container" | wc -l | tr -d ' ')"
    if [[ "$count" -gt 0 ]]; then
      check "OCSF JSON export is live for the sandbox ($count records before the first request)"
      return
    fi
    sleep 2
  done
  fail "no OCSF JSON record from the supervisor within 60 s; settings: $(run_bounded 30 "${CLI[@]}" settings get --global --json 2>&1 | tr '\n' ' '); toggles: $(run_bounded 30 docker logs "$container" 2>&1 | grep -c 'OCSF JSONL logging toggled' || true); log lines: $(run_bounded 30 docker logs "$container" 2>&1 | wc -l | tr -d ' ')"
}

# 7. A request the policy does not allow (the policy allows POST /v1/tasks
# only) is denied by the supervisor itself; no middleware runs and the callee
# is never reached. This is the run's one denied decision.
trust_index_check_policy_denied() {
  local out status body lines_before
  lines_before="$(wc -l <"$LOG_DIR/callee.log")"
  out="$(sandbox_curl "$SANDBOX_NAME" -X DELETE)" || true
  status="$(response_status "$out")"
  body="$(response_body "$out")"
  [[ "$status" == 403 ]] || fail "policy-denied request: status $status, body: $body"
  [[ "$(jq -r .error <<<"$body" 2>/dev/null)" == policy_denied ]] || fail "policy-denied request: not a policy denial: $body"
  [[ "$(wc -l <"$LOG_DIR/callee.log")" -eq "$lines_before" ]] || fail "the callee saw the policy-denied request"
  check "policy-denied request is blocked by the supervisor and the callee is not reached"
}

# 8. Collect the supervisor's records once every decision the run made is in
# them, and prove they are attributable: each carries the gateway-issued
# sandbox id, and the decisions are exactly the run's requests.
trust_index_check_records() {
  local expected allowed
  expected="$(authorized_decisions)"
  allowed=$((expected - 1))
  local records="$LOG_DIR/supervisor-ocsf.jsonl" count=0 deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    ocsf_records "$SUPERVISOR_CONTAINER" >"$records"
    count="$(l7_decisions "$records" | wc -l | tr -d ' ')"
    [[ "$count" -ge "$expected" ]] && break
    sleep 1
  done
  [[ "$count" -eq "$expected" ]] \
    || fail "L7 decisions in the supervisor log: want $expected, got $count: $(l7_decisions "$records" | tr '\n' ';')"
  local foreign
  foreign="$(ocsf_payloads "$records" \
    | jq -r --arg uid "$SANDBOX_ID" --arg name "$SANDBOX_NAME" \
      '(.device.container // .container) as $c | select(($c.uid // "") != $uid or ($c.name // "") != $name) | .message' \
    | head -n 3)"
  [[ -z "$foreign" ]] || fail "records not attributed to $SANDBOX_NAME ($SANDBOX_ID): $foreign"
  local denied allowed_seen transformed
  denied="$(l7_decisions "$records" | grep -c '^L7_REQUEST deny DELETE ' || true)"
  allowed_seen="$(l7_decisions "$records" | grep -c '^L7_REQUEST allow POST ' || true)"
  transformed="$(ocsf_payloads "$records" | jq -r 'select((.message // "") | startswith("L7_REQUEST_TRANSFORMED")) | .message' | wc -l | tr -d ' ')"
  [[ "$denied" -eq 1 && "$allowed_seen" -eq "$allowed" && "$transformed" -eq 0 ]] \
    || fail "decisions: want $allowed allow POST, 1 deny DELETE, 0 transformed; got $allowed_seen, $denied, $transformed"
  check "supervisor OCSF export carries $expected policy decisions, every record attributed to sandbox $SANDBOX_ID"
}

# 9. The hydrator reads the collected records, scores the agent and imports
# the score. The counts are asserted exactly; the score itself is the
# hydrator's to compute (its formula is pinned by its unit tests and may be
# recalibrated), so it is read from the evidence and carried to check 10,
# which proves the Trust Index shows what was imported.
trust_index_check_hydrator() {
  local allowed evidence="$LOG_DIR/activity-evidence.jsonl"
  allowed=$(($(authorized_decisions) - 1))
  write_hydrator_config "$SANDBOX_ID"
  trust_index_retain_configs
  run_bounded 60 "$BIN/ans-ocsf-hydrator" --config "$WORK/hydrator.yaml" --input "$LOG_DIR/supervisor-ocsf.jsonl" \
    --evidence-output "$evidence" --log-format text --log-level "${ANS_SMOKE_TRUST_INDEX_LOG_LEVEL:-info}" 2>"$LOG_DIR/hydrator.log" \
    || fail "hydrator exited non-zero: $(tail -n 5 "$LOG_DIR/hydrator.log" | tr '\n' ';')"
  [[ "$(wc -l <"$evidence" | tr -d ' ')" -eq 1 ]] || fail "hydrator evidence: want 1 agent, got $(wc -l <"$evidence" | tr -d ' ') lines"
  jq -e --arg agent "$AGENT_ID" --argjson allowed "$allowed" '
      .agentId == $agent
      and .measurements.httpInitial == {allowed: $allowed, denied: 1, audited: 0, unknown: 0}
      and .measurements.connections.denied == 0
      and (.score | type) == "number" and .score > 0 and .score < 100
      and (has("unavailableReason") | not)' "$evidence" >/dev/null \
    || fail "hydrator evidence: $(jq -c '{agentId, score, unavailableReason, measurements, diagnostics}' "$evidence"); hydrator log: $(tail -n 3 "$LOG_DIR/hydrator.log" | tr '\n' ';')"
  EXPECTED_SCORE="$(jq -r .score "$evidence")"
  check "hydrator scores $EXPECTED_SCORE from $allowed allowed and 1 denied decision and imports it"
}

# 10. The Trust Index shows the score on the agent's trust evaluation, listed
# under the behavior dimension at weight 0: visible, contributing nothing to
# trust decisions, the rollout state docs/hydrator-activity.md asks for.
trust_index_check_readback() {
  local body
  body="$(run_bounded 30 curl -sS --max-time 20 "$TRUST_INDEX_URL/v1/ans/registered-agents/$AGENT_ID")" \
    || fail "trust index detail request did not complete"
  jq -e --argjson score "$EXPECTED_SCORE" '
      (.trustEvaluation.dimensions[] | select(.dimension == "behavior") | .signalScores[]
        | select(.signalId == "openshell.behavior.activity")) as $s
      | $s.rawScore == $score and $s.weight == 0 and ($s.explanation | length) > 0
        and .trustEvaluation.trustVector.behavior == 0' <<<"$body" >/dev/null \
    || fail "trust index detail: $(jq -c '{trustVector: .trustEvaluation.trustVector, behavior: (.trustEvaluation.dimensions[]? | select(.dimension == "behavior"))}' <<<"$body" 2>/dev/null || printf '%s' "$body")"
  check "trust index shows openshell.behavior.activity = $EXPECTED_SCORE at weight 0"
}

# trust_index_summary: the pinned release as the ALL PASS line names it.
trust_index_summary() {
  printf 'agent-trust-discovery %s (%s)' "$TRUST_INDEX_VERSION" "${TRUST_INDEX_COMMIT:0:7}"
}

trust_index_print_ready() {
  cat <<EOT
  trust index: $TRUST_INDEX_URL   (agent-trust-discovery $TRUST_INDEX_VERSION)
  evidence:    $LOG_DIR/activity-evidence.jsonl
Trust evaluation with the behavior score:
  curl -sS $TRUST_INDEX_URL/v1/ans/registered-agents/$AGENT_ID | jq .trustEvaluation
EOT
}
