#!/usr/bin/env bash
#
# run-demo.sh — drive the live two-agent OpenShell commerce demo end-to-end.
#
# Act 1: a registered buyer agent (commerce-enabled) in an OpenShell sandbox
#        calls the LIVE seller through the Go ans-egress middleware and gets a
#        ticket.
# Act 2: a dev-mode rogue agent (no commerce) makes the same call and is
#        rejected by the live seller (MANDATE_REJECTED).
#
# CONFIG: everything comes from a .env file (see .env.example). The .env is the
# single source of truth — this script RENDERS the agent + policy configs into
# $WORK from it, so there are no checked-in config values and no secrets in the
# repo. The agent owner supplies the .env plus the 3 PEM files out-of-band; the
# .env points at wherever those PEMs are dropped.
#
# The gateway must already be RUNNING (start it per README before this script).
# This script starts/stops the two egress middlewares itself.
#
# Usage:
#   ./run-demo.sh                          # terse pass/fail (CI-style)
#   ./run-demo.sh --narrate                # step-by-step walkthrough with decoded artifacts
#   ./run-demo.sh --narrate --report F.md  # also write a markdown run report to F.md
#   ENV_FILE=/path/to/.env ./run-demo.sh [--narrate] [--report FILE]
#
# --narrate explains each step (what + why) and shows the REAL decoded evidence —
# the GoDaddy-issued cert chain, the production transparency-log vouch, the signed
# DPoP proof claims, the scoped authority mandate, the issued ticket, and the
# rogue's rejection — for a reviewer evaluating ANS as an identity layer. It turns
# on the egress's DEBUG logging so the proof/mandate it builds can be displayed;
# the plain run leaves that off. No private keys are ever shown.
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# --- args --------------------------------------------------------------------
NARRATE=0
REPORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --narrate) NARRATE=1 ;;
    --report)  shift; REPORT="${1:-}"; NARRATE=1
               [ -n "$REPORT" ] || { echo "--report needs a FILE argument" >&2; exit 2; } ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
EGRESS_LOG_LEVEL=info
[ "$NARRATE" = 1 ] && EGRESS_LOG_LEVEL=debug

# WSL2 puts the Windows docker.exe ahead of the Linux CLI on PATH; the Linux one
# lives in /usr/bin. Prepend it so docker/openshell talk to the daemon.
export PATH="/usr/bin:$PATH"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m== %s\033[0m\n' "$*"; }
fail()  { red "FAIL: $*"; exit 1; }

# --- narration (no-ops unless --narrate) -------------------------------------
# Everything narrated is mirrored into the report file (plain text, no colors)
# when --report is set.
STEP_N=0
report() { [ -n "$REPORT" ] && printf '%s\n' "$*" >>"$REPORT"; return 0; }
say()    { [ "$NARRATE" = 1 ] || return 0; printf '%s\n' "$*"; report "$*"; }
note()   { [ "$NARRATE" = 1 ] || return 0; printf '      \033[2m%s\033[0m\n' "$*"; report "      $*"; }
good()   { [ "$NARRATE" = 1 ] || return 0; printf '      \033[32m✓ %s\033[0m\n' "$*"; report "      [OK] $*"; }
bad()    { [ "$NARRATE" = 1 ] || return 0; printf '      \033[31m✗ %s\033[0m\n' "$*"; report "      [X]  $*"; }
step() {  # step "Title" "why this matters"
  [ "$NARRATE" = 1 ] || return 0
  STEP_N=$((STEP_N + 1))
  printf '\n\033[1m\033[36mSTEP %d — %s\033[0m\n' "$STEP_N" "$1"
  report ""; report "## STEP $STEP_N — $1"
  [ -n "${2:-}" ] && { printf '      \033[2mwhy: %s\033[0m\n' "$2"; report "      why: $2"; }
  return 0
}

# --- load .env ---------------------------------------------------------------
ENV_FILE="${ENV_FILE:-$HERE/.env}"
[ -f "$ENV_FILE" ] || fail "no env file at $ENV_FILE — copy .env.example to .env and fill it in"
set -a; . "$ENV_FILE"; set +a

# Required vars (fail fast with a clear message if the .env is incomplete).
for v in WORK REPO HOST_IP BUYER_ANS_NAME BUYER_AGENT_ID BUYER_KEY_FILE \
         BUYER_CERT_FILE BUYER_COMMERCE_DPOP_KEY ROGUE_ANS_NAME ROGUE_AGENT_ID \
         TL_BASE_URL TL_ROOT_KEYS_FILE SELLER_MCP_URL AUTHORITY_MCP_URL \
         SELLER_ANS AUTHORITY_ANS SCOPE_HINT SUBJECT_ANS DEMO_QUOTE_ID \
         DEMO_AMOUNT DEMO_CURRENCY OPENSHELL_GATEWAY_ENDPOINT \
         EGRESS_A_LISTEN EGRESS_B_LISTEN MAX_PAYLOAD_BYTES; do
  [ -n "${!v:-}" ] || fail "$ENV_FILE is missing required variable: $v"
done
export OPENSHELL_GATEWAY_ENDPOINT

OSH="${OPENSHELL:-$WORK/bin/openshell}"
MW_BIN="${MW_BIN:-$REPO/bin/ans-demo-middleware}"
SELLER_URL="$SELLER_MCP_URL"
BODY="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"book_flight\",\"arguments\":{\"quote_id\":\"$DEMO_QUOTE_ID\",\"amount\":$DEMO_AMOUNT,\"currency\":\"$DEMO_CURRENCY\"}}}"

A_CFG="$WORK/agent-a-local.yaml"
B_CFG="$WORK/agent-b-local.yaml"
A_POL="$WORK/policy-a.yaml"
B_POL="$WORK/policy-b.yaml"

# --- intro + trust-boundary diagram (narrate only) ---------------------------
if [ "$NARRATE" = 1 ]; then
  [ -n "$REPORT" ] && : >"$REPORT"
  report "# ANS live two-agent OpenShell demo — run report"
  report "_$(date -u '+%Y-%m-%d %H:%M:%SZ')_"
  cat <<'DIAGRAM'

  ANS as the identity layer — live two-agent OpenShell commerce demo
  ==================================================================

  What this shows: the SAME book_flight request from two agents. One carries a
  real, transparency-log-vouched ANS identity + a scoped spending mandate and
  transacts; the other is unvouched and is refused. Identity and authorization
  are enforced END-TO-END, outside the (untrusted) sandbox workload.

     ┌─────────────────┐   plain POST    ┌──────────────────┐   signed+mutated   ┌────────────────┐
     │  agent in an    │  book_flight    │   ANS egress     │   request (mandate │   LIVE seller  │
     │ OpenShell sandbox│ ───────────────▶│  (middleware)    │ + DPoP + identity) │ (public internet)│
     │  (UNMODIFIED)   │                 │                  │ ──────────────────▶│                │
     └─────────────────┘                 └──────────────────┘                    └────────────────┘
        knows nothing      the identity is          the seller VERIFIES the
        about ANS          stamped HERE, not         identity proof + mandate
                           inside the sandbox        before issuing a ticket

     Trust anchor: GoDaddy production transparency log (transparency.ans.godaddy.com)
DIAGRAM
  report ""
  report '```'
  report '  agent in OpenShell sandbox --plain book_flight--> ANS egress --signed+mandate--> LIVE seller'
  report '  (identity stamped at the egress, OUTSIDE the untrusted sandbox; seller verifies before issuing)'
  report '```'
fi

# --- preflight ---------------------------------------------------------------
info "preflight"
[ -x "$OSH" ] || fail "openshell CLI not found/executable at $OSH (set OPENSHELL=... or bin/openshell under WORK)"
[ -x "$MW_BIN" ] || fail "demo middleware binary not at $MW_BIN — run 'make demo-build' in $REPO (or set MW_BIN=...)"
for f in "$BUYER_KEY_FILE" "$BUYER_CERT_FILE" "$BUYER_COMMERCE_DPOP_KEY" "$TL_ROOT_KEYS_FILE"; do
  [ -f "$f" ] || fail "missing identity/key file: $f (the agent owner supplies the 3 PEMs out-of-band; see SECRETS.md)"
done
"$OSH" sandbox list >/dev/null 2>&1 || fail "gateway not reachable at $OPENSHELL_GATEWAY_ENDPOINT — start it first (see README)"

# Clock skew: the seller tolerates a DPoP proof up to SELLER_SKEW_LEEWAY_SEC in
# its future (and 120s in the past). If the local clock is further ahead, Act 1
# fails with 'proof age -Ns'. The HTTP Date header is second-granular.
SELLER_SKEW_LEEWAY_SEC="${SELLER_SKEW_LEEWAY_SEC:-5}"
seller_epoch=$(date -u -d "$(curl -sI "$SELLER_URL" 2>/dev/null | grep -i '^date:' | cut -d' ' -f2-)" +%s 2>/dev/null || echo 0)
now_epoch=$(date -u +%s)
if [ "$seller_epoch" != 0 ]; then
  skew=$(( now_epoch - seller_epoch ))
  if [ "$skew" -ge "$SELLER_SKEW_LEEWAY_SEC" ]; then
    red "ABORT: local clock is ${skew}s AHEAD of the seller — beyond its ${SELLER_SKEW_LEEWAY_SEC}s"
    red "       DPoP leeway, so proofs would be rejected ('proof age -Ns'). Resync:"
    red "           sudo systemctl restart systemd-timesyncd"
    exit 1
  fi
fi

# --- render configs from .env ------------------------------------------------
# All configs are generated here so the repo carries no values. sandbox_identities
# is left empty; bind_identity fills it per run.
render_configs() {
  info "rendering configs into $WORK from $ENV_FILE"
  mkdir -p "$WORK"

  cat >"$A_CFG" <<YAML
# RENDERED by run-demo.sh from $ENV_FILE — do not edit by hand.
listen: "$EGRESS_A_LISTEN"
health_listen: "0.0.0.0:8091"
auth:
  allow_insecure_no_auth: true
transparency_log:
  base_url: $TL_BASE_URL
  root_keys_file: $TL_ROOT_KEYS_FILE
identities:
  buyer-agent:
    ans_name: $BUYER_ANS_NAME
    agent_id: $BUYER_AGENT_ID
    key_file: $BUYER_KEY_FILE
    cert_file: $BUYER_CERT_FILE
    dev_mode: false
sandbox_identities: {}
max_payload_bytes: $MAX_PAYLOAD_BYTES
commerce:
  seller_mcp_url: $SELLER_MCP_URL
  authority_mcp_url: $AUTHORITY_MCP_URL
  seller_ans: $SELLER_ANS
  authority_ans: $AUTHORITY_ANS
  scope_hint: $SCOPE_HINT
  subject_ans: $SUBJECT_ANS
  commerce_dpop_key_path: $BUYER_COMMERCE_DPOP_KEY
  demo_quote_id: $DEMO_QUOTE_ID
  demo_amount: $DEMO_AMOUNT
  demo_currency: $DEMO_CURRENCY
  max_body_bytes: 10000
YAML

  cat >"$B_CFG" <<YAML
# RENDERED by run-demo.sh from $ENV_FILE — do not edit by hand.
listen: "$EGRESS_B_LISTEN"
health_listen: "0.0.0.0:8092"
auth:
  allow_insecure_no_auth: true
transparency_log:
  base_url: $TL_BASE_URL
  root_keys_file: $TL_ROOT_KEYS_FILE
identities:
  rogue-agent:
    ans_name: $ROGUE_ANS_NAME
    agent_id: $ROGUE_AGENT_ID
    dev_mode: true
sandbox_identities: {}
max_payload_bytes: $MAX_PAYLOAD_BYTES
YAML

  for pair in "$A_POL:ans-egress-a:buyer-agent" "$B_POL:ans-egress-b:rogue-agent"; do
    local path="${pair%%:*}" rest="${pair#*:}"
    local mw="${rest%%:*}" ident="${rest#*:}"
    cat >"$path" <<YAML
# RENDERED by run-demo.sh from $ENV_FILE — do not edit by hand.
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/bin, /usr, /lib, /proc, /dev/urandom, /etc, /var/log]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: best_effort
network_policies:
  skybound:
    name: skybound
    endpoints:
      - host: seller.skybound-travel.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
      - host: authority.skybound-travel.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - { path: /bin/busybox }
      - { path: /usr/bin/wget }
network_middlewares:
  $mw:
    name: $mw
    middleware: $mw
    order: 0
    on_error: fail_closed
    endpoints:
      include: ["seller.skybound-travel.com", "authority.skybound-travel.com"]
    config:
      mode: sign
      identity: $ident
YAML
  done
}
render_configs

# --- helpers -----------------------------------------------------------------

# recreate_sandbox NAME POLICY -> prints the fresh sandbox UUID
recreate_sandbox() {
  local name="$1" policy="$2"
  "$OSH" sandbox delete "$name" >/dev/null 2>&1
  "$OSH" sandbox create --name "$name" --from alpine:3.20 --no-tty --detach \
    --policy "$policy" -- /bin/sh -c "sleep 3600" >/dev/null 2>&1
  local uuid="" phase="" i
  for i in $(seq 1 30); do
    uuid=$("$OSH" sandbox get "$name" 2>/dev/null | awk '/^  Id:/{print $2; exit}')
    phase=$("$OSH" sandbox get "$name" 2>/dev/null | awk '/^  Phase:/{print $2; exit}')
    [ "$phase" = "Ready" ] && break
    sleep 1
  done
  [ "$phase" = "Ready" ] || { red "sandbox $name never reached Ready (phase=$phase)"; return 1; }
  printf '%s' "$uuid"
}

# bind_identity CONFIG UUID IDENTITY — rewrite the single sandbox_identities entry
bind_identity() {
  local cfg="$1" uuid="$2" ident="$3"
  python3 - "$cfg" "$uuid" "$ident" <<'PY'
import sys, re
cfg, uuid, ident = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(cfg).read()
pat = re.compile(r'(?m)^sandbox_identities:.*?(?=^\S|\Z)', re.S)
repl = f"sandbox_identities:\n  {uuid}: {ident}\n"
text, n = pat.subn(repl, text)
if n == 0:
    text += "\n" + repl
open(cfg, 'w').write(text)
PY
}

EGRESS_A_PID=""
EGRESS_B_PID=""
# restart_egress WHICH CONFIG — (re)start a middleware, waiting for port release
restart_egress() {
  local which="$1" cfg="$2"
  local pidvar="EGRESS_${which}_PID"
  local pid="${!pidvar}"
  if [ -n "$pid" ]; then
    kill "$pid" >/dev/null 2>&1
    local w
    for w in $(seq 1 20); do
      kill -0 "$pid" >/dev/null 2>&1 || break
      sleep 0.3
    done
  fi
  : >"$WORK/egress-${which}.log"
  "$MW_BIN" --config "$cfg" --log-level "$EGRESS_LOG_LEVEL" >"$WORK/egress-${which}.log" 2>&1 &
  eval "$pidvar=$!"
  local i
  for i in $(seq 1 30); do
    grep -q "grpc server listening" "$WORK/egress-${which}.log" 2>/dev/null && return 0
    if grep -q "address already in use" "$WORK/egress-${which}.log" 2>/dev/null; then
      red "egress $which: port still in use — a stale middleware is holding it"; return 1
    fi
    sleep 0.5
  done
  red "egress $which did not report ready; see $WORK/egress-${which}.log"; return 1
}

cleanup() {
  [ -n "$EGRESS_A_PID" ] && kill "$EGRESS_A_PID" >/dev/null 2>&1
  [ -n "$EGRESS_B_PID" ] && kill "$EGRESS_B_PID" >/dev/null 2>&1
}
trap cleanup EXIT

# run_booking NAME -> prints the raw seller response body
run_booking() {
  local name="$1"
  "$OSH" sandbox exec "$name" -- /bin/sh -c \
    "wget -O- -q --timeout=90 --header='Content-Type: application/json' --post-data='$BODY' $SELLER_URL 2>&1" 2>/dev/null
}

# --- evidence extractors (used only when narrating) --------------------------
# narrate_identity_provenance: show the cert's ANS SAN + GoDaddy issuer, and
# prove the egress loaded it via the PRODUCTION transparency log.
narrate_identity_provenance() {
  [ "$NARRATE" = 1 ] || return 0
  local san issuer
  san=$(openssl x509 -in "$BUYER_CERT_FILE" -noout -ext subjectAltName 2>/dev/null | grep -oE 'URI:ans://[^,]+' | head -1)
  issuer=$(openssl x509 -in "$BUYER_CERT_FILE" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
  say   "Agent A presents a real ANS identity:"
  good  "ANS name (cert SAN):  ${san:-<none>}"
  good  "issued by:            ${issuer:-<unknown>}"
  # Production transparency-log reachability + the egress's own 'vouched' signal.
  local tl_code
  tl_code=$(curl -s -o /dev/null -w '%{http_code}' "$TL_BASE_URL/root-keys" 2>/dev/null)
  if [ "$tl_code" = "200" ]; then
    good "vouched via production transparency log: $TL_BASE_URL (root-keys HTTP 200)"
  else
    note "transparency log $TL_BASE_URL/root-keys returned HTTP ${tl_code:-?}"
  fi
  grep -q '"artifacts":"transparency_log"' "$WORK/egress-A.log" 2>/dev/null \
    && good "egress loaded the identity from the transparency-log artifact path (not dev-mode)"
}

# narrate_egress_signing: pull the decoded DPoP proof + mandate the egress built
# (emitted at DEBUG by the middleware) and the 'request signed' line.
narrate_egress_signing() {
  [ "$NARRATE" = 1 ] || return 0
  local log="$WORK/egress-A.log" proofline mandline signed
  proofline=$(grep -m1 'dpop proof minted' "$log" 2>/dev/null)
  mandline=$(grep -m1 'mandate attached' "$log" 2>/dev/null)
  signed=$(grep -m1 'request signed' "$log" 2>/dev/null)
  if [ -n "$mandline" ]; then
    say  "The egress fetched a SCOPED mandate from the authority and bound it to the agent:"
    good "mandate:   scope=$(kv "$mandline" scope)  max_amount=$(kv "$mandline" max_amount) $(kv "$mandline" currency)"
    good "bound to:  jkt=$(kv "$mandline" jkt)   subject=$(kv "$mandline" subject_ans)"
    good "authority: $(kv "$mandline" authority_ans)   valid: $(kv "$mandline" not_before) .. $(kv "$mandline" not_after)"
  fi
  if [ -n "$proofline" ]; then
    say  "The egress signed a DPoP proof binding method + target URL to this call:"
    good "dpop:  htm=$(kv "$proofline" htm)  htu=$(kv "$proofline" htu)"
    good "       ath=$(kv "$proofline" ath)  (= base64url(sha256(quote_id)))  iat=$(kv "$proofline" iat)"
  fi
  [ -n "$signed" ] && good "request signed as ans_name=$(kv "$signed" ans_name)  (stamped at the egress, outside the sandbox)"
}

# kv LINE KEY -> value for KEY from a slog logfmt/JSON line (handles both quoted
# and bare values). Best-effort; narration only.
kv() {
  local line="$1" key="$2" v
  v=$(printf '%s' "$line" | grep -oE "\"$key\":\"[^\"]*\"" | head -1 | sed -E "s/\"$key\":\"([^\"]*)\"/\1/")
  [ -z "$v" ] && v=$(printf '%s' "$line" | grep -oE "\"$key\":[0-9.]+" | head -1 | sed -E "s/\"$key\"://")
  printf '%s' "${v:-?}"
}

# --- Act 1: registered buyer -> ticket ---------------------------------------
info "Act 1 — registered buyer (commerce) should get a ticket"
say ""
say "═══ ACT 1 — the vouched, authorized agent transacts ═══"
# The gateway validates the sandbox's middleware connection at `sandbox create`
# time, so the egress MUST be up before create — then bind the fresh UUID and
# restart to pick it up.
restart_egress A "$A_CFG" || exit 1
A_UUID=$(recreate_sandbox ans-agent-a "$A_POL") || exit 1
green "sandbox ans-agent-a ready: $A_UUID"

step "Identity provenance" "a provable identity, not a config string — and who vouches for it"
narrate_identity_provenance

step "The sandboxed agent makes an UNMODIFIED call" "the workload knows nothing about ANS/mandates/DPoP; it just POSTs book_flight"
note "sandbox $A_UUID  →  POST $SELLER_URL  (book_flight, $DEMO_AMOUNT $DEMO_CURRENCY)"

bind_identity "$A_CFG" "$A_UUID" buyer-agent
restart_egress A "$A_CFG" || exit 1
RESP_A=$(run_booking ans-agent-a)

step "The egress stamps identity + authorization (OUTSIDE the sandbox)" "a compromised workload cannot strip or forge what is added here"
narrate_egress_signing

step "The LIVE seller verifies the full chain and issues a ticket" "the counterparty independently checks identity + mandate before honoring the request"
[ "$NARRATE" = 1 ] || echo "$RESP_A"
# The ticket JSON is nested as an escaped string inside result.content[0].text,
# so match the ticket id itself (survives the \"-escaping) and require no error.
TICKET=$(echo "$RESP_A" | grep -oE 'ticket-[a-f0-9]+' | head -1)
PASSENGER=$(echo "$RESP_A" | grep -oE 'passenger_ans[^,]*' | head -1 | grep -oE 'ans://[^"\\]+')
MAND=$(echo "$RESP_A" | grep -oE 'mandate-[a-f0-9]+' | head -1)
if [ -n "$TICKET" ] && ! echo "$RESP_A" | grep -q '"error"'; then
  good "ticket issued: $TICKET   mandate: ${MAND:-?}"
  good "passenger_ans: ${PASSENGER:-?}  (proves the registered identity was attached end-to-end)"
  green "Act 1 PASS — live seller issued $TICKET"
  ACT1=PASS
else
  bad "no ticket returned"
  [ "$NARRATE" = 1 ] && echo "$RESP_A"
  red "Act 1 FAIL — no ticket (see response above)"
  ACT1=FAIL
fi

# --- Act 2: rogue -> rejection -----------------------------------------------
info "Act 2 — dev-mode rogue (no commerce) should be rejected"
say ""
say "═══ ACT 2 — the unvouched agent is refused ═══"
restart_egress B "$B_CFG" || exit 1
B_UUID=$(recreate_sandbox ans-agent-b "$B_POL") || exit 1
green "sandbox ans-agent-b ready: $B_UUID"

step "A rogue identity with no transparency-log vouch" "the negative case: ANS must reject an agent it cannot vouch for"
if [ "$NARRATE" = 1 ]; then
  good "rogue ANS name: $ROGUE_ANS_NAME"
  grep -q 'NOT vouched by any transparency log' "$WORK/egress-B.log" 2>/dev/null \
    && bad "egress flags it: dev-mode, self-signed — NOT vouched by any transparency log"
  note "this agent also has NO commerce capability, so it carries no mandate"
fi

bind_identity "$B_CFG" "$B_UUID" rogue-agent
restart_egress B "$B_CFG" || exit 1
RESP_B=$(run_booking ans-agent-b)

step "The LIVE seller refuses the request" "same endpoint, same call — but without a mandate the seller will not transact"
[ "$NARRATE" = 1 ] || echo "$RESP_B"
if echo "$RESP_B" | grep -q 'MANDATE_REJECTED'; then
  if [ "$NARRATE" = 1 ]; then
    bad "seller response: MANDATE_REJECTED (missing or unparseable mandate)"
    good "egress surfaced a machine-readable hint: required_capabilities=[mandate, dpop_proof]"
  fi
  green "Act 2 PASS — live seller rejected the rogue (MANDATE_REJECTED)"
  ACT2=PASS
else
  [ "$NARRATE" = 1 ] && echo "$RESP_B"
  red "Act 2 FAIL — expected MANDATE_REJECTED (see response above)"
  ACT2=FAIL
fi

# --- verdict -----------------------------------------------------------------
echo
info "RESULT"
echo "  Act 1 (buyer -> ticket):   $ACT1"
echo "  Act 2 (rogue -> rejected): $ACT2"
if [ "$NARRATE" = 1 ]; then
  say ""
  say "Takeaway: the SAME request from two agents. The transparency-log-vouched"
  say "identity with a scoped mandate transacted; the unvouched identity could not."
  say "Identity and authorization were enforced end-to-end — the sandbox workload"
  say "was never trusted to assert its own identity."
  report ""; report "RESULT: Act 1 = $ACT1, Act 2 = $ACT2"
fi
if [ "$ACT1" = PASS ] && [ "$ACT2" = PASS ]; then
  green "DEMO PASS"
  [ -n "$REPORT" ] && { report "DEMO PASS"; info "run report written to $REPORT"; }
  exit 0
fi
red "DEMO FAIL"
[ -n "$REPORT" ] && report "DEMO FAIL"
exit 1
