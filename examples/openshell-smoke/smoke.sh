#!/usr/bin/env bash
# Runs the ANS identity extension against a real OpenShell gateway, supervisor
# and sandbox and asserts the identity guarantees end to end. Everything the
# run needs is minted into a temporary directory: identity material, the
# gateway's JWT signing key, and a private CA for the middleware listener.
# Nothing in the repository holds a key, and the production ANS transparency
# log is never contacted.
#
# Checks, in order:
#   1. an authorized sandbox's plain POST reaches the callee signed, and the
#      callee returns the operator-assigned ANS identity;
#   2. identity headers the workload forges are replaced before the callee
#      sees them;
#   3. a request that never passes the middleware is rejected by the callee,
#      which logs the rejection (this also arms the sentinel used next);
#   4. a sandbox whose id is not approved for the identity is denied before
#      the callee is reached;
#   5. with the middleware stopped, the request is blocked (fail_closed).
#
# The in-process demo (make demo) covers replay and body tampering; this script
# covers what only a real runtime can show: that OpenShell invokes the service,
# applies its header mutations, and blocks traffic when it is down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/openshell-smoke"
KEEP_RUNNING=0
PRINT_CONFIG=0

usage() {
  cat <<USAGE
usage: $0 [--keep-running] [--print-config]

Builds the extension, downloads the pinned OpenShell release, starts a local
gateway with the ANS middleware registered, creates a sandbox, and runs the
identity assertions. Exits non-zero when any assertion fails.

Options:
  --keep-running   After the assertions pass, leave the stack up for
                   interactive use until Ctrl-C.
  --print-config   Print the rendered gateway configuration and exit.
  -h, --help       Show this help.

Environment:
  ANS_SMOKE_HOST      Non-loopback IPv4 address of this machine that sandbox
                      containers can reach. Detected when unset.
  ANS_SMOKE_CACHE     Where OpenShell release assets are cached.
                      Default: \${XDG_CACHE_HOME:-\$HOME/.cache}/ans-openshell-smoke
  ANS_SMOKE_LOG_LEVEL Gateway log level (default: info).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-running) KEEP_RUNNING=1 ;;
    --print-config) PRINT_CONFIG=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=examples/openshell-smoke/openshell-release.env
source "$EXAMPLE_DIR/openshell-release.env"

require_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL missing required command: $1" >&2; exit 1; }
}
for cmd in curl docker go jq tar; do require_command "$cmd"; done

sha256_matches() {
  # $1: expected hex digest, $2: file
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$2" | awk '{ print $1 }')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$2" | awk '{ print $1 }')"
  else
    echo "FAIL neither sha256sum nor shasum is available" >&2
    exit 1
  fi
  [[ "$actual" == "$1" ]]
}

detect_service_host() {
  local address
  if [[ -n "${ANS_SMOKE_HOST:-}" ]]; then
    printf '%s\n' "$ANS_SMOKE_HOST"
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    # Prefer a LAN interface: the default route is often a VPN tunnel that the
    # container VM cannot reach.
    local candidate
    for candidate in $(ifconfig -l 2>/dev/null); do
      [[ "$candidate" == en* ]] || continue
      address="$(ipconfig getifaddr "$candidate" 2>/dev/null || true)"
      if [[ -n "$address" && "$address" != 127.* ]]; then
        printf '%s\n' "$address"
        return
      fi
    done
  fi
  if command -v ip >/dev/null 2>&1; then
    address="$(ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    if [[ -n "$address" ]]; then
      printf '%s\n' "$address"
      return
    fi
  fi
  if command -v hostname >/dev/null 2>&1; then
    address="$(hostname -I 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i !~ /^127\./ && $i !~ /:/) { print $i; exit } }')"
    if [[ -n "$address" ]]; then
      printf '%s\n' "$address"
      return
    fi
  fi
  echo "FAIL could not detect a non-loopback host address; set ANS_SMOKE_HOST" >&2
  exit 1
}

SERVICE_HOST="$(detect_service_host)"
if [[ "$SERVICE_HOST" == 127.* || "$SERVICE_HOST" == *:* || "$SERVICE_HOST" == localhost ]]; then
  echo "FAIL ANS_SMOKE_HOST must be a non-loopback IPv4 address: $SERVICE_HOST" >&2
  exit 1
fi

# The gateway talks to the Docker daemon over its Unix socket. The current
# context names it, which also covers runtimes that do not use the default path.
DOCKER_SOCKET="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
DOCKER_SOCKET="${DOCKER_SOCKET#unix://}"
if [[ -z "$DOCKER_SOCKET" || "$DOCKER_SOCKET" == *://* || ! -S "$DOCKER_SOCKET" ]]; then
  echo "FAIL the Docker context does not expose a local Unix socket (got '${DOCKER_SOCKET:-none}')" >&2
  exit 1
fi
docker info --format '{{.ID}}' >/dev/null \
  || { echo "FAIL the Docker daemon at $DOCKER_SOCKET is not reachable" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Working directory, ports, cleanup
# ---------------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ans-openshell-smoke.XXXXXX")"
LOG_DIR="$WORK/logs"
FIXTURES="$WORK/fixtures"
BIN="$WORK/bin"
# Every OpenShell path (config, state, CLI gateway registrations) lives under
# WORK so the run never touches a real installation.
export XDG_CONFIG_HOME="$WORK/xdg/config"
export XDG_STATE_HOME="$WORK/xdg/state"
export XDG_DATA_HOME="$WORK/xdg/data"
export OPENSHELL_LOCAL_TLS_DIR="$WORK/gateway-tls"
unset OPENSHELL_GATEWAY OPENSHELL_GATEWAY_ENDPOINT OPENSHELL_SANDBOX_POLICY OPENSHELL_COMPUTE_DRIVER OPENSHELL_DRIVERS
mkdir -p "$LOG_DIR" "$BIN" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME"

RUN_ID="ans-smoke-$$-$RANDOM"
MIDDLEWARE_NAME="ans-identity-smoke"
# Docker namespace for everything the gateway creates. One per run, so two runs
# on one daemon never reach each other's sandboxes (see write_gateway_config);
# the pid lets reclaim_dead_runs tell a dead run's leftovers from a live run's.
DOCKER_SANDBOX_LABEL_PREFIX="ans-openshell-smoke-"
DOCKER_SANDBOX_LABEL="$DOCKER_SANDBOX_LABEL_PREFIX$$"
# The workload image is tagged by its Dockerfile's checksum so repeated runs
# reuse the build and a Dockerfile change forces a new one.
WORKLOAD_IMAGE="ans-openshell-smoke-workload:$(cksum "$EXAMPLE_DIR/workload/Dockerfile" | awk '{ print $1 }')"
SANDBOX_NAME="ans-$$"
UNAPPROVED_SANDBOX_NAME="ans-rogue-$$"
GATEWAY_PID=""
MIDDLEWARE_PID=""
CALLEE_PID=""
declare -a CREATED_SANDBOXES=()
declare -a CLI=()

# sandbox_containers prints the ids of every container the Docker driver
# created for this run's sandboxes, running or exited.
sandbox_containers() {
  local name
  for name in ${CREATED_SANDBOXES[@]+"${CREATED_SANDBOXES[@]}"}; do
    run_bounded 30 docker ps -aq --filter "label=openshell.ai/sandbox-namespace=$DOCKER_SANDBOX_LABEL" \
      --filter "label=openshell.ai/sandbox-name=$name" 2>/dev/null
  done | tr '\n' ' '
}

# capture_container_logs saves the stdout and stderr of every container the
# driver created for this run's sandboxes. The supervisor's log is the only
# place a middleware_failed verdict explains itself (TLS handshake, connect
# timeout, JWT audience), and cleanup destroys those containers.
capture_container_logs() {
  local id name
  for id in $(sandbox_containers); do
    name="$(run_bounded 10 docker inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's|^/||' || true)"
    run_bounded 30 docker logs "$id" >"$LOG_DIR/container-${name:-$id}.log" 2>&1 || true
  done
}

# label_resources prints "KIND ID LABEL" for every container and volume the
# Docker driver created under any sandbox namespace, running or exited. Like
# every Docker call on the teardown path it is bounded, so a wedged daemon
# cannot keep cleanup from reaching the key removal.
label_resources() {
  run_bounded 30 docker ps -a --filter label=openshell.ai/sandbox-namespace \
    --format 'container {{.ID}} {{.Label "openshell.ai/sandbox-namespace"}}'
  run_bounded 30 docker volume ls --filter label=openshell.ai/sandbox-namespace \
    --format 'volume {{.Name}} {{.Label "openshell.ai/sandbox-namespace"}}'
}

# remove_resources force-removes the "KIND ID LABEL" lines it reads on stdin.
remove_resources() {
  local kind id _label
  while read -r kind id _label; do
    run_bounded 30 docker "$kind" rm -f "$id" >>"$LOG_DIR/setup.log" 2>&1 || true
  done
}

# reclaim_dead_runs removes what earlier runs that died before their own
# cleanup left on the daemon: everything under a harness label whose pid no
# longer runs. A label whose pid is alive is a run in progress and is left
# alone; its gateway never sees this run's label either.
reclaim_dead_runs() {
  local kind id label pid stale=""
  while read -r kind id label; do
    [[ "$label" == "$DOCKER_SANDBOX_LABEL_PREFIX"* ]] || continue
    pid="${label#"$DOCKER_SANDBOX_LABEL_PREFIX"}"
    [[ "$pid" =~ ^[0-9]+$ && "$pid" != "$$" ]] || continue
    ps -p "$pid" -o pid= >/dev/null 2>&1 && continue
    stale+="$kind $id $label"$'\n'
  done < <(label_resources)
  [[ -n "$stale" ]] || return 0
  echo "WARN removing what earlier smoke runs left on the daemon:" >&2
  printf '%s' "$stale" | awk '{ print "WARN   " $1 " " $2 " (" $3 ")" }' >&2
  printf '%s' "$stale" | remove_resources
}

# run_bounded SECONDS CMD...: runs CMD with a wall-clock deadline so a stalled
# registry pull or a hung RPC becomes a failure with logs instead of a hang.
# Uses coreutils timeout where present (Linux; gtimeout from Homebrew coreutils)
# and a background watchdog otherwise (stock macOS). The watchdog's output goes
# nowhere: inside "$(run_bounded ...)" it would otherwise hold the capture pipe
# open until its sleep ends, and a command that finished at once would not
# return to the caller before the whole deadline had passed.
run_bounded() {
  local seconds="$1" timeout_cmd
  shift
  for timeout_cmd in timeout gtimeout; do
    if command -v "$timeout_cmd" >/dev/null 2>&1; then
      "$timeout_cmd" "$seconds" "$@"
      return
    fi
  done
  "$@" &
  local pid=$!
  (
    trap 'kill "$sleeper" 2>/dev/null; exit 0' TERM
    sleep "$seconds" &
    sleeper=$!
    wait "$sleeper"
    kill "$pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  local watchdog=$!
  local status=0
  wait "$pid" || status=$?
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  return "$status"
}

# stop_process PID sends TERM, allows ten seconds, then KILLs what is left.
stop_process() {
  kill "$1" 2>/dev/null || true
  for _ in {1..100}; do
    kill -0 "$1" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT
  # Everything below runs whatever fails along the way, the Docker daemon
  # included, and a second Ctrl-C does not cut it short: every step is
  # bounded, and the minted keys are removed last.
  set +e
  trap '' INT
  # fail already captured the container logs on an assertion failure; this
  # covers a Ctrl-C or an unexpected exit, before the sandboxes go away.
  [[ $status -eq 0 ]] || capture_container_logs
  if [[ ${#CLI[@]} -gt 0 ]]; then
    for name in ${CREATED_SANDBOXES[@]+"${CREATED_SANDBOXES[@]}"}; do
      run_bounded 60 "${CLI[@]}" sandbox delete "$name" >>"$LOG_DIR/setup.log" 2>&1
    done
    # The gateway removes a sandbox's containers, then its volumes, in a
    # background task after the delete RPC returns, and stopping a supervisor
    # can take ten seconds or more. Give the driver up to a minute before
    # taking the gateway down; whatever it did not get to is removed below.
    local deadline=$((SECONDS + 60))
    while ((SECONDS < deadline)); do
      kill -0 "$GATEWAY_PID" 2>/dev/null || break
      [[ -z "$(sandbox_containers)" ]] && break
      sleep 0.5
    done
  fi
  for pid in "$GATEWAY_PID" "$MIDDLEWARE_PID" "$CALLEE_PID"; do
    [[ -z "$pid" ]] || stop_process "$pid"
  done
  label_resources | awk -v label="$DOCKER_SANDBOX_LABEL" '$3 == label' | remove_resources
  if [[ $status -eq 0 || -z "$(ls -A "$LOG_DIR" 2>/dev/null)" ]]; then
    rm -rf "$WORK"
  else
    # Keep the logs for diagnosis, never the minted private keys, the gateway
    # database or the CLI client certificate.
    rm -rf "$FIXTURES" "$OPENSHELL_LOCAL_TLS_DIR" "$WORK/xdg" "$BIN" "$WORK"/gateway.db*
    echo "logs retained in $LOG_DIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

port_is_free() {
  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then return 1; fi
    return 0
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 1; fi
  return 0
}

choose_port_block() {
  local count="$1" start offset
  for _ in {1..200}; do
    start=$((20000 + RANDOM % 20000))
    for ((offset = 0; offset < count; offset++)); do
      port_is_free "$((start + offset))" || continue 2
    done
    printf '%s\n' "$start"
    return
  done
  echo "FAIL no free local port block" >&2
  exit 1
}

PORT_BASE="$(choose_port_block 5)"
MIDDLEWARE_PORT="$PORT_BASE"
MIDDLEWARE_HEALTH_PORT="$((PORT_BASE + 1))"
CALLEE_PORT="$((PORT_BASE + 2))"
GATEWAY_PORT="$((PORT_BASE + 3))"
GATEWAY_HEALTH_PORT="$((PORT_BASE + 4))"
GATEWAY_ENDPOINT="https://127.0.0.1:$GATEWAY_PORT"
# The sandbox dials the callee by this authority; the middleware signs for it
# and the callee verifies against it (pop trusted host).
CALLEE_AUTHORITY="host.openshell.internal:$CALLEE_PORT"

fail() {
  printf 'FAIL %s\n' "$1" >&2
  capture_container_logs
  local log
  for log in "$LOG_DIR"/*.log; do
    printf '\n--- %s ---\n' "$log" >&2
    tail -n 60 "$log" >&2
  done
  exit 1
}

step() {
  local label="$1"
  shift
  printf 'INFO %s\n' "$label"
  { printf '\n== %s ==\n+' "$label"; printf ' %q' "$@"; printf '\n'; } >>"$LOG_DIR/setup.log"
  "$@" >>"$LOG_DIR/setup.log" 2>&1 || fail "$label"
}

wait_for_http() {
  local label="$1" url="$2" pid="$3" attempts="${4:-60}"
  for _ in $(seq 1 "$attempts"); do
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      fail "$label exited early"
    fi
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      printf 'INFO %s is ready\n' "$label"
      return
    fi
    sleep 1
  done
  fail "$label did not become ready at $url"
}

# ---------------------------------------------------------------------------
# OpenShell release assets, verified against the pinned checksums
# ---------------------------------------------------------------------------
# The checksum variables are assigned by openshell-release.env.
# shellcheck disable=SC2154
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) CLI_ASSET=openshell-x86_64-unknown-linux-musl; GW_ASSET=openshell-gateway-x86_64-unknown-linux-gnu
    CLI_SHA="$OPENSHELL_CLI_SHA256_x86_64_unknown_linux_musl"; GW_SHA="$OPENSHELL_GATEWAY_SHA256_x86_64_unknown_linux_gnu" ;;
  Linux-aarch64 | Linux-arm64) CLI_ASSET=openshell-aarch64-unknown-linux-musl; GW_ASSET=openshell-gateway-aarch64-unknown-linux-gnu
    CLI_SHA="$OPENSHELL_CLI_SHA256_aarch64_unknown_linux_musl"; GW_SHA="$OPENSHELL_GATEWAY_SHA256_aarch64_unknown_linux_gnu" ;;
  Darwin-arm64) CLI_ASSET=openshell-aarch64-apple-darwin; GW_ASSET=openshell-gateway-aarch64-apple-darwin
    CLI_SHA="$OPENSHELL_CLI_SHA256_aarch64_apple_darwin"; GW_SHA="$OPENSHELL_GATEWAY_SHA256_aarch64_apple_darwin" ;;
  *) echo "FAIL unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

CACHE="${ANS_SMOKE_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/ans-openshell-smoke}/$OPENSHELL_VERSION"
mkdir -p "$CACHE"

# fetch_asset NAME SHA BINARY: downloads the release tarball once, verifies it
# against the pinned digest, and extracts BINARY into the run directory.
# Everything it prints goes to stderr so the callers below can read nothing
# but the binary path from stdout.
fetch_asset() {
  local name="$1" sha="$2" bin="$BIN/$3"
  local dest="$CACHE/$name.tar.gz"
  if [[ ! -f "$dest" ]]; then
    printf 'INFO downloading %s %s\n' "$OPENSHELL_VERSION" "$name" >&2
    curl -fsSL --retry 3 --retry-max-time 600 --connect-timeout 15 \
      --speed-limit 1024 --speed-time 30 --max-time 600 -o "$dest.partial" \
      "https://github.com/NVIDIA/OpenShell/releases/download/$OPENSHELL_VERSION/$name.tar.gz"
    mv "$dest.partial" "$dest"
  fi
  if ! sha256_matches "$sha" "$dest"; then
    rm -f "$dest"
    fail "checksum mismatch for $name; the download was discarded"
  fi
  # The binary is extracted from the verified tarball on every run, into the
  # run's own directory, so what executes is always what the checksum covered.
  tar -xzf "$dest" -C "$BIN" "$3"
  chmod 0755 "$bin"
  printf '%s\n' "$bin"
}

CLI_BIN="$(fetch_asset "$CLI_ASSET" "$CLI_SHA" openshell)"
GATEWAY_BIN="$(fetch_asset "$GW_ASSET" "$GW_SHA" openshell-gateway)"
[[ -x "$CLI_BIN" && -x "$GATEWAY_BIN" ]] || fail "release binaries are not executable: $CLI_BIN $GATEWAY_BIN"
printf 'INFO openshell %s\n' "$("$CLI_BIN" --version 2>&1 | head -n 1)"

# ---------------------------------------------------------------------------
# Build the extension and mint the fixtures
# ---------------------------------------------------------------------------
step "building the extension" go build -C "$ROOT" -o "$BIN/" ./cmd/ans-openshell-middleware ./cmd/ans-reference-callee ./examples/openshell-smoke/fixtures
step "minting fixtures" "$BIN/fixtures" -out "$FIXTURES" -middleware-host "$SERVICE_HOST"
if ! docker image inspect "$WORKLOAD_IMAGE" >/dev/null 2>&1; then
  step "building the workload image $WORKLOAD_IMAGE" run_bounded 600 docker build -q -t "$WORKLOAD_IMAGE" "$EXAMPLE_DIR/workload"
fi
IDENTITY="$(jq -r .identity "$FIXTURES/manifest.json")"
ANS_NAME="$(jq -r .ansName "$FIXTURES/manifest.json")"
AGENT_ID="$(jq -r .agentId "$FIXTURES/manifest.json")"

# The gateway's own TLS bundle (listener certificate, CLI client certificate)
# comes from OpenShell's generator; our fixtures supply the JWT signing key so
# the middleware can be given the matching JWKS.
step "generating gateway TLS material" "$GATEWAY_BIN" generate-certs --output-dir "$OPENSHELL_LOCAL_TLS_DIR" \
  --server-san "$SERVICE_HOST" --server-san 127.0.0.1
rm -rf "$OPENSHELL_LOCAL_TLS_DIR/jwt"
cp -R "$FIXTURES/gateway/jwt" "$OPENSHELL_LOCAL_TLS_DIR/jwt"

# ---------------------------------------------------------------------------
# Service configuration
# ---------------------------------------------------------------------------
write_middleware_config() {
  # $1: sandbox_identities YAML flow map, e.g. "{}" or "{<uuid>: example-agent}"
  cat >"$WORK/middleware.yaml" <<YAML
listen: "0.0.0.0:$MIDDLEWARE_PORT"
health_listen: "127.0.0.1:$MIDDLEWARE_HEALTH_PORT"
tls:
  cert_file: $FIXTURES/middleware-tls/tls.crt
  key_file: $FIXTURES/middleware-tls/tls.key
auth:
  gateway_issuer: openshell-gateway:$RUN_ID
  audience: urn:openshell:extension:middleware:$MIDDLEWARE_NAME
  jwks_file: $FIXTURES/gateway/jwks.json
transparency_log:
  root_keys_file: $FIXTURES/tl-root-keys.txt
identities:
  $IDENTITY:
    ans_name: $ANS_NAME
    agent_id: $AGENT_ID
    key_file: $FIXTURES/identity/key.pem
    cert_file: $FIXTURES/identity/cert.pem
    receipt_file: $FIXTURES/identity/receipt.cose
    status_token_file: $FIXTURES/identity/status-token.cose
sandbox_identities: $1
YAML
}

write_gateway_config() {
  cat >"$WORK/gateway.toml" <<TOML
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"

# Supervisors run in the Docker daemon's network namespace. On a VM-backed
# runtime that is not this machine, so they are pointed at the LAN address the
# gateway, middleware and callee all listen on; host.openshell.internal in the
# sandbox resolves to the same address. The sandbox_label scopes the gateway's
# startup reconciliation, which removes every supervisor container in its
# label, to this run: an OpenShell install sharing the daemon keeps its
# sandboxes, and so does a concurrent smoke run, which has a label of its own.
[openshell.drivers.docker]
socket_path = "$DOCKER_SOCKET"
grpc_endpoint = "https://$SERVICE_HOST:$GATEWAY_PORT"
sandbox_label = "$DOCKER_SANDBOX_LABEL"
supervisor_image = "$OPENSHELL_SUPERVISOR_IMAGE"
sandbox_runtime_image = "$OPENSHELL_SANDBOX_IMAGE"

[openshell.gateway.gateway_jwt]
signing_key_path = "$OPENSHELL_LOCAL_TLS_DIR/jwt/signing.pem"
public_key_path = "$OPENSHELL_LOCAL_TLS_DIR/jwt/public.pem"
kid_path = "$OPENSHELL_LOCAL_TLS_DIR/jwt/kid"
gateway_id = "$RUN_ID"

# The ANS middleware. OpenShell authenticates the service by the fixture CA
# and requires the request hook, so a service that stopped advertising it
# would be refused instead of silently skipped.
[[openshell.supervisor.middleware]]
name = "$MIDDLEWARE_NAME"
grpc_endpoint = "https://$SERVICE_HOST:$MIDDLEWARE_PORT"
tls_ca_cert_path = "$FIXTURES/middleware-tls/ca.crt"
max_payload_bytes = 1048576
timeout = "2s"
binding_policy = "allowlist"
bindings = ["http_request_pre_credentials"]
TOML
}

write_gateway_config
write_middleware_config "{}"
if [[ $PRINT_CONFIG -eq 1 ]]; then
  cat "$WORK/gateway.toml" "$WORK/middleware.yaml"
  exit 0
fi

render_policy() {
  sed -e "s/__MIDDLEWARE_NAME__/$MIDDLEWARE_NAME/" -e "s/__IDENTITY__/$IDENTITY/" -e "s/__CALLEE_PORT__/$CALLEE_PORT/" \
    "$EXAMPLE_DIR/policy.template.yaml" >"$WORK/policy.yaml"
}
render_policy
reclaim_dead_runs

# ---------------------------------------------------------------------------
# Start the callee, the middleware, then the gateway
# ---------------------------------------------------------------------------
start_callee() {
  "$BIN/ans-reference-callee" --listen "0.0.0.0:$CALLEE_PORT" \
    --root-keys-file "$FIXTURES/tl-root-keys.txt" \
    --trusted-host "$CALLEE_AUTHORITY" \
    --allow-ans-name "$ANS_NAME" >"$LOG_DIR/callee.log" 2>&1 &
  CALLEE_PID=$!
}

start_middleware() {
  printf '\n== middleware start %s ==\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$LOG_DIR/middleware.log"
  "$BIN/ans-openshell-middleware" --config "$WORK/middleware.yaml" --log-level debug >>"$LOG_DIR/middleware.log" 2>&1 &
  MIDDLEWARE_PID=$!
  wait_for_http "middleware" "http://127.0.0.1:$MIDDLEWARE_HEALTH_PORT/readyz" "$MIDDLEWARE_PID"
}

stop_middleware() {
  stop_process "$MIDDLEWARE_PID"
  MIDDLEWARE_PID=""
  for _ in {1..30}; do
    port_is_free "$MIDDLEWARE_PORT" && return
    sleep 0.2
  done
  fail "middleware port did not close"
}

start_callee
# The callee has no health route; its first signed request is the readiness check.
for _ in {1..30}; do
  (exec 3<>"/dev/tcp/127.0.0.1/$CALLEE_PORT") 2>/dev/null && break
  kill -0 "$CALLEE_PID" 2>/dev/null || fail "callee exited early"
  sleep 0.5
done
start_middleware

printf 'INFO starting gateway %s on %s\n' "$OPENSHELL_VERSION" "$GATEWAY_ENDPOINT"
"$GATEWAY_BIN" --config "$WORK/gateway.toml" --compute-driver docker \
  --bind-address 0.0.0.0 --port "$GATEWAY_PORT" --health-port "$GATEWAY_HEALTH_PORT" --metrics-port 0 \
  --log-level "${ANS_SMOKE_LOG_LEVEL:-info}" --db-url "sqlite://$WORK/gateway.db" >"$LOG_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
wait_for_http "gateway" "http://127.0.0.1:$GATEWAY_HEALTH_PORT/healthz" "$GATEWAY_PID" 120

step "registering the gateway with the CLI" "$CLI_BIN" gateway add "$GATEWAY_ENDPOINT" --local --name smoke
CLI=("$CLI_BIN" --gateway smoke)

middleware_negotiated() {
  "${CLI[@]}" gateway info --output json \
    | jq -e --arg name "$MIDDLEWARE_NAME" '.extensions[] | select(.configured_name == $name)' >/dev/null
}
step "verifying the gateway negotiated the middleware" middleware_negotiated

# ---------------------------------------------------------------------------
# Sandboxes
# ---------------------------------------------------------------------------
# create_sandbox NAME: creates the sandbox and prints its gateway-issued id.
# Callers add NAME to CREATED_SANDBOXES themselves: this runs inside a command
# substitution, where an append would never reach the parent shell.
create_sandbox() {
  local name="$1"
  step "creating sandbox $name" run_bounded 600 "${CLI[@]}" sandbox create --name "$name" --from "$WORKLOAD_IMAGE" \
    --policy "$WORK/policy.yaml" --no-tty --detach -- sleep infinity 1>&2
  "${CLI[@]}" sandbox get "$name" --output json | jq -r '.id'
}

# sandbox_curl NAME [curl args...]: POSTs to the callee from inside the sandbox
# and prints the response body followed by the HTTP status on its own line.
sandbox_curl() {
  local name="$1"
  shift
  run_bounded 90 "${CLI[@]}" sandbox exec --name "$name" --no-tty -- \
    curl -sS --max-time 20 -w '\n%{http_code}' "$@" "http://$CALLEE_AUTHORITY/v1/tasks" \
    -H 'content-type: application/json' --data '{"task":"settle invoice 42"}'
}

# response_status / response_body split sandbox_curl output.
response_status() { tail -n 1 <<<"$1"; }
response_body() { sed '$d' <<<"$1"; }

CREATED_SANDBOXES+=("$SANDBOX_NAME")
SANDBOX_ID="$(create_sandbox "$SANDBOX_NAME")"
[[ -n "$SANDBOX_ID" && "$SANDBOX_ID" != null ]] || fail "could not read the sandbox id"
printf 'INFO sandbox %s has id %s\n' "$SANDBOX_NAME" "$SANDBOX_ID"

# Approve exactly this sandbox for the identity; the operator-owned map is
# the only thing that grants signing.
write_middleware_config "{$SANDBOX_ID: $IDENTITY}"
stop_middleware
start_middleware

PASS=0
check() {
  printf 'PASS %s\n' "$1"
  PASS=$((PASS + 1))
}

# 1. Authorized sandbox: the callee returns the assigned identity. The
# middleware was just restarted to approve the sandbox, and the supervisor's
# gRPC channel to it (5 s connect timeout, 10 s keepalive) takes a few seconds
# to notice and reconnect; until then OpenShell reports middleware_failed and
# blocks the request, which is the fail_closed behavior check 4 asserts.
STATUS=""
for attempt in 1 2 3 4 5 6; do
  OUT="$(sandbox_curl "$SANDBOX_NAME")" || fail "authorized request did not complete"
  STATUS="$(response_status "$OUT")"
  BODY="$(response_body "$OUT")"
  [[ "$STATUS" == 200 ]] && break
  printf 'INFO attempt %d: status %s (%s), retrying\n' "$attempt" "$STATUS" \
    "$(jq -r '[.error, .reason_code] | map(select(. != null)) | join(" ")' <<<"$BODY" 2>/dev/null || printf 'unparsed')"
  sleep 3
done
[[ "$STATUS" == 200 ]] || fail "authorized request: status $STATUS, body: $BODY"
[[ "$(jq -r .caller <<<"$BODY")" == "$ANS_NAME" && "$(jq -r .agentId <<<"$BODY")" == "$AGENT_ID" ]] \
  || fail "callee returned another identity: $BODY"
check "authorized sandbox is verified as $ANS_NAME"

# 2. Forged identity headers from the workload are replaced, not relayed.
OUT="$(sandbox_curl "$SANDBOX_NAME" -H 'DPoP: forged' -H 'X-SCITT-Receipt: forged' -H 'X-ANS-Status-Token: forged')" \
  || fail "forged-header request did not complete"
STATUS="$(response_status "$OUT")"
BODY="$(response_body "$OUT")"
[[ "$STATUS" == 200 && "$(jq -r .caller <<<"$BODY")" == "$ANS_NAME" ]] \
  || fail "forged headers were not replaced: status $STATUS, body: $BODY"
check "forged identity headers are replaced with the operator-assigned identity"

# Probe: a request that bypasses OpenShell is rejected by the callee, and the
# callee logs the rejection. Checks 3 and 4 infer "the callee was never
# reached" from its log not growing, so that sentinel is proven live here
# before it is relied on.
CALLEE_LINES_BEFORE="$(wc -l <"$LOG_DIR/callee.log")"
STATUS="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -X POST "http://127.0.0.1:$CALLEE_PORT/v1/tasks" \
  -H "Host: $CALLEE_AUTHORITY" -H 'content-type: application/json' --data '{"task":"settle invoice 42"}')"
[[ "$STATUS" == 401 ]] || fail "unsigned direct request: status $STATUS"
[[ "$(wc -l <"$LOG_DIR/callee.log")" -gt "$CALLEE_LINES_BEFORE" ]] || fail "the callee did not log the rejected direct request; the not-reached checks would be vacuous"
check "unsigned direct request is rejected by the callee (401) and logged"

# 3. A sandbox that is not approved for the identity is denied before the
# callee: the callee's log, which the probe above showed grows on every
# rejected request, must not grow.
CREATED_SANDBOXES+=("$UNAPPROVED_SANDBOX_NAME")
create_sandbox "$UNAPPROVED_SANDBOX_NAME" >/dev/null
CALLEE_LINES_BEFORE="$(wc -l <"$LOG_DIR/callee.log")"
OUT="$(sandbox_curl "$UNAPPROVED_SANDBOX_NAME")" || true
STATUS="$(response_status "$OUT")"
BODY="$(response_body "$OUT")"
[[ "$STATUS" == 403 ]] || fail "unapproved sandbox: status $STATUS, body: $BODY"
grep -q 'middleware_denied' <<<"$BODY" || fail "unapproved sandbox: not a middleware denial: $BODY"
grep -q 'ans_identity_unauthorized' <<<"$BODY" || fail "unapproved sandbox: unexpected reason: $BODY"
[[ "$(wc -l <"$LOG_DIR/callee.log")" -eq "$CALLEE_LINES_BEFORE" ]] || fail "the callee saw the denied request"
check "unapproved sandbox is denied (ans_identity_unauthorized) and the callee is not reached"

# 4. Middleware unavailable: fail_closed blocks the request.
stop_middleware
CALLEE_LINES_BEFORE="$(wc -l <"$LOG_DIR/callee.log")"
OUT="$(sandbox_curl "$SANDBOX_NAME")" || true
STATUS="$(response_status "$OUT")"
BODY="$(response_body "$OUT")"
[[ "$STATUS" == 403 ]] || fail "middleware down: status $STATUS, body: $BODY"
grep -q 'middleware_failed' <<<"$BODY" || fail "middleware down: not a middleware failure: $BODY"
[[ "$(wc -l <"$LOG_DIR/callee.log")" -eq "$CALLEE_LINES_BEFORE" ]] || fail "the callee saw the request while the middleware was down"
check "request is blocked while the middleware is unavailable (fail_closed)"
start_middleware

printf 'ALL PASS %d checks against OpenShell %s (%s)\n' "$PASS" "$OPENSHELL_VERSION" "${OPENSHELL_COMMIT:0:7}"

if [[ $KEEP_RUNNING -eq 1 ]]; then
  cat <<EOT

READY the stack stays up until Ctrl-C.
  gateway:     $GATEWAY_ENDPOINT   (CLI: $CLI_BIN --gateway smoke, XDG_CONFIG_HOME=$XDG_CONFIG_HOME)
  middleware:  https://$SERVICE_HOST:$MIDDLEWARE_PORT
  callee:      http://$CALLEE_AUTHORITY
  sandbox:     $SANDBOX_NAME ($SANDBOX_ID)
  logs:        $LOG_DIR
Signed request from the sandbox:
  XDG_CONFIG_HOME=$XDG_CONFIG_HOME $CLI_BIN --gateway smoke sandbox exec --name $SANDBOX_NAME --no-tty -- curl -sS http://$CALLEE_AUTHORITY/v1/tasks -H 'content-type: application/json' --data '{"task":"hello"}'
EOT
  while kill -0 "$GATEWAY_PID" 2>/dev/null && kill -0 "$MIDDLEWARE_PID" 2>/dev/null; do sleep 1; done
  fail "a process exited"
fi
