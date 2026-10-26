# Live two-agent OpenShell commerce demo

Proves the whole chain end-to-end against the **live** seller:

- **Act 1 — registered buyer:** an agent in an OpenShell sandbox calls
  `https://seller.skybound-travel.com/mcp/`. The Go `ans-egress` middleware
  injects the AP2 mandate + in-body DPoP + ANS identity proof; the live seller
  verifies and returns a **ticket**.
- **Act 2 — dev-mode rogue:** the same call from a rogue agent with no commerce
  capability is **rejected** by the live seller (`MANDATE_REJECTED`), and our
  pre-return stage surfaces the capability-negotiation `middleware_hint`.

This is the **direct-to-seller** topology (sandbox → egress → live seller). It
is deliberately different from `deploy/examples/`, which is the echo/ingress
topology (sandbox → egress → local `ans-reference-callee` → seller) used by the
unit tests. Don't mix them up: the direct-to-seller policies route by the seller
**hostname**, the examples route to a local ingress IP.

> **Prerequisite — you supply the identity, this repo does not.** The demo
> signs each request with a **real ANS buyer identity**: a GoDaddy-issued
> certificate whose SAN is `ans://…` plus its private key and a commerce DPoP
> key, issued by a `GoDaddy … ANS Issuing CA`. **Those private keys are NOT in
> this repo and never will be** — they live under `$WORK/secrets/` on the operator's
> machine. Without a valid ANS identity + keys the egress cannot start or sign,
> so the demo cannot run. To run it as someone else, substitute your own
> GoDaddy-issued ANS identity throughout (`agent-a-local.yaml` ans_name/agent_id
> + the three key files, and the `subject_ans`/`seller_ans` in the commerce
> block). The committed files here are secret-free scaffolding only.

## Why a script instead of pure copy-paste

Each `openshell sandbox create` mints a **fresh sandbox UUID**, and the egress
only signs for sandboxes it has been told to trust (`sandbox_identities`, no
wildcards). So every run must: create the sandbox → read its UUID → bind that
UUID in the egress config → restart the egress. `run-demo.sh` does exactly that
for both agents, then runs both acts and prints PASS/FAIL.

## Config: one `.env`, no values in the repo

All configuration — identity names, file paths, URLs, demo constants — lives in
a single **`.env`** file. `run-demo.sh` sources it and **renders** the agent and
policy configs into `$WORK` at runtime, so the repo carries no values and no
secrets. The committed `.env.example` lists every variable with placeholders;
`.env` and `*.pem` are gitignored. The agent owner shares a filled `.env` plus
the PEM files it points at, out-of-band. See `SECRETS.md` for exactly what is
required.

## One-time setup (the parts this repo can't carry)

The demo needs machine-local **secrets** and a **running gateway**, which live
OUTSIDE the repo (default: `~/openshell-live/`, referred to below as `$WORK`).
Nothing here is committed.

1. **Build the Go binaries** (from the repo root):
   ```sh
   make build          # produces ./bin/ans-openshell-middleware and ./bin/ans-reference-callee
   ```

2. **Lay out `$WORK`** (`~/openshell-live` by default):
   - `bin/openshell` — the OpenShell CLI (v0.1.5).
   - `pki/…` — gateway mTLS + JWT material (referenced by your `gw.toml`).
   - the buyer identity files wherever you like, e.g. `secrets/buyer/{key.pem,
     cert.pem,commerce-dpop.pem}` + `tl-root-keys.txt` — pointed to by `.env`.
   - a `gw.toml` for the gateway (absolute PKI paths + `<HOST_IP>`). The egress
     and policy configs are **rendered by `run-demo.sh`**, so you do not write
     them by hand.

3. **Create your `.env`:**
   ```sh
   cp deploy/live-demo/.env.example deploy/live-demo/.env   # then edit
   ```
   Fill in `WORK`, `REPO`, `HOST_IP` (your WSL eth0 IP: `ip route get 1.1.1.1 |
   awk '{print $7}'`), the four identity file paths, and the public identity
   values. If an owner shared a filled `.env`, use it and just fix the paths to
   where you dropped the PEM files. See `SECRETS.md`.

4. **Start the stack** (order matters — the gateway dials every registered
   middleware at boot and refuses to start if one is unreachable, so start the
   egresses first). With `/usr/bin` ahead on PATH so you get the Linux docker,
   not the Windows `docker.exe`:
   ```sh
   export PATH="/usr/bin:$PATH"
   export OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:17670"

   # egress A and B (the script also restarts these per run, but the gateway
   # needs them up at its own boot — render them first by running the script
   # once, or start from the configs run-demo.sh writes into $WORK):
   "$REPO/bin/ans-openshell-middleware" --config "$WORK/agent-a-local.yaml" --log-level info &
   "$REPO/bin/ans-openshell-middleware" --config "$WORK/agent-b-local.yaml" --log-level info &

   # gateway:
   "$WORK/bin/openshell-gateway" --config "$WORK/gw.toml" \
     --port 17670 --bind-address 0.0.0.0 --health-port 17671 --log-level info &
   ```
   Confirm the CLI can see the gateway: `"$WORK/bin/openshell" sandbox list`.

## Run it

```sh
./deploy/live-demo/run-demo.sh          # sources deploy/live-demo/.env
# or: ENV_FILE=/path/to/.env ./deploy/live-demo/run-demo.sh
```

Expected tail:

```
== RESULT
  Act 1 (buyer -> ticket):   PASS
  Act 2 (rogue -> rejected): PASS
DEMO PASS
```

Act 1's raw line looks like:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"ticket_id\":\"ticket-…\",\"mandate_id\":\"mandate-…\",\"passenger_ans\":\"ans://<your-buyer-ans-name>\",\"flight\":{…,\"price\":500,\"currency\":\"USD\"},…}"}]}}
```

`passenger_ans` proves the registered ANS identity was attached by the egress.

## Narrated mode (for reviewers) — `--narrate`

The plain run above is a terse pass/fail check. For someone evaluating **ANS as
the identity layer** (e.g. the missing identity piece in an agent-security model
like SAFE), run it narrated:

```sh
./deploy/live-demo/run-demo.sh --narrate
./deploy/live-demo/run-demo.sh --narrate --report run-report.md   # also write a markdown report
```

`--narrate` prints a trust-boundary diagram and walks each step with **what** it
does, **why** it matters, and the **real decoded evidence** pulled live:

- **Identity provenance** — the cert's `ans://` SAN + the **GoDaddy** issuing CA,
  the production transparency-log vouch (`root-keys` HTTP 200), and that the
  egress loaded the identity via the transparency-log path (not dev-mode).
- **Unmodified sandbox call** — the workload just POSTs `book_flight`; it knows
  nothing about ANS, mandates, or DPoP.
- **Egress stamps identity + authorization** — the decoded **scoped mandate**
  (`scope`, `max_amount`, the `jkt` key-binding, authority, validity window) and
  the signed **DPoP proof** claims (`htm`/`htu`/`ath`/`iat`), proving the
  authorization is cryptographic and bound, added *outside* the sandbox.
- **Seller verifies → ticket**; then the **rogue contrast**: an unvouched
  dev-mode identity with no mandate is refused (`MANDATE_REJECTED`) with a
  machine-readable `middleware_hint`.

The decoded proof/mandate come from the egress's **DEBUG logs** — `--narrate`
starts the egresses at `--log-level debug` to surface them. The plain run leaves
debug off, so those lines never appear in normal operation. **No private keys
are ever printed** — only the public cert, the mandate, and the proof claims
(the `jkt` and `ath` are a key thumbprint and a hash, not secrets).

`--report FILE` writes the same narrative + decoded artifacts to a markdown file
(ANSI-free) for after-the-fact review.

## Gotchas (both bite in practice)

- **Dial the hostname, not the IP.** The sandbox must POST to
  `https://seller.skybound-travel.com/mcp/`. The OpenShell network policy routes
  that hostname (synthetic DNS `198.18.x.x`) through the egress, so the
  middleware sees `target.host == seller.skybound-travel.com` and the commerce
  transform fires. Dial a raw IP and the commerce gate misses → no mandate, no
  `SignURL` → the egress signs the wrong `htu` → `401 HTTP_BINDING_MISMATCH`.
- **Clock skew.** A DPoP proof dated in the seller's *future* is rejected
  (`DPOP_REJECTED: proof age -Ns`). The deployed seller now tolerates up to 5s
  of future skew (RFC 9449 §11.1 clock-skew leeway); the demo's own host clock
  can still drift further ahead than that under WSL2, so `run-demo.sh` aborts in
  preflight if it measures ≥5s ahead. Fix: `sudo systemctl restart
  systemd-timesyncd`.
- **`scitt_receipt` is empty** in the ticket — expected (the live TL's RA key
  isn't discoverable; the DPoP + cert chain still verify). Egress runs with the
  receipt requirement relaxed for the demo.
