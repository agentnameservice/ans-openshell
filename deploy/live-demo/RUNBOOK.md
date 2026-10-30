# Runbook — live two-agent OpenShell commerce demo

A linear, do-this-then-that operator guide. Read `README.md` first for what the
demo proves and why the topology is what it is. This runbook assumes WSL2 +
Docker Desktop, the setup the reference run used.

Legend: `$WORK` = your machine-local work dir (default `~/openshell-live`),
`$REPO` = this repository checkout.

---

## 0. Prerequisites (one-time)

You MUST have your own **ANS buyer identity** — this repo does not and cannot
ship it:

- a GoDaddy-issued certificate with an `ans://…` SAN (`cert.pem`),
- its private key (`key.pem`),
- a commerce DPoP private key (`commerce-dpop.pem`).

Verify the cert is what you think it is and that the key matches it:

```sh
openssl x509 -in $WORK/secrets/<you>/cert.pem -noout -subject -ext subjectAltName
openssl x509 -in $WORK/secrets/<you>/cert.pem -noout -issuer          # GoDaddy … ANS Issuing CA
# key matches cert iff these two hashes are equal:
openssl pkey  -in $WORK/secrets/<you>/key.pem  -pubout | openssl dgst -sha256
openssl x509  -in $WORK/secrets/<you>/cert.pem -noout -pubkey | openssl dgst -sha256
```

Other machine-local material under `$WORK` (see README §one-time-setup):
`bin/openshell` (CLI v0.1.5), `pki/` (gateway mTLS+JWT), `tl-root-keys.txt`
(pinned GoDaddy TL root keys).

Build the binaries (the demo egress is `ans-demo-middleware` — the production
middleware plus the commerce tutorial transform; `make demo-build` generates a
gitignored `go.work` so the `tutorial/` module resolves the in-repo core):

```sh
cd $REPO && make demo-build    # ./bin/ans-demo-middleware (demo egress)
cd $REPO && make build         # ./bin/ans-reference-callee (ingress)
```

Fill the configs from the templates in this directory (absolute paths,
`<HOST_IP>` = `ip route get 1.1.1.1 | awk '{print $7}'`, and your identity in
`agent-a-local.yaml`):

```sh
for f in gw.toml agent-a-local.yaml agent-b-local.yaml policy-a.yaml policy-b.yaml; do
  cp $REPO/deploy/live-demo/$f.template $WORK/$f      # then edit $WORK/$f
done
```

---

## 1. Preflight checks (every run)

```sh
export PATH="/usr/bin:$PATH"                           # Linux docker, not docker.exe
export OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:17670"

# Docker daemon reachable:
/usr/bin/docker info >/dev/null && echo "docker OK"

# Clock not ahead of the seller (seller tolerates <=5s future; WSL2 drifts):
sudo systemctl restart systemd-timesyncd && sleep 2    # resync if in doubt

# GoDaddy production transparency log reachable:
curl -s -o /dev/null -w "TL /root-keys -> %{http_code}\n" https://transparency.ans.godaddy.com/root-keys
```

---

## 2. Start the stack (order matters)

The gateway dials every registered middleware at boot and refuses to start if
one is unreachable — so **egresses first, gateway last**.

```sh
cd $WORK
$REPO/bin/ans-demo-middleware --config $WORK/agent-a-local.yaml --log-level info >egress-a.log 2>&1 &
$REPO/bin/ans-demo-middleware --config $WORK/agent-b-local.yaml --log-level info >egress-b.log 2>&1 &
$WORK/bin/openshell-gateway --config $WORK/gw.toml \
  --port 17670 --bind-address 0.0.0.0 --health-port 17671 --log-level info >gateway.log 2>&1 &
```

Confirm each egress printed `grpc server listening` and loaded your identity
with `artifacts":"transparency_log"` (NOT `dev-mode … NOT vouched`), and that
the CLI can see the gateway:

```sh
grep -E 'identity loaded|grpc server listening' $WORK/egress-a.log
$WORK/bin/openshell sandbox list
```

---

## 3. Run the demo

```sh
WORK=$WORK $REPO/deploy/live-demo/run-demo.sh
```

The script recreates both sandboxes, binds their fresh UUIDs, restarts the
egresses, runs both acts, and prints the verdict. Success:

```
== RESULT
  Act 1 (buyer -> ticket):   PASS
  Act 2 (rogue -> rejected): PASS
DEMO PASS
```

### 3b. Reviewer walkthrough — `--narrate`

For a demo to someone evaluating ANS as an identity layer, run it narrated so
each step is explained and the real decoded artifacts are shown:

```sh
WORK=$WORK $REPO/deploy/live-demo/run-demo.sh --narrate --report /tmp/ans-demo.md
```

This prints a trust-boundary diagram, then numbered steps: identity provenance
(cert SAN + GoDaddy issuer + transparency-log vouch) → unmodified sandbox call →
egress stamps the decoded scoped mandate + DPoP proof → seller issues the ticket
→ the rogue is refused with a machine-readable hint. `--narrate` starts the
egresses at `--log-level debug` to surface the proof/mandate it builds (off in
the plain run). `--report FILE` saves an ANSI-free markdown copy. No private keys
are printed — only the public cert, mandate, and proof claims. See README
"Narrated mode" for the field-by-field meaning.

---

## 4. What "it worked" looks like (verification)

- **Act 1** returns a ticket whose `passenger_ans` is your buyer ANS name —
  proof the egress attached the real identity and the live seller honored it:
  ```
  ticket_id: ticket-…  mandate_id: mandate-…  passenger_ans: ans://…  price: 500 USD
  ```
- **Act 2** returns `MANDATE_REJECTED` with a `middleware_hint`
  (`required_capabilities: [mandate, dpop_proof]`) — the rogue reached the live
  seller but had no mandate, so it was refused.
- **Sandboxes are real Docker containers**, not stubs:
  ```sh
  /usr/bin/docker ps --format '{{.Names}} {{.Status}}' | grep ans-agent
  ```
- **Egress signed toward the public seller host** (grep the egress log):
  ```sh
  grep 'request signed' $WORK/egress-A.log   # host: seller.skybound-travel.com, ans_name: ans://…
  ```
- **The signed artifacts themselves** — run with `--narrate` (or start the egress
  at `--log-level debug`) and the egress log carries the decoded proof + mandate:
  ```sh
  grep -E 'dpop proof minted|mandate attached' $WORK/egress-A.log
  # dpop proof minted  htm=POST htu=…/mcp/ ath=… iat=…
  # mandate attached   scope=purchase:flight:demo max_amount=500 currency=USD jkt=… subject_ans=ans://…
  ```
  Cross-check: the mandate's `max_amount`/`scope` match your `.env` demo values,
  and the proof's `htu` equals the seller MCP URL — i.e. the narration reflects
  the real signed request, not canned text.

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| preflight `ABORT: clock … AHEAD` | host clock past the seller's 5s leeway | `sudo systemctl restart systemd-timesyncd` |
| `401 HTTP_BINDING_MISMATCH` | sandbox dialed a raw IP, not the seller hostname | use the hostname policy (templates here); never `http://<IP>:…` |
| `sandbox … ValidateConfig failed: tcp connect error` at create | egress not running when the gateway validated it | start the egress before `sandbox create` (the script already orders this) |
| `address already in use` on egress restart | previous egress hadn't released its port | the script waits for exit; if run by hand, `kill` and wait before restarting |
| egress logs `dev-mode … NOT vouched` for the buyer | wrong identity/config (dev_mode true or missing cert) | point `agent-a-local.yaml` at the real GoDaddy cert + key, `dev_mode: false` |
| `MANDATE_REJECTED` for Act 1 (not Act 2) | authority unreachable or mandate not prefetched | check the egress log for `demo mandate prefetched`; confirm `authority.skybound-travel.com` reachable |

---

## 6. Scope / honest caveats

- **Real** OpenShell (Rust gateway + Docker sandboxes), **real** GoDaddy
  production ANS identity, **real** sandbox→internet communication over TLS.
- The seller and authority (`*.skybound-travel.com`) are genuinely deployed and
  remote, but are **operator-controlled infrastructure** (a Cloudflare Worker +
  GCP services), not an independent third party.
- `scitt_receipt` is empty in the ticket by design — the live TL's receipt RA
  key isn't discoverable; the DPoP + certificate chain still verify.
