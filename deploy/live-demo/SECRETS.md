# What the demo needs from the buyer agent

The demo signs each request as a **real ANS buyer identity**. Exactly **two
private keys** are required; everything else is public or generated per run.
Nothing with a value is committed to this repo — the agent owner shares a filled
`.env` plus the PEM files it points at, out-of-band.

## Required from the agent owner (out-of-band)

| Item | Kind | Carried by |
|---|---|---|
| `key.pem` | **PRIVATE** — the ANS identity signing key | a PEM file; path in `.env` as `BUYER_KEY_FILE` |
| `commerce-dpop.pem` | **PRIVATE** — the commerce DPoP (spend) key | a PEM file; path in `.env` as `BUYER_COMMERCE_DPOP_KEY` |
| `cert.pem` | public — the ANS identity certificate | a PEM file; path in `.env` as `BUYER_CERT_FILE` |
| `tl-root-keys.txt` | public — pinned GoDaddy TL root key(s) | a file; path in `.env` as `TL_ROOT_KEYS_FILE` |
| `.env` scalars | public — ans_name, agent_id, URLs, demo constants | the `.env` itself |

The two private keys authorize acting **as** the buyer ANS identity. In this
demo the buyer is a **disposable identity with no wallet**, so leaking the keys
cannot move money — but anyone holding them can present as that ANS name. Treat
the `.env` + PEMs as shareable only with people you trust to run the demo, and
revoke the identity (`ans-cli revoke <agent_id> --reason …`) if it is ever
misused. Do not commit them; `.gitignore` blocks `.env` and `*.pem`.

## Setup for someone receiving the bundle

1. Clone the repo and `cp deploy/live-demo/.env.example deploy/live-demo/.env`.
2. Drop the 3 PEMs + `tl-root-keys.txt` somewhere under your `$WORK` (e.g.
   `$WORK/secrets/buyer/`).
3. Edit `.env`: set `WORK`, `REPO`, `HOST_IP`, the four file paths, and paste
   the public identifiers (`BUYER_ANS_NAME`, `BUYER_AGENT_ID`, the seller /
   authority ANS names) the owner gave you. Or just use the `.env` the owner
   shared verbatim and only fix the paths to where you dropped the files.
4. Follow `RUNBOOK.md` from "Start the stack".

`run-demo.sh` renders all agent/policy configs from the `.env` at runtime, so
there is nothing else to edit.

## What `--narrate` displays

The reviewer-facing `--narrate` mode decodes and prints only **public** material:
the certificate (SAN + issuer), the authority mandate (scope, max_amount, the
`jkt` key *thumbprint*, parties, validity), and the DPoP proof *claims*
(`htm`/`htu`/`ath`/`iat`, where `ath` is a hash of the quote id). The two
private keys (`key.pem`, `commerce-dpop.pem`) are used to sign but are **never
printed** by the narrator or logged by the egress.
