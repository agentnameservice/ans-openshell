# ans-openshell

ANS identity for agents running in [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell).

An agent inside an OpenShell sandbox never sees its own credentials: the supervisor outside the
sandbox injects them. This repository extends that model to agent identity. A supervisor
middleware signs every allowed outbound request as the sandbox's registered
[Agent Name Service](https://github.com/agentnameservice/ans-registry) (ANS) agent using
ANS-6 Method B (a DPoP proof plus the agent's transparency-log receipt and status token), so any
callee that implements ANS-6 can verify who is calling without the sandbox ever holding the
identity key. A gateway interceptor vets destination hosts against ANS registration before a
policy is committed, and a hydrator turns OpenShell's OCSF audit export into Trust Index
observations.

| Binary | Purpose |
| --- | --- |
| `ans-openshell-middleware` | OpenShell supervisor middleware (`PRE_CREDENTIALS`): mints the ANS-6 proof, staples the receipt and status token, optionally vets the destination |
| `ans-openshell-interceptor` | OpenShell gateway interceptor (`validate`): denies or annotates proposed network policies whose hosts are not registered ANS agents |
| `ans-ocsf-hydrator` | Aggregates OCSF JSONL into signed Trust Index observations |
| `ans-reference-callee` | Demo callee that verifies ANS-6 Method B callers with the SDK's `pop.Middleware` |

Example configurations for every service are under [deploy/examples](deploy/examples). The reason
codes the middleware and the interceptor return to the gateway are defined in
`internal/middleware/reasons.go` and `internal/vetting/verdict.go`.

## Status

v0.1, research preview. OpenShell's supervisor-middleware and gateway-interceptor contracts are
themselves marked as research previews upstream and may change. The extension is built against
the OpenShell protos recorded in `third_party/openshell/VERSION` and ANS SDK v0.1.19.

## Quick start

Build everything:

```bash
make build
```

Run the in-process demo, which starts a fake transparency log, the middleware service, a
reference callee, and plays the supervisor: it sends an `EvaluateHttpRequest`, applies the
returned header mutations to a real HTTP request and shows the callee accepting the signed call
and rejecting a replay, a tampered body and an unsigned request:

```bash
make demo
```

Run the tests:

```bash
make cover
```

## Running the services

Every service takes one YAML file. Flags: `--config` (required), `--listen` to override the
configured address, `--log-level` (`debug`, `info`, `warn`, `error`), `--log-format` (`json`,
`text`) and `--version`. Both services expose plaintext `GET /healthz` and `GET /readyz` on
`health_listen` (default `:8081`) for probes.

```bash
./bin/ans-openshell-middleware --config deploy/examples/middleware.yaml
./bin/ans-openshell-interceptor --config deploy/examples/interceptor.yaml
```

The hydrator is a batch job over the sandbox supervisors' OCSF records. Enable OpenShell's JSON
export with `openshell settings set --global --key ocsf_json_enabled --value true`; each
supervisor then writes one `OCSF-JSON` line per event to its stderr and, where its `/var/log` is
writable, to `/var/log/openshell-ocsf.<date>.jsonl` inside the supervisor container. Collect
either with your log pipeline into a file the hydrator can read, one bare line per record: it
accepts raw supervisor stderr lines and plain JSONL, aggregates per agent and posts one batch.
`--window-last 15m` restricts a scheduled run to the trailing window so it does not re-post the
whole file. The gateway's own `ocsf_log` JSONL holds gateway-origin events only, not sandbox
traffic, so it is not the input.

```bash
./bin/ans-ocsf-hydrator --config deploy/examples/hydrator.yaml --input supervisor-ocsf.jsonl --window-last 15m
```

`--dry-run` prints the import request instead of posting it; `--window-start` and
`--window-end` (RFC 3339) pin the observation window. The job exits non-zero when events were
parsed but none mapped to a configured agent, which usually means the sandbox mapping drifted;
`--allow-unmapped` accepts that. The Trust Index admin key comes from
`trust_index.admin_key_file` or the `ANS_TRUST_INDEX_ADMIN_KEY` environment variable.

The reference callee takes flags only:

```bash
./bin/ans-reference-callee --listen :8443 --root-keys-file tl-root-keys.txt --trusted-host callee.example:8443
```

## Deploying with OpenShell

1. Register the services in the gateway configuration: see
   [deploy/examples/gateway.toml](deploy/examples/gateway.toml). The middleware needs
   `max_payload_bytes` large enough for the request bodies your agents send, because the body is
   hashed into the proof.
2. Configure the middleware with the identities sandboxes may sign as:
   [deploy/examples/middleware.yaml](deploy/examples/middleware.yaml). Each identity is an ANS
   registration (ANS name, agent id) plus its Identity Certificate and P-256 key, read from files
   or mounted secrets. The transparency log base URL and its pinned root keys let the service
   fetch and refresh the receipt and status token in the background.
3. Provision the gateway's JWKS (its `/.well-known/jwks.json`) as `auth.jwks_file` so the service
   can authenticate the gateway and the sandbox supervisors on their first call.
4. Bind the middleware in sandbox policies: [deploy/examples/policy.yaml](deploy/examples/policy.yaml).
   `config.identity` picks the identity; `config.destination_policy` chooses `off`, `observe` or
   `require_registered`. After creating the sandbox, approve its gateway-issued ID in the
   middleware service configuration: `sandbox_identities: {<sandbox-id>: payments-agent}`.
   Restart the service (or upgrade its Helm values) to apply the approval. Until then, signing
   is denied. Sandbox names and workspace labels cannot grant identity access.
5. Optionally register the interceptor ([deploy/examples/interceptor.yaml](deploy/examples/interceptor.yaml))
   to vet hosts when sandboxes are created, policies are updated, custom provider profiles are
   imported or updated, and Advisor proposals are submitted, edited or approved. An operation
   naming more than 64 destinations is denied under `require_registered`, so import large profile
   sets in batches. Approving a stored draft installs a rule the request does not carry, so the
   interceptor resolves it from the gateway state attached to the evaluation (`current_state`,
   which must carry the draft policy's `chunks`); the pinned OpenShell release does not populate
   that state, so under `require_registered` draft approvals are refused until it does, while
   `observe` allows and annotates them. Proposals are vetted when submitted or edited, so before
   moving a gateway from `observe` to `require_registered` clear its pending drafts. Proposals the
   gateway auto-approves (`proposal_approval_mode` auto) never pass through the approve RPCs and
   are vetted at submission only. Built-in provider profiles never pass through an interceptable
   RPC, so the interceptor cannot vet their endpoints; the middleware still vets the destination
   of every signed request, so under its `require_registered` list the built-in endpoints your
   sandboxes use in the middleware's `vetting.exempt_hosts`, as exact hosts where possible: a
   `*.suffix` pattern exempts every host under it.
6. Ship the collected supervisor OCSF feed to the hydrator ([deploy/examples/hydrator.yaml](deploy/examples/hydrator.yaml))
   on a schedule to feed the Trust Index; the Helm chart's CronJob reads `hydrator.input` from a
   volume your log collector writes. The signal ids it emits are configurable; the Trust
   Index must register them before it scores them.

A Helm chart for both gRPC services is in [deploy/helm/ans-openshell](deploy/helm/ans-openshell)
and a multi-stage Dockerfile in [deploy/Dockerfile](deploy/Dockerfile).

## How a signed request looks to the callee

```http
POST /v1/tasks HTTP/1.1
Host: tools.example.com
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwiandr...
X-SCITT-Receipt: 0oRDoQEmoQRQ...
X-ANS-Status-Token: 0oRDoQEmoQRQ...
Authorization: Bearer <provider credential injected by OpenShell after the middleware ran>
```

The callee verifies the proof's signature under the certificate in `x5c`, checks the certificate
fingerprint against the status token's valid identity certificates, checks the certificate's
`ans://` name against the status token and the receipt, confirms `htm`, `htu` and
`ans_content_digest` match the request it received, and rejects a reused `jti`. The SDK's
`pop.Middleware` does all of this; `cmd/ans-reference-callee` shows the wiring.

## Security notes

- The middleware is a signing oracle for the identities it holds. It authenticates every caller
  with the OpenShell extension JWT and only mints proofs for a supervisor's own sandbox. Do not
  run it with `allow_insecure_no_auth` outside local development.
- Policy authors can request an identity, but the operator-owned `sandbox_identities` map must
  authorize that exact sandbox ID and identity before any proof is issued. Missing bindings
  deny signing, including in local unauthenticated mode.
- Stale or missing artifacts, signer errors and unverifiable destinations under
  `require_registered` all deny. Bind the middleware with `on_error: fail_closed` and `order`
  last so no later middleware rewrites a signed request. Signing rejects raw or percent-encoded
  OpenShell credential placeholders in the body or URL path: OpenShell substitutes them after
  `PRE_CREDENTIALS`, which would invalidate the proof. Credential headers and query-only
  substitution remain supported.
- `require_registered` screens destination registration; the current OpenShell API does not
  provide the actual TLS peer certificate, so ANS-6 server-certificate binding is not implemented.
  Normal TLS CA/hostname verification still applies.
- OAuth `ath` binding is not available at `PRE_CREDENTIALS` because the injected bearer token is
  not visible to middleware; proofs carry no `ath`, which RFC 9449 permits when no DPoP-bound
  token is presented.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): Developer Certificate of Origin sign-off on every commit,
Conventional Commits, and disclosure of AI assistance. Security issues go to the address in
[SECURITY.md](SECURITY.md).

## License

MIT (see [LICENSE](LICENSE)). The OpenShell protocol definitions under `third_party/openshell`
are Apache-2.0, copyright NVIDIA Corporation & Affiliates.
