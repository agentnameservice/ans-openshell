# OpenShell smoke test

Runs `ans-openshell-middleware` and `ans-reference-callee` against a real OpenShell gateway,
supervisor and sandbox, and asserts the identity guarantees the middleware makes. The in-process
demo (`make demo`) plays the supervisor itself; this test shows what only a real runtime can:
that OpenShell invokes the service, applies its header mutations before the request leaves,
and blocks the request when the service is down.

> OpenShell's supervisor-middleware contract is a research preview upstream and may change.
> The test pins one release; see [Updating the OpenShell pin](#updating-the-openshell-pin).

## What it does

```bash
make openshell-smoke
```

1. Builds the middleware, the callee and the fixture generator from this checkout, and a
   workload image ([workload/Dockerfile](workload/Dockerfile)): OpenShell's default workload
   image plus `curl`, the one binary the policy lets reach the callee.
2. Downloads the pinned OpenShell CLI and gateway release assets, verifies their SHA-256
   against [openshell-release.env](openshell-release.env), and caches them under
   `~/.cache/ans-openshell-smoke`.
3. Mints everything a deployment normally receives from elsewhere into a temporary directory:
   a fixture transparency-log root key; one registered identity with its key, certificate,
   receipt and status token; the gateway's Ed25519 JWT signing key with the matching JWKS;
   and a private CA with a serving certificate for the middleware's gRPC listener. The
   repository holds no key material and the production transparency log is never contacted.
4. Starts the callee, the middleware (TLS, gateway JWTs verified) and an OpenShell gateway on
   the Docker driver with the middleware registered under
   `binding_policy = "allowlist"` and `bindings = ["http_request_pre_credentials"]`.
5. Creates a sandbox with [policy.template.yaml](policy.template.yaml), reads its
   gateway-issued id, approves exactly that id for the identity in the middleware's
   `sandbox_identities`, and restarts the middleware.
6. Runs the assertions below and tears everything down. On failure the logs are kept, including
   each sandbox's supervisor container log, and the minted keys are not.

| Check | Expected observation |
|-------|----------------------|
| Authorized sandbox | A plain `POST /v1/tasks` from the workload reaches the callee signed; the callee returns the operator-assigned ANS name and agent id. |
| Forged identity headers | `DPoP`, `X-SCITT-Receipt` and `X-ANS-Status-Token` set by the workload are overwritten; the callee still verifies the assigned identity. |
| Unsigned direct request | A request to the callee that bypasses OpenShell is rejected with `401`, and the callee logs the rejection. This arms the sentinel the next two checks use. |
| Unapproved sandbox | A second sandbox whose id is not in `sandbox_identities` gets `403 middleware_denied` with reason `ans_identity_unauthorized`; the callee's log does not grow, so it never saw the request. |
| Middleware unavailable | With the middleware stopped, the request gets `403 middleware_failed` (`on_error: fail_closed`); the callee's log does not grow. |

Replay and body tampering are covered by the verifier's own tests and by `make demo`, and are
reported there, not here.

## Requirements

- Linux (x86_64 or arm64) or macOS on Apple silicon, with Bash, `curl`, `jq`, `tar`,
  `sha256sum` or `shasum`, and Go.
- A Docker daemon reachable over the Unix socket named by the current `docker context`, with
  host networking for the supervisor container (the OpenShell Docker driver's default), and
  access to `ghcr.io` and `nvcr.io` for the pinned supervisor and sandbox runtime images and
  the workload base image.
- A non-loopback IPv4 address on this machine that containers can reach. It is detected
  automatically; set `ANS_SMOKE_HOST` to override. For the duration of the run the gateway
  (mTLS), the middleware (TLS, gateway JWTs) and the callee (DPoP-verified) listen on all
  interfaces so the supervisor, which runs in the daemon's network namespace, can reach them.

The test never touches an existing OpenShell installation: it points `XDG_CONFIG_HOME`,
`XDG_STATE_HOME` and `OPENSHELL_LOCAL_TLS_DIR` at its temporary directory, so the gateway's
database, TLS bundle and the CLI's gateway registration all live and die with the run. On the
Docker daemon its gateway works under its own `sandbox_label`, `ans-openshell-smoke`, so the
startup reconciliation that removes a gateway's stray supervisor containers cannot reach another
gateway's sandboxes, and leftovers from a crashed run are reclaimed by the next one.

## Options

| Flag or variable | Effect |
|------------------|--------|
| `--keep-running` | After the assertions pass, keep the gateway, middleware, callee and sandbox up until Ctrl-C and print the commands to use them. |
| `--print-config` | Print the rendered `gateway.toml` and `middleware.yaml` and exit. |
| `ANS_SMOKE_HOST` | Address the gateway and sandboxes use to reach the middleware and callee. |
| `ANS_SMOKE_CACHE` | Where release assets are cached. |
| `ANS_SMOKE_LOG_LEVEL` | Gateway log level, default `info`. |

## Fixture trust versus production trust

The fixture transparency log is one ES256 key minted per run. Its root key is handed to the
middleware (`transparency_log.root_keys_file`) and to the callee (`--root-keys-file`), and the
identity's receipt and status token are pinned with `receipt_file` and `status_token_file`, so
the middleware verifies them against that key at startup and never fetches anything. In
production the middleware is given the real log's base URL and published root keys, fetches
and refreshes the artifacts itself, and the callee pins the same published keys. Nothing else
differs: the proof, the headers, the verifier and the sandbox authorization path are the
production code.

The gateway's own TLS bundle and the CLI's client certificate come from OpenShell's
`openshell-gateway generate-certs`; only the JWT signing key is replaced with the one the
fixtures minted so the middleware's JWKS matches.

## What is pinned, and how

| Artifact | Pin | Verified by |
|----------|-----|-------------|
| OpenShell CLI and gateway tarballs | SHA-256 per asset in [openshell-release.env](openshell-release.env) | `smoke.sh`, every run, before extraction into the run directory |
| Vendored extension protos | `OPENSHELL_COMMIT` in the same file | CI's proto-drift job diffs them against that commit |
| Supervisor and sandbox runtime images | manifest-list digests in the same file, passed to the gateway as `supervisor_image` and `sandbox_runtime_image` | the container engine, by digest |
| Workload base image | manifest-list digest in [workload/Dockerfile](workload/Dockerfile) | the container engine, by digest |

The `apt-get install curl` layer in the workload image is the one unpinned input; the identity
assertions do not rest on it, because the callee's own log corroborates the two denial checks and
its rejection logging is proven live first.

## Limitations

- `sandbox_identities` is read when the middleware starts. Approving a sandbox means editing the
  map and restarting the service, and until the supervisor's channel to it reconnects (a few
  seconds) matching requests fail closed with `middleware_failed`. The harness does exactly this
  and retries the first request through that window; a production operator would see the same
  window on every approval.
- The fixture status token lives one hour. A `--keep-running` stack stops signing when it lapses.
- Only Linux and macOS on Apple silicon are supported; the pinned release has no Intel macOS
  gateway build.

## Ownership

The harness, its OpenShell pin and the `OpenShell smoke` workflow are maintained by this
repository's maintainers under its normal [contribution process](../../CONTRIBUTING.md); a
maintainer roster is proposed in the governance change under review. File problems as issues
on this repository. The link from OpenShell's supervisor-middleware documentation belongs to
the upstream contribution and is not part of this repository.

## Updating the OpenShell pin

1. Edit [openshell-release.env](openshell-release.env): the version, the tag's commit, and the
   SHA-256 of each asset from the release's `openshell-checksums-sha256.txt` and
   `openshell-gateway-checksums-sha256.txt`.
2. Re-pin the vendored contract (`third_party/openshell`, then `make proto`) if the proto-drift
   job reports a difference at the new commit.
3. Run `make openshell-smoke`.
