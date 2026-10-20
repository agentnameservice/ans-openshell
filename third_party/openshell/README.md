# OpenShell protocol definitions

The `.proto` files in `proto/` are copied verbatim from
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) (`proto/` directory) at
the revision recorded in `VERSION`. They are licensed under the Apache License 2.0
(see `LICENSE`) and are not covered by this repository's MIT license.

Only the files needed by the supervisor-middleware and gateway-interceptor
contracts, and their transitive imports, are vendored. Go bindings are generated
into `gen/openshell` with `make proto`.
