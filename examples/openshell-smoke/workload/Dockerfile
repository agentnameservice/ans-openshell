# Workload image for the smoke test: OpenShell's default workload image plus
# curl, which the sandbox policy admits as the only binary allowed to reach the
# callee. Built by smoke.sh with the local container engine and passed to
# `openshell sandbox create --from`.
# Pinned to the multi-arch manifest digest of nvcr.io/nvidia/base/ubuntu:24.04
# so the image the sandbox runs is the one that was reviewed; bump the digest
# deliberately (docker buildx imagetools inspect <image>:24.04).
FROM nvcr.io/nvidia/base/ubuntu@sha256:d9461f428eea54e553add3a5158a0f245c6e1ea73efc59fff8e98e3d4a38e378
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && apt-get clean
