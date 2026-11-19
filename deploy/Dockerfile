# syntax=docker/dockerfile:1
# Build: docker build -f deploy/Dockerfile --build-arg CMD=ans-openshell-middleware --build-arg VERSION=0.1.0 -t ans-openshell-middleware .
ARG GO_VERSION=1.26.9
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG CMD=ans-openshell-middleware
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/${CMD} ./cmd/${CMD}

FROM gcr.io/distroless/static-debian12:nonroot
ARG CMD=ans-openshell-middleware
COPY --from=build /out/${CMD} /usr/local/bin/app
COPY LICENSE NOTICE /usr/share/licenses/ans/
COPY LICENSES/MIT.txt /usr/share/licenses/ans/LICENSES/MIT.txt
COPY third_party/openshell/LICENSE third_party/openshell/README.md /usr/share/licenses/ans/third_party/openshell/
LABEL org.opencontainers.image.licenses="Apache-2.0 AND MIT"
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/app"]
CMD ["--config", "/etc/ans-openshell/config.yaml"]
