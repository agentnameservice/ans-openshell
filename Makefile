GO ?= go
# golangci-lint must type-check with the Go version it was built against; override when the
# local toolchain is newer, e.g. LINT_GOTOOLCHAIN=go1.26.1.
LINT_GOTOOLCHAIN ?= local
BIN := bin
CMDS := ans-openshell-middleware ans-openshell-interceptor ans-ocsf-hydrator ans-reference-callee

.PHONY: all build demo-build workspace proto test cover lint vet demo clean

all: build

build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do echo "building $$c"; $(GO) build -o $(BIN)/$$c ./cmd/$$c; done

# The tutorial (dev-only demo) module lives in ./tutorial and consumes the core
# via a Go workspace. go.work is gitignored; `workspace` (re)generates it with a
# version-pinned replace so the module resolves the in-repo core. It is harmless
# to run repeatedly.
workspace:
	rm -f go.work go.work.sum
	$(GO) work init . ./tutorial
	$(GO) work edit -replace github.com/agentnameservice/ans-openshell@v0.0.0=./

# demo-build produces the dev-only demo binary (production middleware + the
# commerce tutorial transform). run-demo.sh runs this binary, not the prod one.
demo-build: workspace
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/ans-demo-middleware ./tutorial/cmd/ans-demo-middleware

# Generated code must match CI byte for byte. protoc-gen-go formats its output with the
# go/format of the toolchain that built it, so the plugins are built with the CI toolchain.
PROTO_GOTOOLCHAIN ?= go1.26.9
PROTOC_GEN_GO_VERSION := v1.36.12
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2

proto:
	@mkdir -p $(BIN)
	GOBIN=$(abspath $(BIN)) GOTOOLCHAIN=$(PROTO_GOTOOLCHAIN) $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(abspath $(BIN)) GOTOOLCHAIN=$(PROTO_GOTOOLCHAIN) $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	PATH="$(abspath $(BIN)):$$PATH" buf generate

test:
	$(GO) test -race ./...

cover:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	@grep -v -e '/gen/' -e '/cmd/' -e '/examples/' coverage.out > coverage.lib.out
	@$(GO) tool cover -func=coverage.lib.out | tail -1

lint:
	GOTOOLCHAIN=$(LINT_GOTOOLCHAIN) golangci-lint run ./...

vet:
	$(GO) vet ./...

demo:
	$(GO) run ./examples/demo

clean:
	rm -rf $(BIN) coverage*.out
