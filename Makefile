GO ?= go
# golangci-lint must type-check with the Go version it was built against; override when the
# local toolchain is newer, e.g. LINT_GOTOOLCHAIN=go1.26.1.
LINT_GOTOOLCHAIN ?= local
BIN := bin
CMDS := ans-openshell-middleware ans-openshell-interceptor ans-ocsf-hydrator ans-reference-callee

.PHONY: all build proto test cover lint vet demo clean

all: build

build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do echo "building $$c"; $(GO) build -o $(BIN)/$$c ./cmd/$$c; done

proto:
	buf generate

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
