// Command demo runs the ANS extension end to end without OpenShell: it starts
// a fixture transparency log, the middleware service and the reference callee,
// then plays the sandbox supervisor. It sends EvaluateHttpRequest calls,
// applies the returned header mutations to real HTTP requests and shows the
// callee accepting the signed call and rejecting a replay, a tampered body,
// an unsigned request and a stripped one. It exits non-zero when any
// expectation fails, so it doubles as a smoke test.
package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if err := runDemo(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func runDemo() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := newDemo(ctx, os.Stdout)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	defer d.close()
	return d.run(ctx)
}
