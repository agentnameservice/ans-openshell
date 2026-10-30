// Command ans-reference-callee runs an HTTP service that authenticates callers
// with ANS-6 Method B and echoes the proven identity.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/callee"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 5 * time.Second
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ans-reference-callee:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen         = flag.String("listen", ":8443", "address to listen on")
		rootKeysFile   = flag.String("root-keys-file", "", "file of newline-delimited C2SP transparency log root keys (required unless --tl-base-url is set)")
		tlBaseURL      = flag.String("tl-base-url", "", "transparency log base URL for live root-key refresh")
		sellerURL      = flag.String("seller-url", "", "upstream seller URL for forwarding verified requests")
		requireReceipt = flag.Bool("require-receipt", true, "require SCITT receipts on incoming requests")
		tlsCert        = flag.String("tls-cert", "", "serving certificate PEM (plain HTTP when empty)")
		tlsKey         = flag.String("tls-key", "", "serving key PEM")
		trustedHosts   stringList
		allowedNames   stringList
	)
	flag.Var(&trustedHosts, "trusted-host", "externally visible authority (host[:port]) callers sign for; repeatable, required")
	flag.Var(&allowedNames, "allow-ans-name", "ans:// name to accept; repeatable; all proven agents when empty")
	flag.Parse()

	var keys []string
	if *rootKeysFile != "" {
		var err error
		keys, err = callee.ReadRootKeys(*rootKeysFile)
		if err != nil {
			return err
		}
	} else if *tlBaseURL == "" {
		return errors.New("--root-keys-file is required when --tl-base-url is not set")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	h, err := callee.New(ctx, callee.Config{
		TLBaseURL:       *tlBaseURL,
		SellerURL:       *sellerURL,
		RequireReceipt:  *requireReceipt,
		RootKeys:        keys,
		TrustedHosts:    trustedHosts,
		AllowedAnsNames: allowedNames,
	}, logger)
	if err != nil {
		return err
	}
	defer h.Close()

	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	errc := make(chan error, 1)
	go func() {
		logger.InfoContext(ctx, "listening", "addr", *listen, "tls", *tlsCert != "")
		if *tlsCert != "" {
			errc <- srv.ListenAndServeTLS(*tlsCert, *tlsKey)
			return
		}
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
