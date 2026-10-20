// Command ans-ocsf-hydrator turns OpenShell's OCSF audit export into signed
// behavioral observations for the ANS Trust Index.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/hydrator"
	"github.com/agentnameservice/ans-openshell/internal/logging"
	"github.com/agentnameservice/ans-openshell/pkg/provenance"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// adminKeyEnv names the environment variable that supplies the Trust Index
// admin key when trust_index.admin_key_file is not set.
const adminKeyEnv = "ANS_TRUST_INDEX_ADMIN_KEY"

type fileConfig struct {
	TrustIndex struct {
		BaseURL      string `yaml:"base_url"`
		AdminKeyFile string `yaml:"admin_key_file"`
	} `yaml:"trust_index"`
	Provenance struct {
		AIMID       string `yaml:"aim_id"`
		EvidenceURL string `yaml:"evidence_url"`
	} `yaml:"provenance"`
	Signals struct {
		PolicyViolationRate *string `yaml:"policy_violation_rate"`
		ProtocolAdherence   *string `yaml:"protocol_adherence"`
	} `yaml:"signals"`
	Signing struct {
		KeyFile  string `yaml:"key_file"`
		CertFile string `yaml:"cert_file"`
	} `yaml:"signing"`
	Agents []hydrator.AgentMapping `yaml:"agents"`
}

type flags struct {
	configPath, input, windowStart, windowEnd string
	windowLast                                time.Duration
	dryRun, allowUnmapped                     bool
}

// A run that yields nothing is usually misconfiguration rather than a quiet
// period, so it fails instead of quietly starving the Trust Index: no events in
// a non-empty input is the shape of a feed with ocsf_json_enabled off or a
// collector wrapping the lines, and no attributed event at all is mapping drift.
var (
	errNoEvents          = errors.New("input had lines but no OCSF events; check that ocsf_json_enabled is set and that the collector writes bare lines (set --allow-unmapped to accept this)")
	errNothingAttributed = errors.New("events were parsed but none of them mapped to a configured agent (set --allow-unmapped to accept this)")
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ans-ocsf-hydrator:", err)
		os.Exit(1)
	}
}

func run() error {
	var f flags
	flag.StringVar(&f.configPath, "config", "", "path to the YAML configuration (required)")
	flag.StringVar(&f.input, "input", "-", "OCSF JSONL file, or - for stdin")
	flag.BoolVar(&f.dryRun, "dry-run", false, "print the import request instead of posting it")
	flag.BoolVar(&f.allowUnmapped, "allow-unmapped", false, "exit 0 when the input yields no OCSF events or none of them map to an agent")
	flag.StringVar(&f.windowStart, "window-start", "", "RFC 3339 start of the observation window (default: first event)")
	flag.StringVar(&f.windowEnd, "window-end", "", "RFC 3339 end of the observation window (default: last event)")
	flag.DurationVar(&f.windowLast, "window-last", 0, "aggregate only the trailing duration before now, e.g. 15m; an alternative to --window-start/--window-end")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	logFormat := flag.String("log-format", "json", "json or text")
	showVer := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVer {
		fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if f.configPath == "" {
		return errors.New("--config is required")
	}
	logger, err := logging.New(*logLevel, *logFormat, os.Stderr)
	if err != nil {
		return err
	}
	var cfg fileConfig
	if err := config.Load(f.configPath, &cfg); err != nil {
		return err
	}
	opts, err := buildOptions(cfg, f)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sink, err := buildSink(ctx, cfg, f.dryRun, logger)
	if err != nil {
		return err
	}
	in, closeInput, err := openInput(f.input)
	if err != nil {
		return err
	}
	defer closeInput()

	report, err := hydrator.Run(ctx, in, sink, opts, logger)
	logReport(ctx, logger, cfg.Agents, report, err)
	if err != nil {
		return err
	}
	if err := emptyRunError(report, f.allowUnmapped); err != nil {
		logger.ErrorContext(ctx, "hydration rejected", "err", err)
		return err
	}
	return nil
}

// emptyRunError decides whether a run that posted nothing is a failure. A
// batch that did map but carried no network or HTTP activity is a quiet period
// and succeeds without posting; so does one whose events all fell outside an
// explicit window.
func emptyRunError(report hydrator.Report, allowEmpty bool) error {
	switch {
	case allowEmpty:
		return nil
	case report.Parse.Lines > 0 && report.Parse.Events == 0:
		return errNoEvents
	case report.Unmapped > 0 && report.Attributed == 0:
		return errNothingAttributed
	}
	return nil
}

func buildOptions(cfg fileConfig, f flags) (hydrator.Options, error) {
	if len(cfg.Agents) == 0 {
		return hydrator.Options{}, errors.New("agents: at least one agent mapping is required")
	}
	agents, err := hydrator.NewAgentMap(cfg.Agents)
	if err != nil {
		return hydrator.Options{}, err
	}
	if cfg.Provenance.AIMID == "" {
		return hydrator.Options{}, errors.New("provenance.aim_id is required")
	}
	signals, err := signalConfig(cfg)
	if err != nil {
		return hydrator.Options{}, err
	}
	opts := hydrator.Options{Agents: agents, Signals: signals, AIMID: cfg.Provenance.AIMID, EvidenceURL: cfg.Provenance.EvidenceURL}
	if opts.Signer, err = batchSigner(cfg); err != nil {
		return hydrator.Options{}, err
	}
	if opts.Window, err = windowFlags(f, time.Now()); err != nil {
		return hydrator.Options{}, err
	}
	return opts, nil
}

// windowFlags resolves the observation window: --window-last gives a trailing
// window ending now, the shape a scheduled job wants, and the explicit pair
// gives a fixed one.
func windowFlags(f flags, now time.Time) (*hydrator.Window, error) {
	explicit := f.windowStart != "" || f.windowEnd != ""
	switch {
	case f.windowLast < 0:
		return nil, errors.New("--window-last must be positive")
	case f.windowLast > 0 && explicit:
		return nil, errors.New("--window-last cannot be combined with --window-start or --window-end")
	case f.windowLast > 0:
		now = now.UTC()
		return &hydrator.Window{Start: now.Add(-f.windowLast), End: now}, nil
	case explicit:
		w, err := parseWindow(f.windowStart, f.windowEnd)
		if err != nil {
			return nil, err
		}
		return &w, nil
	}
	return nil, nil //nolint:nilnil // no window selects the span of the input
}

// signalConfig applies the optional signal id overrides; an empty id disables
// that signal.
func signalConfig(cfg fileConfig) (hydrator.SignalConfig, error) {
	signals := hydrator.DefaultSignalConfig()
	if cfg.Signals.PolicyViolationRate != nil {
		signals.PolicyViolationRateID = *cfg.Signals.PolicyViolationRate
		signals.EmitPolicyViolationRate = *cfg.Signals.PolicyViolationRate != ""
	}
	if cfg.Signals.ProtocolAdherence != nil {
		signals.ProtocolAdherenceID = *cfg.Signals.ProtocolAdherence
		signals.EmitProtocolAdherence = *cfg.Signals.ProtocolAdherence != ""
	}
	if !signals.EmitPolicyViolationRate && !signals.EmitProtocolAdherence {
		return hydrator.SignalConfig{}, errors.New("signals: every signal is disabled; nothing would be posted")
	}
	return signals, nil
}

// batchSigner loads the optional signing key pair; nil means unsigned batches.
func batchSigner(cfg fileConfig) (provenance.BatchSigner, error) {
	if cfg.Signing.KeyFile == "" && cfg.Signing.CertFile == "" {
		return nil, nil //nolint:nilnil // no signer configured is a valid, documented state
	}
	if cfg.Signing.KeyFile == "" || cfg.Signing.CertFile == "" {
		return nil, errors.New("signing.key_file and signing.cert_file must both be set")
	}
	keyPEM, err := os.ReadFile(cfg.Signing.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("signing.key_file: %w", err)
	}
	certPEM, err := os.ReadFile(cfg.Signing.CertFile)
	if err != nil {
		return nil, fmt.Errorf("signing.cert_file: %w", err)
	}
	return provenance.NewPEMSigner(keyPEM, certPEM)
}

func parseWindow(start, end string) (hydrator.Window, error) {
	if start == "" || end == "" {
		return hydrator.Window{}, errors.New("--window-start and --window-end must be given together")
	}
	s, err := time.Parse(time.RFC3339, start)
	if err != nil {
		return hydrator.Window{}, fmt.Errorf("--window-start: %w", err)
	}
	e, err := time.Parse(time.RFC3339, end)
	if err != nil {
		return hydrator.Window{}, fmt.Errorf("--window-end: %w", err)
	}
	if !e.After(s) {
		return hydrator.Window{}, errors.New("--window-end must be after --window-start")
	}
	return hydrator.Window{Start: s, End: e}, nil
}

func buildSink(ctx context.Context, cfg fileConfig, dryRun bool, logger *slog.Logger) (hydrator.Sink, error) {
	if dryRun {
		return hydrator.NewWriterSink(os.Stdout), nil
	}
	if cfg.TrustIndex.BaseURL == "" {
		return nil, errors.New("trust_index.base_url is required unless --dry-run is set")
	}
	key := os.Getenv(adminKeyEnv)
	if cfg.TrustIndex.AdminKeyFile != "" {
		b, err := os.ReadFile(cfg.TrustIndex.AdminKeyFile)
		if err != nil {
			return nil, fmt.Errorf("trust_index.admin_key_file: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" {
		logger.WarnContext(ctx, "no trust index admin key configured; posting without Authorization")
	}
	if strings.HasPrefix(strings.ToLower(cfg.TrustIndex.BaseURL), "http://") {
		logger.WarnContext(ctx, "trust index base url is plaintext http; the admin key and observations travel in the clear")
	}
	sink, err := hydrator.NewHTTPSink(cfg.TrustIndex.BaseURL, key, nil)
	if err != nil {
		return nil, err
	}
	sink.UserAgent = "ans-ocsf-hydrator/" + version
	return sink, nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("--input: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func logReport(ctx context.Context, logger *slog.Logger, configured []hydrator.AgentMapping, r hydrator.Report, runErr error) {
	if runErr != nil {
		logger.ErrorContext(ctx, "hydration failed", "err", runErr)
	}
	logger.InfoContext(ctx, "hydration summary",
		"lines", r.Parse.Lines, "events", r.Parse.Events, "skipped", r.Parse.Skipped, "attributed", r.Attributed,
		"unmapped", r.Unmapped, "no_container", r.NoContainer, "out_of_window", r.OutOfWindow,
		"agents", len(r.Agents), "observations", r.Observations, "posted", r.Posted, "signed", r.Signed,
		"window_start", r.Window.Start.Format(time.RFC3339), "window_end", r.Window.End.Format(time.RFC3339))
	seen := make(map[string]bool, len(r.Agents))
	for _, a := range r.Agents {
		seen[a.AgentID] = true
		logger.InfoContext(ctx, "agent summary", "agent_id", a.AgentID, "ans_name", a.AnsName,
			"events", a.Events, "denied", a.Denied, "observations", a.Observations)
	}
	for _, m := range configured {
		if !seen[m.AgentID] {
			logger.WarnContext(ctx, "configured agent received no events", "agent_id", m.AgentID, "ans_name", m.AnsName)
		}
	}
}
