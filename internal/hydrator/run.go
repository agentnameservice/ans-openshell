package hydrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/agentnameservice/ans-openshell/pkg/provenance"
)

// Options configures Run.
type Options struct {
	// Agents attributes sandboxes to agents.
	Agents AgentMap
	// Signals selects the signals to emit and names them.
	Signals SignalConfig
	// AIMID identifies the operator in provenance.aimId and in the batch
	// signature, for example an ans:// name or a did:web.
	AIMID string
	// EvidenceURL is recorded in provenance.evidenceUrl when set.
	EvidenceURL string
	// Window overrides the observation period. When set, events outside it
	// and events without a timestamp are excluded; when nil the window is the
	// span of event times in the input.
	Window *Window
	// Signer signs the batch; nil posts it unsigned.
	Signer provenance.BatchSigner
	// Clock supplies the signing time, and the window when no event carries a
	// timestamp; nil uses time.Now.
	Clock func() time.Time
}

// AgentSummary reports one agent's share of the input.
type AgentSummary struct {
	AgentID      string
	AnsName      string
	Events       int
	Denied       int
	Observations int
}

// Report describes one Run.
type Report struct {
	Parse ParseStats
	// Unmapped counts events that resolved to no agent; NoContainer is the
	// subset that carried no container at all, as downgraded records do.
	Unmapped    int
	NoContainer int
	// OutOfWindow counts events excluded by an explicit Options.Window.
	OutOfWindow  int
	Window       Window
	Agents       []AgentSummary
	Observations int
	Posted       bool
	Signed       bool
}

// Run reads every event from in, aggregates them per agent and posts one
// batch to sink. Without observations nothing is posted. The Report is
// populated as far as the run got, also when the error is non-nil.
func Run(ctx context.Context, in io.Reader, sink Sink, opts Options, logger *slog.Logger) (Report, error) {
	if in == nil || sink == nil {
		return Report{}, errors.New("hydrator: input and sink are required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	reader := NewReader(in)
	agg := newAggregator(opts.Agents, opts.Window)
	err := consume(ctx, reader, agg)
	report := Report{
		Parse:       reader.Stats(),
		Unmapped:    agg.unmapped,
		NoContainer: agg.noContainer,
		OutOfWindow: agg.outOfWindow,
		Window:      agg.resolveWindow(clock()),
	}
	if err != nil {
		return report, err
	}
	logger.DebugContext(ctx, "input parsed",
		"lines", report.Parse.Lines, "events", report.Parse.Events,
		"skipped", report.Parse.Skipped, "oversized", report.Parse.Oversized)
	if report.Unmapped > 0 {
		logger.WarnContext(ctx, "events without an agent mapping were skipped",
			"unmapped", report.Unmapped, "no_container", report.NoContainer)
	}
	observations, err := buildObservations(agg, report.Window, opts, &report)
	if err != nil {
		return report, err
	}
	if len(observations) == 0 {
		logger.InfoContext(ctx, "no observations to post", "events", report.Parse.Events)
		return report, nil
	}
	batch, err := newBatch(observations, opts, clock())
	if err != nil {
		return report, err
	}
	if err := sink.Post(ctx, batch); err != nil {
		return report, err
	}
	report.Posted = true
	report.Signed = batch.Signature != ""
	logger.InfoContext(ctx, "observations posted",
		"observations", len(observations), "agents", len(report.Agents), "signed", report.Signed)
	return report, nil
}

func consume(ctx context.Context, reader *Reader, agg *aggregator) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hydrator: %w", err)
		}
		ev, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		agg.add(ev)
	}
}

func buildObservations(agg *aggregator, window Window, opts Options, report *Report) ([]Observation, error) {
	builder := observationBuilder{
		signals:    opts.Signals.withDefaults(),
		provenance: newProvenance(opts.AIMID, opts.EvidenceURL),
		window:     window,
	}
	ids := slices.Sorted(maps.Keys(agg.stats))
	observations := make([]Observation, 0, len(ids))
	report.Agents = make([]AgentSummary, 0, len(ids))
	for _, id := range ids {
		st := agg.stats[id]
		obs, err := builder.build(st)
		if err != nil {
			return nil, err
		}
		observations = append(observations, obs...)
		report.Agents = append(report.Agents, AgentSummary{
			AgentID:      id,
			AnsName:      st.mapping.AnsName,
			Events:       st.events,
			Denied:       st.denied,
			Observations: len(obs),
		})
	}
	report.Observations = len(observations)
	return observations, nil
}

func newBatch(observations []Observation, opts Options, now time.Time) (Batch, error) {
	body, err := json.Marshal(importRequest{Observations: observations})
	if err != nil {
		return Batch{}, fmt.Errorf("hydrator: encode batch: %w", err)
	}
	batch := Batch{Observations: observations, Body: body}
	if opts.Signer != nil {
		signature, err := opts.Signer.Sign(body, now, len(observations), opts.AIMID)
		if err != nil {
			return Batch{}, err
		}
		batch.Signature = signature
	}
	return batch, nil
}
