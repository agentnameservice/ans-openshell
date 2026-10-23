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
	// Activity configures the optional corrected evidence and score path.
	Activity ActivityConfig
	// Evidence receives one local ActivityEvidence JSON object per agent. It
	// is independent of score emission, including finding-only windows.
	Evidence io.Writer
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
	// Activity is populated only when corrected evidence or scores were requested.
	Activity []ActivityEvidence
	Parse    ParseStats
	// Attributed counts events that resolved to a configured agent and fell
	// inside the window, whatever their class.
	Attributed int
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
	if err := opts.Activity.Validate(); err != nil {
		return Report{}, err
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	reader := NewReader(in)
	agg := newAggregator(opts.Agents, opts.Window)
	if opts.Signals.EmitActivity || opts.Evidence != nil {
		agg.activity = newActivityAggregator(opts.Agents, opts.Window, opts.Activity)
		agg.skipLegacyStats = !opts.Signals.EmitPolicyViolationRate && !opts.Signals.EmitProtocolAdherence
	}
	err := consume(ctx, reader, agg)
	report := Report{
		Parse:       reader.Stats(),
		Attributed:  agg.attributed,
		Unmapped:    agg.unmapped,
		NoContainer: agg.noContainer,
		OutOfWindow: agg.outOfWindow,
		Window:      agg.resolveWindow(clock()),
	}
	if err != nil {
		return report, err
	}
	if agg.activity != nil {
		report.Activity = agg.activity.evidence(report.Window, reader.invalidOCSF+reader.oversizedOCSF)
		if opts.Evidence != nil {
			encoder := json.NewEncoder(opts.Evidence)
			for _, evidence := range report.Activity {
				if err := encoder.Encode(evidence); err != nil {
					return report, fmt.Errorf("hydrator: write activity evidence: %w", err)
				}
			}
		}
	}
	logger.DebugContext(ctx, "input parsed",
		"lines", report.Parse.Lines, "events", report.Parse.Events,
		"skipped", report.Parse.Skipped, "oversized", report.Parse.Oversized)
	if report.Unmapped > 0 {
		logger.WarnContext(ctx, "events without an agent mapping were skipped",
			"unmapped", report.Unmapped, "no_container", report.NoContainer)
	}
	if report.Parse.Events > 0 && report.OutOfWindow == report.Parse.Events {
		logger.WarnContext(ctx, "every event fell outside the window",
			"events", report.Parse.Events, "window_start", report.Window.Start, "window_end", report.Window.End)
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
	activity := make(map[string]ActivityEvidence, len(report.Activity))
	for _, evidence := range report.Activity {
		activity[evidence.AgentID] = evidence
	}
	observations := make([]Observation, 0, len(ids))
	report.Agents = make([]AgentSummary, 0, len(ids))
	for _, id := range ids {
		st := agg.stats[id]
		obs, err := builder.build(st)
		if err != nil {
			return nil, err
		}
		if evidence, ok := activity[id]; ok && builder.signals.EmitActivity && evidence.Score != nil {
			value := struct {
				Score       int    `json:"score"`
				Explanation string `json:"explanation"`
			}{Score: *evidence.Score, Explanation: activityExplanation(evidence)}
			row, err := builder.observation(id, builder.signals.ActivityID, value)
			if err != nil {
				return nil, err
			}
			obs = append(obs, row)
		}
		observations = append(observations, obs...)
		denied := st.denied
		if agg.skipLegacyStats {
			for _, counts := range activity[id].Measurements.groups() {
				denied += counts.Denied
			}
		}
		report.Agents = append(report.Agents, AgentSummary{
			AgentID:      id,
			AnsName:      st.mapping.AnsName,
			Events:       st.events,
			Denied:       denied,
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
