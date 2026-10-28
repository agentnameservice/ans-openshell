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
	AgentID string
	AnsName string
	Events  int
	// Denied counts events under the legacy rule. It stays zero when only the
	// activity output is enabled; Report.Activity carries corrected counts.
	Denied       int
	Observations int
}

// Report describes one Run.
type Report struct {
	// Activity is populated only when corrected evidence or scores were requested.
	Activity []ActivityEvidence
	// UnreadableAuditRecords counts audit-shaped lines in the body of the input
	// that could not be decoded or were oversized. Like Activity, it is
	// populated only when corrected evidence or scores were requested.
	UnreadableAuditRecords int
	Parse                  ParseStats
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
	stats := newRunStats(opts)
	err := consume(ctx, reader, stats.attributor)
	report := Report{
		Parse:       reader.Stats(),
		Attributed:  stats.attributor.attributed,
		Unmapped:    stats.attributor.unmapped,
		NoContainer: stats.attributor.noContainer,
		OutOfWindow: stats.attributor.outOfWindow,
		Window:      stats.attributor.resolveWindow(clock()),
	}
	if err != nil {
		return report, err
	}
	if stats.activity != nil {
		health := reader.auditHealth()
		report.UnreadableAuditRecords = health.unreadable
		report.Activity = stats.activity.evidence(report.Window, health)
		if err := writeActivityEvidence(opts.Evidence, report.Activity); err != nil {
			return report, err
		}
		logActivityHealth(ctx, logger, health, report.Activity)
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
	observations, err := buildObservations(stats, report.Window, opts, &report)
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

// eventConsumer receives every decoded event in input order.
type eventConsumer interface {
	add(ev Event)
}

// logActivityHealth reports, once per run, audit lines the corrected path could
// not read and agents whose new score was withheld.
func logActivityHealth(ctx context.Context, logger *slog.Logger, health auditInputHealth, evidence []ActivityEvidence) {
	if health.unreadable > 0 {
		logger.WarnContext(ctx, "audit records could not be read; activity evidence omits them",
			"unreadable", health.unreadable, "truncated_final_line", health.truncatedTail)
	}
	withheld := 0
	for _, item := range evidence {
		if item.Degraded() {
			withheld++
		}
	}
	if withheld > 0 {
		logger.WarnContext(ctx, "activity scores withheld", "withheld", withheld, "agents", len(evidence))
	}
}

// runStats is the attributor and the stats consumers registered for one run.
type runStats struct {
	attributor *attributor
	// legacy is nil unless a legacy signal is emitted.
	legacy *legacyAggregator
	// activity is nil unless corrected evidence or scores are requested.
	activity *activityAggregator
}

func newRunStats(opts Options) runStats {
	var stats runStats
	var consumers []statsConsumer
	if opts.Signals.EmitPolicyViolationRate || opts.Signals.EmitProtocolAdherence {
		stats.legacy = newLegacyAggregator()
		consumers = append(consumers, stats.legacy)
	}
	if opts.Signals.EmitActivity || opts.Evidence != nil {
		stats.activity = newActivityAggregator(opts.Window, opts.Activity)
		consumers = append(consumers, stats.activity)
	}
	stats.attributor = newAttributor(opts.Agents, opts.Window, consumers...)
	return stats
}

func writeActivityEvidence(writer io.Writer, evidence []ActivityEvidence) error {
	if writer == nil {
		return nil
	}
	encoder := json.NewEncoder(writer)
	for _, item := range evidence {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("hydrator: write activity evidence: %w", err)
		}
	}
	return nil
}

func consume(ctx context.Context, reader *Reader, consumers ...eventConsumer) error {
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
		for _, consumer := range consumers {
			consumer.add(ev)
		}
	}
}

func buildObservations(stats runStats, window Window, opts Options, report *Report) ([]Observation, error) {
	builder := observationBuilder{
		signals:    opts.Signals.withDefaults(),
		provenance: newProvenance(opts.AIMID, opts.EvidenceURL),
		window:     window,
	}
	ids := slices.Sorted(maps.Keys(stats.attributor.seen))
	activity := make(map[string]ActivityEvidence, len(report.Activity))
	for _, evidence := range report.Activity {
		activity[evidence.AgentID] = evidence
	}
	observations := make([]Observation, 0, len(ids))
	report.Agents = make([]AgentSummary, 0, len(ids))
	for _, id := range ids {
		agent := stats.attributor.seen[id]
		var obs []Observation
		denied := 0
		if st := stats.legacyStats(id); st != nil {
			rows, err := builder.build(st)
			if err != nil {
				return nil, err
			}
			obs, denied = rows, st.denied
		}
		if evidence, ok := activity[id]; ok && builder.signals.EmitActivity && evidence.Score != nil {
			row, err := builder.activity(id, evidence)
			if err != nil {
				return nil, err
			}
			obs = append(obs, row)
		}
		observations = append(observations, obs...)
		report.Agents = append(report.Agents, AgentSummary{
			AgentID:      id,
			AnsName:      agent.mapping.AnsName,
			Events:       agent.events,
			Denied:       denied,
			Observations: len(obs),
		})
	}
	report.Observations = len(observations)
	return observations, nil
}

// legacyStats returns the agent's legacy payload, or nil when no legacy
// signal is emitted.
func (s runStats) legacyStats(agentID string) *agentStats {
	if s.legacy == nil {
		return nil
	}
	return s.legacy.stats[agentID]
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
