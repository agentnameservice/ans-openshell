package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/hydrator"
)

func TestActivitySignalConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		yaml        string
		evidence    string
		wantID      string
		wantEnabled bool
		wantLegacy  bool
		wantErr     string
	}{
		{name: "legacy defaults remain", wantLegacy: true},
		{name: "activity explicitly disabled", yaml: "signals:\n  activity: \"\"\n", wantLegacy: true},
		{name: "activity only", yaml: "signals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n  activity: openshell.behavior.activity\n", wantID: "openshell.behavior.activity", wantEnabled: true},
		{name: "custom activity ID", yaml: "signals:\n  activity: acme.behavior.activity\n", wantID: "acme.behavior.activity", wantEnabled: true, wantLegacy: true},
		{name: "all outputs disabled", yaml: "signals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n", wantErr: "every signal is disabled"},
		{name: "evidence only", yaml: "signals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n", evidence: "evidence.jsonl"},
		{name: "negative sample minimum", yaml: "activity:\n  min_decisions: -1\n", wantErr: "must be positive"},
		{name: "negative agent UID budget", yaml: "activity:\n  max_uids_per_agent: -1\n", wantErr: "must be positive"},
		{name: "negative total UID budget", yaml: "activity:\n  max_uids: -1\n", wantErr: "must be positive"},
		{name: "unknown activity setting", yaml: "activity:\n  typo: 10\n", wantErr: "field typo not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cfg fileConfig
			var opts hydrator.Options
			data := "provenance:\n  aim_id: ans://v1.0.0.collector.example.com\nagents:\n  - agent_id: probe\n    sandbox_names: [probe]\n" + tt.yaml
			err := config.Parse([]byte(data), &cfg)
			if err == nil {
				opts, err = buildOptions(cfg, flags{evidenceOutput: tt.evidence})
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("configuration failed: %v", err)
			}
			if opts.Signals.EmitActivity != tt.wantEnabled {
				t.Errorf("EmitActivity = %v, want %v", opts.Signals.EmitActivity, tt.wantEnabled)
			}
			if tt.wantID != "" && opts.Signals.ActivityID != tt.wantID {
				t.Errorf("ActivityID = %q, want %q", opts.Signals.ActivityID, tt.wantID)
			}
			if opts.Signals.EmitPolicyViolationRate != tt.wantLegacy || opts.Signals.EmitProtocolAdherence != tt.wantLegacy {
				t.Errorf("legacy signals = %+v, want enabled=%v", opts.Signals, tt.wantLegacy)
			}
		})
	}
}

func TestActivityExampleConfiguration(t *testing.T) {
	t.Parallel()
	for _, filename := range []string{"../../deploy/examples/hydrator-activity.yaml"} {
		t.Run(filepath.Base(filename), func(t *testing.T) {
			t.Parallel()
			var cfg fileConfig
			if err := config.Load(filename, &cfg); err != nil {
				t.Fatal(err)
			}
			encoded, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var decoded fileConfig
			if err := config.Parse(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			opts, err := buildOptions(decoded, flags{dryRun: true})
			if err != nil {
				t.Fatal(err)
			}
			if !opts.Signals.EmitActivity || opts.Signals.ActivityID != "openshell.behavior.activity" || opts.Signals.EmitPolicyViolationRate || opts.Signals.EmitProtocolAdherence {
				t.Fatalf("example must select only activity: %+v", opts.Signals)
			}
		})
	}
}

func TestActivityOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                   string
		minimum, perAgent, max int
	}{
		{name: "zero selects defaults"},
		{name: "explicit bounds", minimum: 10, perAgent: 200, max: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cfg fileConfig
			data := []byte("provenance:\n  aim_id: ans://v1.0.0.collector.example.com\nagents:\n  - agent_id: probe\n    sandbox_names: [probe]\n")
			if err := config.Parse(data, &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.Activity.MinDecisions, cfg.Activity.MaxUIDsPerAgent, cfg.Activity.MaxUIDs = tt.minimum, tt.perAgent, tt.max
			opts, err := buildOptions(cfg, flags{})
			if err != nil {
				t.Fatal(err)
			}
			if opts.Activity.MinDecisions != tt.minimum || opts.Activity.MaxUIDsPerAgent != tt.perAgent || opts.Activity.MaxUIDs != tt.max {
				t.Fatalf("activity options not preserved: %+v", opts.Activity)
			}
		})
	}
}

func TestHydrateEvidenceOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		dryRun     bool
		conflict   bool
		missing    bool
		legacy     bool
		canceled   bool
		noAgents   bool
		wantErr    string
		wantOutput bool
	}{
		{name: "finding only without a Trust Index", input: `{"class_uid":2004,"container":{"name":"probe"},"severity_id":3,"finding_info":{"uid":"review.finding"}}`, wantOutput: true},
		{name: "dry run with private evidence file", input: `{"class_uid":4001,"activity_id":1,"container":{"name":"probe"},"status_id":1,"message":"Supervisor session established"}`, dryRun: true, wantOutput: true},
		{name: "empty input", input: ""},
		{name: "missing input", missing: true, wantErr: "--input"},
		{name: "existing evidence file", input: `{"class_uid":2004,"container":{"name":"probe"}}`, conflict: true, wantErr: "--evidence-output"},
		{name: "unknown lines remain an input error", input: "not an OCSF record", wantErr: "input had lines"},
		{name: "legacy posting still requires a server", legacy: true, wantErr: "trust_index.base_url"},
		{name: "invalid options", noAgents: true, wantErr: "agent mapping"},
		{name: "canceled run closes evidence", canceled: true, wantErr: "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			input := filepath.Join(dir, "input.jsonl")
			output := filepath.Join(dir, "evidence.jsonl")
			if !tt.missing {
				if err := os.WriteFile(input, []byte(tt.input), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.conflict {
				if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			data := "provenance:\n  aim_id: ans://v1.0.0.collector.example.com\nagents:\n  - agent_id: probe\n    sandbox_names: [probe]\n"
			if !tt.legacy {
				data += "signals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n"
			}
			var cfg fileConfig
			if err := config.Parse([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if tt.noAgents {
				cfg.Agents = nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			err := hydrate(ctx, cfg, flags{input: input, evidenceOutput: output, dryRun: tt.dryRun}, slog.New(slog.DiscardHandler))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("hydrate() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != tt.wantOutput {
				t.Fatalf("evidence = %q, want output=%v", got, tt.wantOutput)
			}
		})
	}
}

func TestHydrateActivityPosting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "generic observation posted directly", status: http.StatusOK},
		{name: "import failure propagated", status: http.StatusServiceUnavailable, wantErr: "HTTP 503"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var posted atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posted.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != hydrator.ImportPath {
					t.Errorf("import request = %s %s", r.Method, r.URL.Path)
				}
				var batch struct {
					Observations []struct {
						SignalID string          `json:"signalId"`
						Value    json.RawMessage `json:"value"`
					} `json:"observations"`
				}
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Errorf("decode import: %v", err)
				}
				if len(batch.Observations) != 1 || batch.Observations[0].SignalID != "openshell.behavior.activity" {
					t.Errorf("unexpected observations: %+v", batch.Observations)
				} else {
					var value struct {
						Score       *int     `json:"score"`
						Explanation string   `json:"explanation"`
						RiskCodes   []string `json:"riskCodes"`
					}
					decoder := json.NewDecoder(bytes.NewReader(batch.Observations[0].Value))
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&value); err != nil || value.Score == nil || *value.Score != 50 || value.Explanation == "" || len(value.RiskCodes) != 0 {
						t.Errorf("unsupported generic score value: %s (error %v)", batch.Observations[0].Value, err)
					}
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			var cfg fileConfig
			data := "provenance:\n  aim_id: ans://v1.0.0.collector.example.com\nagents:\n  - agent_id: probe\n    sandbox_names: [probe]\nsignals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n  activity: openshell.behavior.activity\n"
			if err := config.Parse([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.TrustIndex.BaseURL = server.URL
			input := filepath.Join(t.TempDir(), "input.jsonl")
			payload := `{"class_uid":4002,"activity_id":99,"action_id":1,"disposition_id":1,"time":1791996120000,"container":{"name":"probe"},"message":"L7_REQUEST allow GET example.com:443/test reason=rule"}
{"class_uid":4002,"activity_id":99,"action_id":1,"disposition_id":1,"time":1791996121000,"container":{"name":"probe"},"message":"L7_REQUEST audit POST example.com:443/test reason=rule"}`
			if err := os.WriteFile(input, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			err := hydrate(context.Background(), cfg, flags{input: input}, slog.New(slog.DiscardHandler))
			if got := posted.Load(); got != 1 {
				t.Fatalf("posted %d requests, want 1", got)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("hydrate() error = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHydrateDegradedRun(t *testing.T) {
	t.Parallel()
	const (
		allowed = `{"class_uid":4002,"activity_id":99,"action_id":1,"disposition_id":1,"time":1791996120000,"container":{"name":"probe"},"message":"L7_REQUEST allow GET example.com:443/test reason=rule"}`
		unknown = `{"class_uid":4002,"activity_id":99,"action_id":1,"disposition_id":1,"time":1791996120000,"container":{"name":"probe"},"message":"FUTURE_L7_FORMAT permitted=true"}`
		broken  = "OCSF-JSON {broken"
	)
	tests := []struct {
		name       string
		payload    string
		allow      bool
		wantPosted int32
		wantErr    error
	}{
		{name: "unreadable line still posts the score", payload: allowed + "\n" + broken + "\n", wantPosted: 1, wantErr: errUnreadableAudit},
		{name: "unreadable line accepted", payload: allowed + "\n" + broken + "\n", allow: true, wantPosted: 1},
		{name: "every score withheld", payload: unknown + "\n", wantErr: errActivityWithheld},
		{name: "every score withheld accepted", payload: unknown + "\n", allow: true},
		{name: "clean run", payload: allowed + "\n", wantPosted: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var posted atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				posted.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			var cfg fileConfig
			data := "provenance:\n  aim_id: ans://v1.0.0.collector.example.com\nagents:\n  - agent_id: probe\n    sandbox_names: [probe]\nsignals:\n  policy_violation_rate: \"\"\n  protocol_adherence: \"\"\n  activity: openshell.behavior.activity\n"
			if err := config.Parse([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.TrustIndex.BaseURL = server.URL
			input := filepath.Join(t.TempDir(), "input.jsonl")
			if err := os.WriteFile(input, []byte(tt.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			err := hydrate(context.Background(), cfg, flags{input: input, allowUnmapped: tt.allow}, slog.New(slog.DiscardHandler))
			if got := posted.Load(); got != tt.wantPosted {
				t.Fatalf("posted %d requests, want %d", got, tt.wantPosted)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("hydrate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogReportLegacyDenied(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		report := hydrator.Report{Agents: []hydrator.AgentSummary{{AgentID: "probe", Events: 3, Denied: 1, Observations: 1}}}
		logReport(context.Background(), logger, nil, report, legacy, nil)
		var agentLine map[string]json.RawMessage
		for line := range strings.SplitSeq(strings.TrimSpace(output.String()), "\n") {
			var record map[string]json.RawMessage
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal(err)
			}
			if string(record["msg"]) == `"agent summary"` {
				agentLine = record
			}
		}
		if agentLine == nil {
			t.Fatalf("legacy=%v: agent summary missing: %s", legacy, output.Bytes())
		}
		if _, logged := agentLine["denied"]; logged != legacy {
			t.Fatalf("legacy=%v: denied logged=%v: %s", legacy, logged, output.Bytes())
		}
	}
}

func TestOpenEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		dryRun  bool
		exists  bool
		wantNil bool
		wantErr string
	}{
		{name: "disabled", wantNil: true},
		{name: "stdout", path: "-"},
		{name: "stdout conflicts with import JSON", path: "-", dryRun: true, wantErr: "--dry-run"},
		{name: "private new file", path: "evidence.jsonl"},
		{name: "file with dry run", path: "evidence.jsonl", dryRun: true},
		{name: "existing input or config cannot be truncated", path: "existing.jsonl", exists: true, wantErr: "--evidence-output"},
		{name: "missing parent", path: "missing/evidence.jsonl", wantErr: "--evidence-output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path
			if path != "" && path != "-" {
				path = filepath.Join(t.TempDir(), path)
			}
			original := []byte("keep this input/config intact\n")
			if tt.exists {
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writer, closeOutput, err := openEvidence(path, tt.dryRun)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("openEvidence() error = %v, want %q", err, tt.wantErr)
				}
				if tt.exists {
					got, readErr := os.ReadFile(path)
					if readErr != nil || !bytes.Equal(got, original) {
						t.Fatalf("existing file changed: %q, %v", got, readErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (writer == nil) != tt.wantNil {
				t.Fatalf("writer = %v, want nil=%v", writer, tt.wantNil)
			}
			if path != "" && path != "-" {
				if _, err := io.WriteString(writer, "{\"test\":true}\n"); err != nil {
					t.Fatal(err)
				}
			}
			if err := closeOutput(); err != nil {
				t.Fatal(err)
			}
			if path == "-" && writer != os.Stdout {
				t.Fatalf("stdout writer = %v", writer)
			}
			if path != "" && path != "-" {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm()&0o077 != 0 {
					t.Fatalf("evidence file permissions: %v, %v", info, err)
				}
			}
		})
	}
}

func TestLogActivity(t *testing.T) {
	t.Parallel()
	score := 67
	tests := []struct {
		name        string
		score       *int
		unavailable string
		level       string
	}{
		{name: "numeric score", score: &score, level: "INFO"},
		{name: "no eligible decisions", unavailable: "no_eligible_decisions", level: "INFO"},
		{name: "sample minimum", unavailable: "insufficient_sample", level: "INFO"},
		{name: "deduplication saturated", unavailable: "dedup_saturated", level: "WARN"},
		{name: "unknown policy format", unavailable: "interpretation_incomplete", level: "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			measurements := hydrator.ActivityMeasurements{HTTPInitial: hydrator.DecisionCounts{Allowed: 4, Denied: 1, Audited: 3}, Connections: hydrator.DecisionCounts{Denied: 1}}
			logActivity(context.Background(), logger, []hydrator.ActivityEvidence{{AgentID: "probe", Score: tt.score, SampleSize: 6, Measurements: measurements, Unavailable: tt.unavailable}})
			var record map[string]json.RawMessage
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			wantScore := "null"
			if tt.score != nil {
				wantScore = "67"
			}
			if string(record["score"]) != wantScore || string(record["sample_size"]) != "6" || string(record["denied"]) != "2" || string(record["audited"]) != "3" {
				t.Fatalf("score/sample/denied/audited not logged: %s", output.Bytes())
			}
			var reason string
			if err := json.Unmarshal(record["unavailable_reason"], &reason); err != nil || reason != tt.unavailable {
				t.Fatalf("unavailable reason missing: %s", output.Bytes())
			}
			var level string
			if err := json.Unmarshal(record["level"], &level); err != nil || level != tt.level {
				t.Fatalf("activity log level=%s, want %s", record["level"], tt.level)
			}
		})
	}
}
