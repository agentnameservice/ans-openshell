package deploy_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHydratorActivityChart(t *testing.T) {
	t.Parallel()
	helm := deploymentTool(t, "helm")
	tests := []struct {
		name     string
		window   string
		evidence string
	}{
		{name: "no evidence output", window: "15m"},
		{name: "stdout evidence with longer window", window: "24h", evidence: "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resources := renderChart(t, helm, "https://gateway.example/.well-known/jwks.json",
				"--set", "hydrator.enabled=true",
				"--set-string", "hydrator.window="+tt.window,
				"--set-string", "hydrator.evidenceOutput="+tt.evidence,
				"--set-string", "hydrator.config.signals.policy_violation_rate=",
				"--set-string", "hydrator.config.signals.protocol_adherence=",
				"--set-string", "hydrator.config.signals.activity=openshell.behavior.activity")
			job := resources["CronJob/regression-hydrator"]
			containers := job.Spec.JobTemplate.Spec.Template.Spec.Containers
			if len(containers) != 1 {
				t.Fatalf("hydrator containers = %d, want one", len(containers))
			}
			args := containers[0].Args
			windowIndex := slices.Index(args, "--window-last")
			if windowIndex < 0 || windowIndex+1 >= len(args) || args[windowIndex+1] != tt.window {
				t.Fatalf("window argument missing from %v", args)
			}
			evidenceIndex := slices.Index(args, "--evidence-output")
			if tt.evidence == "" {
				if evidenceIndex >= 0 {
					t.Fatalf("unexpected evidence flag in %v", args)
				}
			} else if evidenceIndex < 0 || evidenceIndex+1 >= len(args) || args[evidenceIndex+1] != tt.evidence {
				t.Fatalf("evidence argument missing from %v", args)
			}
			var cfg struct {
				Signals struct {
					Activity            string `yaml:"activity"`
					PolicyViolationRate string `yaml:"policy_violation_rate"`
					ProtocolAdherence   string `yaml:"protocol_adherence"`
				} `yaml:"signals"`
			}
			if err := yaml.Unmarshal([]byte(resources["ConfigMap/regression-hydrator"].Data["config.yaml"]), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Signals.Activity != "openshell.behavior.activity" || cfg.Signals.PolicyViolationRate != "" || cfg.Signals.ProtocolAdherence != "" {
				t.Fatalf("activity migration config not preserved: %+v", cfg.Signals)
			}
		})
	}
}

func TestHydratorEvidenceFileRejected(t *testing.T) {
	t.Parallel()
	helm := deploymentTool(t, "helm")
	output, err := exec.CommandContext(t.Context(), helm, "template", "regression", "helm/ans-openshell",
		"--set-string", "gateway.jwksURL=https://gateway.example/.well-known/jwks.json",
		"--set", "hydrator.enabled=true",
		"--set-string", "hydrator.evidenceOutput=/evidence/run.jsonl").CombinedOutput()
	if err == nil {
		t.Fatal("chart rendered a file evidence path that fails on the second scheduled run")
	}
	if !strings.Contains(string(output), "hydrator.evidenceOutput must be empty") {
		t.Fatalf("unexpected render error: %s", output)
	}
}
