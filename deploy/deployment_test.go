package deploy_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/internal/interceptor"
)

type gatewayRegistration struct {
	Name          string            `json:"name"`
	BindingPolicy string            `json:"binding_policy"`
	Bindings      []operatorBinding `json:"bindings"`
}

type operatorBinding struct {
	RPC    string   `json:"rpc"`
	Phases []string `json:"phases"`
}

func TestGatewayRegistrationCoversInterceptorManifest(t *testing.T) {
	t.Parallel()
	python := deploymentTool(t, "python3")
	const parse = `import json, sys, tomllib
with open(sys.argv[1], "rb") as source:
    json.dump(tomllib.load(source)["openshell"]["gateway"]["interceptors"], sys.stdout)
`
	data, err := exec.CommandContext(t.Context(), python, "-c", parse, "examples/gateway.toml").CombinedOutput()
	if err != nil {
		t.Fatalf("parse gateway TOML with Python 3.11+: %v\n%s", err, data)
	}
	var registrations []gatewayRegistration
	if err := json.Unmarshal(data, &registrations); err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(registrations, func(r gatewayRegistration) bool { return r.Name == "ans-destinations" })
	if index < 0 {
		t.Fatal("ANS destination interceptor registration is missing")
	}
	registration := registrations[index]
	if registration.BindingPolicy != "allowlist" && registration.BindingPolicy != "exact" {
		t.Fatalf("binding policy = %q; want explicit operator authority", registration.BindingPolicy)
	}
	service := interceptor.NewService(nil, interceptor.Config{}, nil)
	manifest, err := service.Describe(t.Context(), &interceptorv1.DescribeRequest{
		Gateway: &extensionv1.PeerMetadata{ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(registration.Bindings) != len(manifest.GetBindings()) {
		t.Fatalf("registration has %d bindings, manifest has %d", len(registration.Bindings), len(manifest.GetBindings()))
	}
	for _, binding := range manifest.GetBindings() {
		rpc := binding.GetSelector().GetRpc()
		var matches []operatorBinding
		for _, configured := range registration.Bindings {
			if configured.RPC == rpc {
				matches = append(matches, configured)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("manifest RPC %s has %d configured bindings; want one", rpc, len(matches))
		}
		if !slices.Equal(binding.GetPhases(), []interceptorv1.GatewayInterceptorPhase{
			interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE,
		}) || !slices.Equal(matches[0].Phases, []string{"validate"}) {
			t.Fatalf("RPC %s must enable the manifest's validate phase", rpc)
		}
	}
}

type renderedResource struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func TestJWKSURLChangesRollBothServices(t *testing.T) {
	t.Parallel()
	helm := deploymentTool(t, "helm")
	previous := make(map[string]string)
	for _, jwksURL := range []string{
		"https://gateway-a.example/.well-known/jwks.json",
		"https://gateway-b.example/.well-known/jwks.json",
		"",
	} {
		resources := renderChart(t, helm, jwksURL)
		for _, service := range []string{"middleware", "interceptor"} {
			name := "regression-" + service
			configMap, exists := resources["ConfigMap/"+name]
			if !exists {
				t.Fatalf("missing ConfigMap %s", name)
			}
			configText := configMap.Data["config.yaml"]
			var config struct {
				Auth struct {
					JWKSURL string `yaml:"jwks_url"`
				} `yaml:"auth"`
			}
			if err := yaml.Unmarshal([]byte(configText), &config); err != nil {
				t.Fatalf("%s config: %v", name, err)
			}
			if config.Auth.JWKSURL != jwksURL {
				t.Fatalf("%s JWKS URL = %q, want %q", name, config.Auth.JWKSURL, jwksURL)
			}
			deployment, exists := resources["Deployment/"+name]
			if !exists {
				t.Fatalf("missing Deployment %s", name)
			}
			checksum := deployment.Spec.Template.Metadata.Annotations["checksum/config"]
			want := fmt.Sprintf("%x", sha256.Sum256([]byte(configText)))
			if checksum != want {
				t.Fatalf("%s checksum = %q, want complete mounted config hash %q", name, checksum, want)
			}
			if previous[name] == checksum {
				t.Fatalf("%s pod template did not change after JWKS URL changed", name)
			}
			previous[name] = checksum
		}
	}
}

func renderChart(t *testing.T, helm, jwksURL string) map[string]renderedResource {
	t.Helper()
	data, err := exec.CommandContext(t.Context(), helm, "template", "regression", "helm/ans-openshell",
		"--set-string", "gateway.jwksURL="+jwksURL).CombinedOutput()
	if err != nil {
		t.Fatalf("render Helm chart: %v\n%s", err, data)
	}
	resources := make(map[string]renderedResource)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var resource renderedResource
		if err := decoder.Decode(&resource); errors.Is(err, io.EOF) {
			return resources
		} else if err != nil {
			t.Fatalf("decode Helm output: %v", err)
		}
		key := resource.Kind + "/" + resource.Metadata.Name
		if _, exists := resources[key]; exists {
			t.Fatalf("duplicate rendered resource %s", key)
		}
		resources[key] = resource
	}
}

func deploymentTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("deployment regression tests require %s in CI: %v", name, err)
	}
	t.Skipf("deployment regression tests require %s: %v", name, err)
	return ""
}
