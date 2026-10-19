package interceptor

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
)

func TestNormalizeHosts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: []string{}},
		{name: "lowercase trim trailing dot", in: []string{" API.Example.COM. "}, want: []string{"api.example.com"}},
		{name: "dedupe after normalization", in: []string{"a.example.com", "A.EXAMPLE.COM.", "a.example.com"}, want: []string{"a.example.com"}},
		{name: "drop empty", in: []string{"", "  ", ".", "b.example.com"}, want: []string{"b.example.com"}},
		{name: "sorted", in: []string{"z.example.com", "a.example.com", "m.example.com"}, want: []string{"a.example.com", "m.example.com", "z.example.com"}},
		{name: "keeps globs and ip literals", in: []string{"*.example.com", "192.0.2.1", "[::1]"}, want: []string{"*.example.com", "192.0.2.1", "[::1]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeHosts(tt.in); !slices.Equal(got, tt.want) {
				t.Fatalf("normalizeHosts(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewBindings(t *testing.T) {
	t.Parallel()
	got := newBindings()
	want := []struct{ id, rpc string }{
		{"create-sandbox", "openshell.v1.OpenShell/CreateSandbox"},
		{"update-config", "openshell.v1.OpenShell/UpdateConfig"},
		{"submit-policy-analysis", "openshell.v1.OpenShell/SubmitPolicyAnalysis"},
		{"edit-draft-chunk", "openshell.v1.OpenShell/EditDraftChunk"},
		{"import-provider-profiles", "openshell.v1.OpenShell/ImportProviderProfiles"},
		{"update-provider-profiles", "openshell.v1.OpenShell/UpdateProviderProfiles"},
	}
	if len(got) != len(want) {
		t.Fatalf("newBindings() returned %d bindings, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].id != w.id || got[i].rpc != w.rpc || got[i].extract == nil {
			t.Errorf("binding %d = %+v, want %+v with an extractor", i, got[i], w)
		}
	}
}

func TestExtractors(t *testing.T) {
	t.Parallel()
	bindings := newBindings()
	extractor := func(method string) hostExtractor {
		for _, b := range bindings {
			if b.rpc == openShellService+"/"+method {
				return b.extract
			}
		}
		t.Fatalf("no binding for %q", method)
		return nil
	}
	tests := []struct {
		name    string
		method  string
		op      *structpb.Struct
		want    []string
		wantErr bool
	}{
		{
			name: "create sandbox collects every rule", method: methodCreate,
			op: toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{
				"tools": rule("api.example.com", "api.example.com"), "git": rule("github.example.com"), "empty": rule(),
			})),
			want: []string{"api.example.com", "api.example.com", "github.example.com"},
		},
		{name: "create sandbox without policy", method: methodCreate, op: toStruct(t, createSandbox(nil)), want: nil},
		{
			name: "submit policy analysis collects every chunk", method: methodSubmit,
			op:   toStruct(t, submitPolicyAnalysis(rule("a.example.com"), rule("b.example.com", "c.example.com"))),
			want: []string{"a.example.com", "b.example.com", "c.example.com"},
		},
		{name: "edit draft chunk", method: methodEdit, op: toStruct(t, editDraftChunk(rule("new.example.com"))), want: []string{"new.example.com"}},
		{name: "edit draft chunk without rule", method: methodEdit, op: toStruct(t, editDraftChunk(nil)), want: []string{}},
		{
			name: "import provider profiles collects every profile endpoint", method: methodImport,
			op: toStruct(t, importProviderProfiles(
				providerProfile("crm", endpoint("crm.example.com"), endpoint("api.example.com")),
				providerProfile("metrics", &sandboxv1.NetworkEndpoint{AllowedIps: []string{"198.51.100.0/24"}, Port: 443}),
			)),
			want: []string{"198.51.100.0/24", "api.example.com", "crm.example.com"},
		},
		{name: "import provider profiles without profiles", method: methodImport, op: toStruct(t, importProviderProfiles()), want: nil},
		{name: "update provider profile", method: methodUpdate, op: toStruct(t, updateProviderProfiles(providerProfile("crm", endpoint("new.example.com")))), want: []string{"new.example.com"}},
		{name: "update provider profile without payload", method: methodUpdate, op: toStruct(t, updateProviderProfiles(nil)), want: []string{}},
		{name: "import provider profiles nil operation", method: methodImport, op: nil, wantErr: true},
		{name: "update provider profile wrong field type", method: methodUpdate, op: mustStruct(t, map[string]any{"profile": "nope"}), wantErr: true},
		{name: "nil operation", method: methodCreate, op: nil, wantErr: true},
		{name: "wrong field type", method: methodCreate, op: mustStruct(t, map[string]any{"spec": "nope"}), wantErr: true},
		{name: "wrong nested type", method: methodSubmit, op: mustStruct(t, map[string]any{"proposedChunks": map[string]any{"a": 1}}), wantErr: true},
		{name: "unknown fields discarded", method: methodEdit, op: mustStruct(t, map[string]any{
			"future": true, "proposedRule": map[string]any{"endpoints": []any{map[string]any{"host": "x.example.com", "futureFlag": 1}}},
		}), want: []string{"x.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractor(tt.method)(tt.op)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extract() error = %v, wantErr %v", err, tt.wantErr)
			}
			slices.Sort(got)
			if !tt.wantErr && !slices.Equal(got, tt.want) {
				t.Fatalf("extract() = %q, want %q", got, tt.want)
			}
		})
	}
}
