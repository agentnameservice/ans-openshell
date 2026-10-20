package testfixtures

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
)

const contentTypeCOSE = "application/cose"

// FakeTLServer serves the transparency-log routes a scitt.HTTPClient reads for
// the given identities: GET /v1/agents/{agentId}/receipt,
// GET /v1/agents/{agentId}/status-token (a fresh ACTIVE token per call) and
// GET /root-keys (newline-delimited C2SP). Unknown agents receive 404. The
// SDK's HeaderSupplier and RefreshableKeyStore read only these three routes;
// /checkpoint is not served. The caller closes the server.
func FakeTLServer(tl *TL, idents ...*Identity) *httptest.Server {
	byID := make(map[string]*Identity, len(idents))
	for _, id := range idents {
		byID[id.AgentID] = id
	}
	lookup := func(w http.ResponseWriter, r *http.Request) (*Identity, bool) {
		id, ok := byID[r.PathValue("agentId")]
		if !ok {
			http.NotFound(w, r)
		}
		return id, ok
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agents/{agentId}/receipt", func(w http.ResponseWriter, r *http.Request) {
		if id, ok := lookup(w, r); ok {
			writeCOSE(w, tl.Receipt(id.AgentID, id.AnsName))
		}
	})
	mux.HandleFunc("GET /v1/agents/{agentId}/status-token", func(w http.ResponseWriter, r *http.Request) {
		if id, ok := lookup(w, r); ok {
			writeCOSE(w, tl.FreshStatusToken(id))
		}
	})
	mux.HandleFunc("GET /root-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, tl.RootKeyC2SP()+"\n")
	})
	return httptest.NewServer(mux)
}

func writeCOSE(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", contentTypeCOSE)
	_, _ = w.Write(b) //nolint:gosec // G705: b is a COSE_Sign1 artifact the fixture minted, served as application/cose
}

// StaticArtifacts mints a receipt and a fresh ACTIVE status token for id and
// returns them base64-encoded, receipt first, as they travel in the
// X-SCITT-Receipt and X-ANS-Status-Token headers. It serves tests and demos
// that pin artifacts instead of running a scitt.HeaderSupplier.
func StaticArtifacts(tl *TL, id *Identity) (string, string) {
	return base64.StdEncoding.EncodeToString(tl.Receipt(id.AgentID, id.AnsName)),
		base64.StdEncoding.EncodeToString(tl.FreshStatusToken(id))
}
