package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

// supervisorToken mints the extension JWT a sandbox supervisor presents:
// EdDSA, typ openshell-ext+jwt, caller_kind supervisor, bound to one sandbox.
func (d *demo) supervisorToken(sandbox string) string {
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": gatewayKid, "typ": "openshell-ext+jwt"})
	claims, _ := json.Marshal(map[string]any{
		"iss": gatewayIssuer, "aud": audience, "sub": "spiffe://openshell/sandbox/" + sandbox,
		"iat": now.Unix(), "exp": now.Add(tokenTTL).Unix(), "jti": strconv.FormatInt(now.UnixNano(), 10),
		"caller_kind": "supervisor", "sandbox_id": sandbox,
	})
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sig := ed25519.Sign(d.gwKey, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// outbound is one request the sandboxed agent is making.
type outbound struct {
	method string
	path   string
	body   string
}

// evaluate plays the supervisor's call into the middleware for one request.
func (d *demo) evaluate(ctx context.Context, token string, policy map[string]string, req outbound) (*middlewarev1.HttpRequestResult, error) {
	cfg, err := structpb.NewStruct(stringMap(policy))
	if err != nil {
		return nil, err
	}
	host, port := splitAuthority(d.callee.authority)
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}
	return d.client.EvaluateHttpRequest(ctx, &middlewarev1.HttpRequestEvaluation{
		Phase: middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context: &middlewarev1.RequestContext{
			RequestId: fmt.Sprintf("req-%d", time.Now().UnixNano()), SandboxId: sandboxID,
			Sandbox: "payments", Workspace: "default",
		},
		Config:         cfg,
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "http", Host: host, Port: port, Method: req.method, Path: req.path},
		Headers:        []*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}},
		Body:           []byte(req.body),
		MiddlewareName: "ans",
	})
}

// forward applies the middleware's header mutations the way the supervisor
// would and sends the request to the callee.
func (d *demo) forward(ctx context.Context, req outbound, mutations []*middlewarev1.HeaderMutation, body string) (int, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.method, "http://"+d.callee.authority+req.path, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyMutations(httpReq.Header, mutations)
	resp, err := http.DefaultClient.Do(httpReq) //nolint:gosec // G704: the authority is the demo's own loopback callee
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), err
}

func applyMutations(h http.Header, mutations []*middlewarev1.HeaderMutation) {
	for _, m := range mutations {
		switch op := m.GetOperation().(type) {
		case *middlewarev1.HeaderMutation_Write:
			w := op.Write
			switch w.GetOnExisting() {
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_APPEND:
				h.Add(w.GetName(), w.GetValue())
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_SKIP:
				if h.Get(w.GetName()) == "" {
					h.Set(w.GetName(), w.GetValue())
				}
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE,
				middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_UNSPECIFIED:
				h.Set(w.GetName(), w.GetValue())
			}
		case *middlewarev1.HeaderMutation_Remove:
			h.Del(op.Remove.GetName())
		}
	}
}

func stringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func splitAuthority(authority string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return authority, 0
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return host, 0
	}
	return host, uint32(port)
}
