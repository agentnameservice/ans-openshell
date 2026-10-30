package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

func TestPreReturnService_onEvent(t *testing.T) {
	t.Parallel()
	s := NewPreReturnService(slog.New(slog.DiscardHandler))

	t.Run("preflight returns Skip when WHOLE_BODY_BYTES not permitted", func(t *testing.T) {
		t.Parallel()
		ev := &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
					},
				},
			},
		}
		var inspecting bool
		var maxPayloadBytes uint64
		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		if result == nil {
			t.Fatal("onEvent(preflight) result = nil, want Skip")
		}
		if result.GetPreflightResult().GetSkip() == nil {
			t.Fatalf("onEvent(preflight) result = %v, want Skip", result)
		}
		if inspecting {
			t.Error("inspecting = true after Skip, want false")
		}
	})

	t.Run("preflight returns Inspect when WHOLE_BODY_BYTES permitted", func(t *testing.T) {
		t.Parallel()
		ev := &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
					},
					MaxPayloadBytes: 1024,
				},
			},
		}
		var inspecting bool
		var maxPayloadBytes uint64
		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		if result == nil {
			t.Fatal("onEvent(preflight) result = nil, want Inspect")
		}
		inspect := result.GetPreflightResult().GetInspect()
		if inspect == nil {
			t.Fatalf("onEvent(preflight) result = %v, want Inspect", result)
		}
		if inspect.GetBodyMode() != middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES {
			t.Errorf("Inspect.BodyMode = %v, want WHOLE_BODY_BYTES", inspect.GetBodyMode())
		}
		if !inspecting {
			t.Error("inspecting = false after Inspect, want true")
		}
		if maxPayloadBytes != 1024 {
			t.Errorf("maxPayloadBytes = %d, want 1024", maxPayloadBytes)
		}
	})

	t.Run("body returns PassThrough with matching Sequence when not inspecting", func(t *testing.T) {
		t.Parallel()
		ev := &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_Body{
				Body: &middlewarev1.HttpResponseBodyUnit{
					Sequence: 42,
					Payload: &middlewarev1.HttpResponseBodyUnit_Data{
						Data: []byte("test"),
					},
				},
			},
		}
		var inspecting bool // false
		var maxPayloadBytes uint64
		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		if result == nil {
			t.Fatal("onEvent(body) result = nil, want PassThrough")
		}
		bodyResult := result.GetBodyResult()
		if bodyResult == nil {
			t.Fatalf("onEvent(body) result = %v, want BodyResult", result)
		}
		if bodyResult.GetSequence() != 42 {
			t.Errorf("onEvent(body) Sequence = %d, want 42", bodyResult.GetSequence())
		}
		if bodyResult.GetPassThrough() == nil {
			t.Fatalf("onEvent(body) action = %v, want PassThrough", bodyResult)
		}
	})

	t.Run("trailers returns empty TrailersResult", func(t *testing.T) {
		t.Parallel()
		ev := &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_Trailers{
				Trailers: &middlewarev1.HttpResponseTrailers{},
			},
		}
		var inspecting bool
		var maxPayloadBytes uint64
		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		if result == nil {
			t.Fatal("onEvent(trailers) result = nil, want TrailersResult")
		}
		if result.GetTrailersResult() == nil {
			t.Fatalf("onEvent(trailers) result = %v, want TrailersResult", result)
		}
	})

	t.Run("session_end returns nil", func(t *testing.T) {
		t.Parallel()
		ev := &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_SessionEnd{
				SessionEnd: &middlewarev1.MiddlewareSessionEnd{},
			},
		}
		var inspecting bool
		var maxPayloadBytes uint64
		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		if result != nil {
			t.Errorf("onEvent(session_end) result = %v, want nil (no reply)", result)
		}
	})
}

func TestNewPreReturnService(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()
		log := slog.New(slog.DiscardHandler)
		svc := NewPreReturnService(log)
		if svc == nil {
			t.Fatal("NewPreReturnService(log) = nil, want non-nil")
		}
		if svc.log != log {
			t.Error("NewPreReturnService(log) did not set log field")
		}
	})

	t.Run("with nil logger", func(t *testing.T) {
		t.Parallel()
		svc := NewPreReturnService(nil)
		if svc == nil {
			t.Fatal("NewPreReturnService(nil) = nil, want non-nil")
		}
		if svc.log == nil {
			t.Error("NewPreReturnService(nil) log field is nil, want default")
		}
	})
}

// assertCapabilityErrorTransformed checks that a capability error was transformed correctly.
func assertCapabilityErrorTransformed(t *testing.T, newBody []byte) {
	t.Helper()
	// Parse the result to check structure
	var result map[string]any
	if err := json.Unmarshal(newBody, &result); err != nil {
		t.Fatalf("json.Unmarshal(newBody) error = %v", err)
	}

	// Check middleware_hint exists
	hint, ok := result["middleware_hint"].(map[string]any)
	if !ok {
		t.Fatalf("middleware_hint not found or not an object in result: %v", result)
	}

	// Check middleware_hint.missing_capabilities
	missingCaps, ok := hint["missing_capabilities"].([]any)
	if !ok {
		t.Fatalf("middleware_hint.missing_capabilities not found or not an array: %v", hint)
	}
	if len(missingCaps) != 2 {
		t.Errorf("len(missing_capabilities) = %d, want 2", len(missingCaps))
	}
	if missingCaps[0] != "mandate" || missingCaps[1] != "dpop_proof" {
		t.Errorf("missing_capabilities = %v, want [mandate, dpop_proof]", missingCaps)
	}

	// Check middleware_hint.source
	if hint["source"] != "ans-egress" {
		t.Errorf("middleware_hint.source = %v, want ans-egress", hint["source"])
	}

	// Check original error object is preserved
	errorObj, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatalf("error object not found or not an object in result: %v", result)
	}
	if errorObj["code"].(float64) != -32000 {
		t.Errorf("error.code = %v, want -32000", errorObj["code"])
	}
	if errorObj["message"] != "MANDATE_REJECTED: missing capabilities" {
		t.Errorf("error.message = %v, want original", errorObj["message"])
	}

	// Check error.data is preserved
	errorData, ok := errorObj["data"].(map[string]any)
	if !ok {
		t.Fatalf("error.data not found or not an object: %v", errorObj)
	}
	requiredCaps, ok := errorData["required_capabilities"].([]any)
	if !ok || len(requiredCaps) != 2 {
		t.Errorf("error.data.required_capabilities = %v, want preserved array", errorData["required_capabilities"])
	}
	if errorData["authority_ans"] != "seller.ans" {
		t.Errorf("error.data.authority_ans = %v, want seller.ans", errorData["authority_ans"])
	}
}

func TestSurfaceCapabilityError(t *testing.T) {
	t.Parallel()

	t.Run("capability error with required_capabilities array", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"error": {
				"code": -32000,
				"message": "MANDATE_REJECTED: missing capabilities",
				"data": {
					"required_capabilities": ["mandate", "dpop_proof"],
					"dpop": {"method": "POST", "uri": "https://example.com"},
					"authority_ans": "seller.ans",
					"docs": "https://docs.example.com"
				}
			}
		}`)

		newBody, changed := surfaceCapabilityError(input)
		if !changed {
			t.Fatal("surfaceCapabilityError(capability error) changed = false, want true")
		}

		assertCapabilityErrorTransformed(t, newBody)
	})

	t.Run("success response unchanged", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"result": {
				"ticket": "ticket-123",
				"expires_at": "2026-10-22T00:00:00Z"
			}
		}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(success) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(success) body changed unexpectedly")
		}
	})

	t.Run("error without data unchanged", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"error": {
				"code": -32600,
				"message": "Invalid Request"
			}
		}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(error without data) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(error without data) body changed unexpectedly")
		}
	})

	t.Run("error with empty required_capabilities unchanged", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"error": {
				"code": -32000,
				"message": "Some error",
				"data": {
					"required_capabilities": []
				}
			}
		}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(empty required_capabilities) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(empty required_capabilities) body changed unexpectedly")
		}
	})

	t.Run("malformed JSON unchanged and no panic", func(t *testing.T) {
		t.Parallel()
		input := []byte(`not valid json`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(malformed) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(malformed) body changed unexpectedly")
		}
	})

	t.Run("error field not an object", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{"jsonrpc":"2.0","id":"1","error":"string-not-object"}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(error not object) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(error not object) body changed unexpectedly")
		}
	})

	t.Run("error.data not an object", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"err","data":"string-not-object"}}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(data not object) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(data not object) body changed unexpectedly")
		}
	})

	t.Run("required_capabilities not an array", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"err","data":{"required_capabilities":"not-array"}}}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(required_capabilities not array) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(required_capabilities not array) body changed unexpectedly")
		}
	})

	t.Run("error.data without required_capabilities key", func(t *testing.T) {
		t.Parallel()
		input := []byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"err","data":{"other_field":"value"}}}`)

		newBody, changed := surfaceCapabilityError(input)
		if changed {
			t.Errorf("surfaceCapabilityError(missing required_capabilities key) changed = true, want false")
		}
		if string(newBody) != string(input) {
			t.Errorf("surfaceCapabilityError(missing required_capabilities key) body changed unexpectedly")
		}
	})
}

// preReturnTestClient sets up a bufconn-based PreReturnService for testing.
type preReturnTestClient struct {
	client middlewarev1.HttpResponsePreReturnClient
	ctx    context.Context
	srv    *grpc.Server
}

func newPreReturnTestClient(t *testing.T) *preReturnTestClient {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	middlewarev1.RegisterHttpResponsePreReturnServer(srv, NewPreReturnService(slog.New(slog.DiscardHandler)))
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			panic(err)
		}
	}()
	t.Cleanup(srv.Stop)

	ctx := context.Background()
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &preReturnTestClient{
		client: middlewarev1.NewHttpResponsePreReturnClient(conn),
		ctx:    ctx,
		srv:    srv,
	}
}

// runPreReturnStream sends events and collects results until EOF.
func (c *preReturnTestClient) runPreReturnStream(t *testing.T, events []*middlewarev1.HttpResponseEvent) []*middlewarev1.HttpResponseEventResult {
	t.Helper()
	stream, err := c.client.Evaluate(c.ctx)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	var results []*middlewarev1.HttpResponseEventResult
	for _, ev := range events {
		if err := stream.Send(ev); err != nil {
			t.Fatalf("Send(%T) error = %v", ev.GetEvent(), err)
		}
		// session_end doesn't get a reply
		if ev.GetSessionEnd() != nil {
			break
		}
		result, recvErr := stream.Recv()
		if recvErr != nil {
			t.Fatalf("Recv() error = %v", recvErr)
		}
		results = append(results, result)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	if _, recvErr := stream.Recv(); !errors.Is(recvErr, io.EOF) {
		t.Errorf("Recv() after close = %v, want io.EOF", recvErr)
	}
	return results
}

func TestPreReturnService_Evaluate_errors(t *testing.T) {
	t.Parallel()

	t.Run("context cancellation", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		srv := NewPreReturnService(slog.New(slog.DiscardHandler))
		stream := &mockEvaluateStream{ctx: ctx}
		err := srv.Evaluate(stream)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Evaluate(canceled ctx) error = %v, want context.Canceled", err)
		}
	})

	t.Run("recv non-EOF error", func(t *testing.T) {
		t.Parallel()
		srv := NewPreReturnService(slog.New(slog.DiscardHandler))
		recvErr := errors.New("recv error")
		stream := &mockEvaluateStream{
			ctx:     context.Background(),
			recvErr: recvErr,
		}
		err := srv.Evaluate(stream)
		if !errors.Is(err, recvErr) {
			t.Errorf("Evaluate(recv error) error = %v, want %v", err, recvErr)
		}
	})

	t.Run("send error", func(t *testing.T) {
		t.Parallel()
		srv := NewPreReturnService(slog.New(slog.DiscardHandler))
		sendErr := errors.New("send error")
		stream := &mockEvaluateStream{
			ctx:      context.Background(),
			recvOnce: true,
			sendErr:  sendErr,
		}
		err := srv.Evaluate(stream)
		if !errors.Is(err, sendErr) {
			t.Errorf("Evaluate(send error) error = %v, want %v", err, sendErr)
		}
	})
}

// mockEvaluateStream implements HttpResponsePreReturn_EvaluateServer for error testing.
type mockEvaluateStream struct {
	middlewarev1.HttpResponsePreReturn_EvaluateServer
	ctx      context.Context
	recvOnce bool
	recvErr  error
	sendErr  error
}

func (m *mockEvaluateStream) Context() context.Context {
	return m.ctx
}

func (m *mockEvaluateStream) Recv() (*middlewarev1.HttpResponseEvent, error) {
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	if m.recvOnce {
		m.recvErr = io.EOF
		// Return a preflight event to trigger Send
		return &middlewarev1.HttpResponseEvent{
			Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{},
			},
		}, nil
	}
	return nil, io.EOF
}

func (m *mockEvaluateStream) Send(*middlewarev1.HttpResponseEventResult) error {
	return m.sendErr
}

func TestPreReturnService_Evaluate_bufconn(t *testing.T) {
	t.Parallel()
	tc := newPreReturnTestClient(t)

	t.Run("skip when WHOLE_BODY_BYTES not permitted", func(t *testing.T) {
		t.Parallel()
		events := []*middlewarev1.HttpResponseEvent{
			{Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
					},
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_SessionEnd{
				SessionEnd: &middlewarev1.MiddlewareSessionEnd{},
			}},
		}
		results := tc.runPreReturnStream(t, events)
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		if results[0].GetPreflightResult().GetSkip() == nil {
			t.Errorf("preflight result = %v, want Skip", results[0])
		}
	})

	t.Run("inspect and transform capability error", func(t *testing.T) {
		t.Parallel()
		capErrorBody := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"error": {
				"code": -32000,
				"message": "MANDATE_REJECTED: missing capabilities",
				"data": {
					"required_capabilities": ["mandate", "dpop_proof"]
				}
			}
		}`)
		events := []*middlewarev1.HttpResponseEvent{
			{Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
					},
					MaxPayloadBytes: 1024 * 1024,
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_Body{
				Body: &middlewarev1.HttpResponseBodyUnit{
					Sequence: 1,
					Payload: &middlewarev1.HttpResponseBodyUnit_Data{
						Data: capErrorBody,
					},
					EndOfStream: true,
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_Trailers{
				Trailers: &middlewarev1.HttpResponseTrailers{},
			}},
			{Event: &middlewarev1.HttpResponseEvent_SessionEnd{
				SessionEnd: &middlewarev1.MiddlewareSessionEnd{},
			}},
		}
		results := tc.runPreReturnStream(t, events)
		if len(results) != 3 {
			t.Fatalf("got %d results, want 3", len(results))
		}

		// Check Inspect result
		inspect := results[0].GetPreflightResult().GetInspect()
		if inspect == nil {
			t.Fatalf("preflight result = %v, want Inspect", results[0])
		}
		if inspect.GetBodyMode() != middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES {
			t.Errorf("Inspect.BodyMode = %v, want WHOLE_BODY_BYTES", inspect.GetBodyMode())
		}

		// Check Transform result
		br := results[1].GetBodyResult()
		if br == nil {
			t.Fatalf("body result = %v, want BodyResult", results[1])
		}
		transform := br.GetTransform()
		if transform == nil {
			t.Fatalf("BodyResult action = %v, want Transform", br)
		}
		replacement, ok := transform.GetReplacement().(*middlewarev1.HttpResponseBodyTransform_Data)
		if !ok {
			t.Fatalf("Transform.Replacement = %T, want *HttpResponseBodyTransform_Data", transform.GetReplacement())
		}

		// Verify middleware_hint
		var transformed map[string]any
		if err := json.Unmarshal(replacement.Data, &transformed); err != nil {
			t.Fatalf("json.Unmarshal(transformed) error = %v", err)
		}
		hint, ok := transformed["middleware_hint"].(map[string]any)
		if !ok {
			t.Fatalf("middleware_hint not found in transformed body: %v", transformed)
		}
		if hint["source"] != "ans-egress" {
			t.Errorf("middleware_hint.source = %v, want ans-egress", hint["source"])
		}

		// Check TrailersResult
		if results[2].GetTrailersResult() == nil {
			t.Errorf("trailers result = %v, want TrailersResult", results[2])
		}
	})

	t.Run("inspect and passthrough when transformed exceeds MaxPayloadBytes", func(t *testing.T) {
		t.Parallel()
		capErrorBody := []byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"ERR","data":{"required_capabilities":["mandate"]}}}`)
		events := []*middlewarev1.HttpResponseEvent{
			{Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
					},
					MaxPayloadBytes: 50, // Very small limit
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_Body{
				Body: &middlewarev1.HttpResponseBodyUnit{
					Sequence: 1,
					Payload: &middlewarev1.HttpResponseBodyUnit_Data{
						Data: capErrorBody,
					},
					EndOfStream: true,
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_SessionEnd{
				SessionEnd: &middlewarev1.MiddlewareSessionEnd{},
			}},
		}
		results := tc.runPreReturnStream(t, events)
		if len(results) != 2 {
			t.Fatalf("got %d results, want 2", len(results))
		}

		// Check Inspect result
		if results[0].GetPreflightResult().GetInspect() == nil {
			t.Fatalf("preflight result = %v, want Inspect", results[0])
		}

		// Check PassThrough (transformed exceeds MaxPayloadBytes)
		br := results[1].GetBodyResult()
		if br == nil {
			t.Fatalf("body result = %v, want BodyResult", results[1])
		}
		if br.GetPassThrough() == nil {
			t.Fatalf("BodyResult action = %v, want PassThrough (size limit)", br)
		}
	})

	t.Run("inspect and passthrough success response", func(t *testing.T) {
		t.Parallel()
		successBody := []byte(`{
			"jsonrpc": "2.0",
			"id": "req-1",
			"result": {
				"ticket": "ticket-123"
			}
		}`)
		events := []*middlewarev1.HttpResponseEvent{
			{Event: &middlewarev1.HttpResponseEvent_Preflight{
				Preflight: &middlewarev1.HttpResponsePreflight{
					PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
						middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
					},
					MaxPayloadBytes: 1024 * 1024,
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_Body{
				Body: &middlewarev1.HttpResponseBodyUnit{
					Sequence: 1,
					Payload: &middlewarev1.HttpResponseBodyUnit_Data{
						Data: successBody,
					},
					EndOfStream: true,
				},
			}},
			{Event: &middlewarev1.HttpResponseEvent_SessionEnd{
				SessionEnd: &middlewarev1.MiddlewareSessionEnd{},
			}},
		}
		results := tc.runPreReturnStream(t, events)
		if len(results) != 2 {
			t.Fatalf("got %d results, want 2", len(results))
		}

		// Check Inspect result
		if results[0].GetPreflightResult().GetInspect() == nil {
			t.Fatalf("preflight result = %v, want Inspect", results[0])
		}

		// Check PassThrough
		br := results[1].GetBodyResult()
		if br == nil {
			t.Fatalf("body result = %v, want BodyResult", results[1])
		}
		if br.GetPassThrough() == nil {
			t.Fatalf("BodyResult action = %v, want PassThrough", br)
		}
	})
}
