package middleware

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

const bufSize = 1 << 20

// dialService serves s over an in-memory connection and returns a client.
func dialService(t *testing.T, s *Service) middlewarev1.SupervisorMiddlewareClient {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	server := grpc.NewServer()
	middlewarev1.RegisterSupervisorMiddlewareServer(server, s)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return middlewarev1.NewSupervisorMiddlewareClient(conn)
}

func TestGRPCContract(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	client := dialService(t, NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{Audience: "urn:openshell:extension:middleware:ans"}, nil))
	ctx := t.Context()

	m, err := client.Describe(ctx, &middlewarev1.MiddlewareDescribeRequest{
		Gateway: &extensionv1.PeerMetadata{ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1}}})
	if err != nil || m.GetName() != ManifestName || len(m.GetBindings()) != 2 {
		t.Fatalf("Describe() = %v, %v", m, err)
	}
	_, err = client.Describe(ctx, &middlewarev1.MiddlewareDescribeRequest{
		Gateway: &extensionv1.PeerMetadata{ProtocolVersion: &extensionv1.ProtocolVersion{Major: 2}}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Describe(v2) error = %v, want FailedPrecondition", err)
	}

	v, err := client.ValidateConfig(ctx, &middlewarev1.ValidateConfigRequest{Config: structOf(t, signPolicy())})
	if err != nil || !v.GetValid() {
		t.Fatalf("ValidateConfig() = %v, %v", v, err)
	}
	v, err = client.ValidateConfig(ctx, &middlewarev1.ValidateConfigRequest{Config: structOf(t, map[string]any{"identity": "ghost"})})
	if err != nil || v.GetValid() || v.GetReason() == "" {
		t.Fatalf("ValidateConfig(ghost) = %v, %v", v, err)
	}
	if _, nilErr := client.ValidateConfig(ctx, &middlewarev1.ValidateConfigRequest{}); status.Code(nilErr) != codes.InvalidArgument {
		t.Fatalf("ValidateConfig(nil) error = %v, want InvalidArgument", nilErr)
	}

	res, err := client.EvaluateHttpRequest(ctx, evaluation(t, signPolicy(), []byte("body")))
	if err != nil || res.GetDecision() != allow || len(res.GetHeaderMutations()) != 3 {
		t.Fatalf("EvaluateHttpRequest() = %v, %v", res, err)
	}
	res, err = client.EvaluateHttpRequest(ctx, evaluation(t, map[string]any{"identity": "ghost"}, nil))
	if err != nil || res.GetDecision() != deny || res.GetReasonCode() != ReasonIdentityUnknown {
		t.Fatalf("EvaluateHttpRequest(ghost) = %v, %v", res, err)
	}

	stream, err := client.EvaluateWebSocketSession(ctx)
	if err != nil {
		t.Fatalf("EvaluateWebSocketSession open: %v", err)
	}
	if err := stream.Send(&middlewarev1.WebSocketSessionEvent{}); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Send: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unimplemented {
		t.Fatalf("EvaluateWebSocketSession Recv error = %v, want Unimplemented", err)
	}
}
