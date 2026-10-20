package interceptor

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

func startServer(t *testing.T, svc *Service) interceptorv1.GatewayInterceptorClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	interceptorv1.RegisterGatewayInterceptorServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return interceptorv1.NewGatewayInterceptorClient(conn)
}

func TestContractOverBufconn(t *testing.T) {
	t.Parallel()
	fake := &fakeVerifier{verdicts: map[string]vetting.Verdict{
		"api.example.com":  registered(),
		"evil.example.com": withStatus(vetting.StatusUnregistered),
	}}
	svc := NewService(fake, Config{Audience: testAudience, Mode: vetting.ModeRequire, ImplementationVersion: "v0.1.0-test"}, discardLogger())
	client := startServer(t, svc)
	ctx := t.Context()

	manifest, err := client.Describe(ctx, &interceptorv1.DescribeRequest{Gateway: gatewayPeer(1, 0, contractCapability)})
	if err != nil {
		t.Fatalf("Describe() error = %v", err)
	}
	checkManifest(t, manifest)

	if _, err = client.Describe(ctx, &interceptorv1.DescribeRequest{Gateway: gatewayPeer(2, 0)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Describe(major 2) error = %v, want FailedPrecondition", err)
	}

	policy := map[string]*sandboxv1.NetworkPolicyRule{"tools": rule("api.example.com", "evil.example.com")}
	res, err := client.Evaluate(ctx, validateEval(methodCreate, toStruct(t, createSandbox(policy))))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if res.GetAllowed() || res.GetStatusCode() != "PERMISSION_DENIED" || !strings.Contains(res.GetReason(), "evil.example.com ans_destination_unregistered") {
		t.Fatalf("Evaluate() = %v, want a denial naming evil.example.com", res)
	}
	if res.GetLogAnnotations()["ans.vetting.verdicts"] != "api.example.com=registered,evil.example.com=unregistered" {
		t.Fatalf("annotations = %v", res.GetLogAnnotations())
	}

	res, err = client.Evaluate(ctx, validateEval(methodCreate, toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"tools": rule("api.example.com")}))))
	if err != nil || !res.GetAllowed() {
		t.Fatalf("Evaluate(registered only) = %v, %v; want allowed", res, err)
	}

	if _, err := client.SnapshotProviderProfiles(ctx, &interceptorv1.ProviderProfileSnapshotRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("SnapshotProviderProfiles() error = %v, want Unimplemented", err)
	}
}
