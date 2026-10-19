package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// identityHeaderCount is DPoP, X-SCITT-Receipt and X-ANS-Status-Token.
const identityHeaderCount = 3

func (d *demo) run(ctx context.Context) error {
	token := d.supervisorToken(sandboxID)
	signPolicy := map[string]string{"mode": "sign", "identity": identityKey}
	call := outbound{method: http.MethodPost, path: "/v1/tasks", body: `{"task":"settle invoice 42"}`}

	d.section("1. Signed request")
	res, err := d.evaluate(ctx, token, signPolicy, call)
	if err != nil {
		return err
	}
	allow := res.GetDecision() == middlewarev1.Decision_DECISION_ALLOW
	d.check("middleware allows and returns header mutations", allow && len(res.GetHeaderMutations()) == identityHeaderCount,
		fmt.Sprintf("decision=%s mutations=%d findings=%s", res.GetDecision(), len(res.GetHeaderMutations()), findings(res)))
	for _, m := range res.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil {
			d.sayf("%-19s %s (%d bytes)", w.GetName(), w.GetOnExisting(), len(w.GetValue()))
		}
	}
	code, body, err := d.forward(ctx, call, res.GetHeaderMutations(), call.body)
	if err != nil {
		return err
	}
	d.check("callee authenticates the sandboxed agent", code == http.StatusOK && strings.Contains(body, ansName),
		fmt.Sprintf("status=%d body=%s", code, body))

	d.section("2. Replay, tampering, no identity")
	code, _, err = d.forward(ctx, call, res.GetHeaderMutations(), call.body)
	if err != nil {
		return err
	}
	d.check("replaying the same proof is rejected", code == http.StatusUnauthorized, fmt.Sprintf("status=%d", code))
	fresh, err := d.evaluate(ctx, token, signPolicy, call)
	if err != nil {
		return err
	}
	code, _, err = d.forward(ctx, call, fresh.GetHeaderMutations(), `{"task":"settle invoice 43"}`)
	if err != nil {
		return err
	}
	d.check("a body changed after signing is rejected", code == http.StatusUnauthorized, fmt.Sprintf("status=%d", code))
	code, _, err = d.forward(ctx, call, nil, call.body)
	if err != nil {
		return err
	}
	d.check("an unsigned request is rejected", code == http.StatusUnauthorized, fmt.Sprintf("status=%d", code))

	if err := d.policyScenarios(ctx, token, call); err != nil {
		return err
	}
	d.authScenarios(ctx, signPolicy, call)
	return d.summary()
}

func (d *demo) policyScenarios(ctx context.Context, token string, call outbound) error {
	d.section("3. Policy modes")
	res, err := d.evaluate(ctx, token, map[string]string{"mode": "strip"}, call)
	if err != nil {
		return err
	}
	stripped := res.GetDecision() == middlewarev1.Decision_DECISION_ALLOW && removes(res) == identityHeaderCount
	d.check("strip mode removes identity headers", stripped, fmt.Sprintf("decision=%s removes=%d", res.GetDecision(), removes(res)))

	res, err = d.evaluate(ctx, token, map[string]string{"identity": staleKey}, call)
	if err != nil {
		return err
	}
	d.check("another configured identity is not authorized for this sandbox",
		res.GetDecision() == middlewarev1.Decision_DECISION_DENY && res.GetReasonCode() == middleware.ReasonIdentityUnauthorized,
		fmt.Sprintf("decision=%s reason_code=%s", res.GetDecision(), res.GetReasonCode()))

	res, err = d.evaluate(ctx, token, map[string]string{"identity": identityKey, "destination_policy": "require_registered"}, call)
	if err != nil {
		return err
	}
	d.check("require_registered denies an unregistered destination",
		res.GetDecision() == middlewarev1.Decision_DECISION_DENY && res.GetReasonCode() == vetting.ReasonUnregistered,
		fmt.Sprintf("decision=%s reason_code=%s", res.GetDecision(), res.GetReasonCode()))

	res, err = d.evaluate(ctx, token, map[string]string{"identity": identityKey, "destination_policy": "observe"}, call)
	if err != nil {
		return err
	}
	d.check("observe allows and records the destination finding",
		res.GetDecision() == middlewarev1.Decision_DECISION_ALLOW && strings.Contains(findings(res), "ans_destination_unregistered"),
		fmt.Sprintf("decision=%s findings=%s", res.GetDecision(), findings(res)))
	return nil
}

func (d *demo) authScenarios(ctx context.Context, policy map[string]string, call outbound) {
	d.section("4. Caller authentication")
	res, err := d.evaluate(ctx, d.supervisorToken("sb-other"), policy, call)
	d.check("a supervisor credential for another sandbox is denied",
		err == nil && res.GetDecision() == middlewarev1.Decision_DECISION_DENY && res.GetReasonCode() == middleware.ReasonCallerSandboxMismatch,
		fmt.Sprintf("err=%v reason_code=%s", err, res.GetReasonCode()))
	_, err = d.evaluate(ctx, "", policy, call)
	d.check("a call without a gateway credential is unauthenticated",
		status.Code(err) == codes.Unauthenticated, fmt.Sprintf("grpc code=%s", status.Code(err)))
}

func (d *demo) summary() error {
	d.section("Summary")
	if d.failures > 0 {
		return fmt.Errorf("%d expectation(s) failed", d.failures)
	}
	d.sayf("all expectations held")
	return nil
}

func findings(res *middlewarev1.HttpRequestResult) string {
	names := make([]string, 0, len(res.GetFindings()))
	for _, f := range res.GetFindings() {
		names = append(names, f.GetType())
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

func removes(res *middlewarev1.HttpRequestResult) int {
	n := 0
	for _, m := range res.GetHeaderMutations() {
		if m.GetRemove() != nil {
			n++
		}
	}
	return n
}
