package hydrator

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// The two record examples from OpenShell's OCSF JSON export documentation,
// compacted to one line each as they appear in a JSONL file.
const (
	allowedExampleJSON = `{"class_uid":4001,"class_name":"Network Activity","category_uid":4,"category_name":"Network Activity","activity_id":1,"activity_name":"Open","severity_id":1,"severity":"Informational","status_id":1,"status":"Success","time":1775014138811,"message":"CONNECT allowed api.github.com:443","metadata":{"product":{"name":"OpenShell Sandbox Supervisor","vendor_name":"OpenShell","version":"0.1.4"},"version":"1.8.0"},"action_id":1,"action":"Allowed","disposition_id":1,"disposition":"Allowed","dst_endpoint":{"domain":"api.github.com","port":443},"src_endpoint":{"ip":"192.0.2.31","port":37494},"actor":{"process":{"name":"/usr/bin/curl","pid":57}},"firewall_rule":{"name":"github_api","type":"opa"}}`
	deniedExampleJSON  = `{"class_uid":4001,"class_name":"Network Activity","category_uid":4,"category_name":"Network Activity","activity_id":1,"activity_name":"Open","type_uid":400101,"type_name":"Network Activity: Open","time":1791996125789,"severity_id":3,"severity":"Medium","status_id":2,"status":"Failure","message":"Transparent TCP denied before relay: network connections not allowed by policy","status_detail":"transparent_tcp_policy_denied","metadata":{"version":"1.8.0","product":{"name":"OpenShell Sandbox Supervisor","vendor_name":"OpenShell","version":"0.1.4"},"profiles":["security_control","network_proxy","container","host"],"uid":"b885957d-124a-4af7-9eef-75cc410ff070"},"device":{"hostname":"docker-desktop","type_id":99,"type":"Sandbox","os":{"name":"Linux"}},"container":{"name":"docs-deny","uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"},"dst_endpoint":{"domain":"github.com","ip":"198.18.0.2","port":443},"proxy_endpoint":{"ip":"127.0.0.1","port":3128},"actor":{"process":{"name":"/usr/bin/curl","pid":2187,"cmd_line":"curl https://github.com"}},"action_id":2,"action":"Denied","disposition_id":2,"disposition":"Blocked","is_src_dst_assignment_known":true}`

	deniedExampleUID   = "3949f6fc-2b84-45b2-a631-46debe41d84f"
	deniedExampleName  = "docs-deny"
	deniedExampleTime  = int64(1791996125789)
	allowedExampleTime = int64(1775014138811)

	stderrTimestamp = "2026-10-07T23:21:19.000Z"
)

// netSpec describes a synthetic Network or HTTP Activity record.
type netSpec struct {
	class    int
	uid      string
	name     string
	denied   bool
	statusID int
	detail   string
	domain   string
	ip       string
	timeMs   int64
}

func netLine(t *testing.T, s netSpec) string {
	t.Helper()
	fields := map[string]any{"class_uid": s.class}
	if s.timeMs != 0 {
		fields["time"] = s.timeMs
	}
	if s.uid != "" || s.name != "" {
		fields["container"] = map[string]any{"uid": s.uid, "name": s.name}
	}
	if s.domain != "" || s.ip != "" {
		fields["dst_endpoint"] = map[string]any{"domain": s.domain, "ip": s.ip, "port": 443}
	}
	switch {
	case s.denied:
		fields["action_id"] = 2
		fields["disposition_id"] = 2
		fields["status_id"] = 2
		fields["status_detail"] = s.detail
	case s.statusID != 0:
		fields["action_id"] = 1
		fields["disposition_id"] = 1
		fields["status_id"] = s.statusID
	default:
		fields["action_id"] = 1
		fields["disposition_id"] = 1
		fields["status_id"] = 1
	}
	return jsonLine(t, fields)
}

func findingLine(t *testing.T, uid string, severity int, timeMs int64) string {
	t.Helper()
	return jsonLine(t, map[string]any{
		"class_uid":   ClassDetectionFinding,
		"severity_id": severity,
		"time":        timeMs,
		"container":   map[string]any{"uid": uid},
	})
}

func stderrLine(payload string) string {
	return stderrTimestamp + " OCSF-JSON " + payload
}

func jsonLine(t *testing.T, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

func exampleFields(t *testing.T, example string) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(example), &fields); err != nil {
		t.Fatalf("unmarshal example: %v", err)
	}
	return fields
}

func parseAll(t *testing.T, input string) ([]Event, ParseStats) {
	t.Helper()
	r := NewReader(strings.NewReader(input))
	var events []Event
	for {
		ev, err := r.Read()
		if errors.Is(err, io.EOF) {
			return events, r.Stats()
		}
		if err != nil {
			t.Fatalf("Read() error: %v", err)
		}
		events = append(events, ev)
	}
}

func mustAgentMap(t *testing.T, mappings ...AgentMapping) AgentMap {
	t.Helper()
	m, err := NewAgentMap(mappings)
	if err != nil {
		t.Fatalf("NewAgentMap() error: %v", err)
	}
	return m
}

func netEvent(class int, sandboxUID string, denied bool, detail, domain, ip string, timeMs int64) Event {
	ev := Event{ClassUID: class, Time: timeMs, StatusDetail: detail, ActionID: 1, DispositionID: 1, StatusID: 1}
	if sandboxUID != "" {
		ev.Container = &Container{UID: sandboxUID}
	}
	if domain != "" || ip != "" {
		ev.DstEndpoint = &Endpoint{Domain: domain, IP: ip}
	}
	if denied {
		ev.ActionID = deniedID
		ev.DispositionID = deniedID
		ev.StatusID = deniedID
	}
	return ev
}
