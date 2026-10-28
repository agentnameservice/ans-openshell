package hydrator

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// OCSF class_uid values emitted by OpenShell.
const (
	ClassBaseEvent          = 0
	ClassProcessActivity    = 1007
	ClassDetectionFinding   = 2004
	ClassNetworkActivity    = 4001
	ClassHTTPActivity       = 4002
	ClassSSHActivity        = 4007
	ClassDeviceConfigChange = 5019
	ClassAppLifecycle       = 6002
)

// deniedID is the shared OCSF enum value of action_id Denied, disposition_id
// Blocked and status_id Failure.
const deniedID = 2

// MaxLineBytes bounds one input line including its terminator. Longer lines
// are discarded and counted in ParseStats.Oversized.
const MaxLineBytes = 1 << 20

const readChunkBytes = 64 << 10

// ocsfJSONMarker separates the timestamp from the JSON payload on supervisor
// stderr; the payload is everything after it.
const ocsfJSONMarker = "OCSF-JSON "

// Event is the subset of an OCSF record the hydrator reads. Unknown classes
// decode too, so they can be counted even when they carry nothing of interest.
type Event struct {
	ClassUID      int           `json:"class_uid"`
	ActivityID    int           `json:"activity_id"`
	ActionID      int           `json:"action_id"`
	DispositionID int           `json:"disposition_id"`
	StatusID      int           `json:"status_id"`
	SeverityID    int           `json:"severity_id"`
	StatusDetail  string        `json:"status_detail"`
	Message       string        `json:"message"`
	Time          int64         `json:"time"`
	Metadata      Metadata      `json:"metadata"`
	Container     *Container    `json:"container"`
	DstEndpoint   *Endpoint     `json:"dst_endpoint"`
	Actor         *Actor        `json:"actor"`
	FirewallRule  *FirewallRule `json:"firewall_rule"`
	// Raw metadata preserves legacy decoding even when the optional fields
	// have a shape the corrected evidence path does not understand.
	Unmapped    json.RawMessage `json:"unmapped"`
	FindingInfo json.RawMessage `json:"finding_info"`
}

// Metadata is the OCSF metadata object.
type Metadata struct {
	UID     string  `json:"uid"`
	Version string  `json:"version"`
	Product Product `json:"product"`
}

// Product identifies the emitting OpenShell component.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// Container is the sandbox the event belongs to. OpenShell omits it for
// events without a sandbox association and strips it on schema downgrade.
type Container struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
}

// Endpoint is an OCSF network endpoint.
type Endpoint struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}

// Actor is the OCSF actor object.
type Actor struct {
	Process *Process `json:"process"`
}

// Process is the sandbox process that caused the event.
type Process struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
}

// FirewallRule is the network policy rule that decided the event.
type FirewallRule struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Timestamp returns the event time (OCSF time is milliseconds since the Unix
// epoch) and whether the record carried one.
func (e Event) Timestamp() (time.Time, bool) {
	if e.Time <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(e.Time).UTC(), true
}

// Denied reports whether the event was denied, blocked or failed: any of
// action_id, disposition_id or status_id equals 2.
func (e Event) Denied() bool {
	return e.ActionID == deniedID || e.DispositionID == deniedID || e.StatusID == deniedID
}

// IsNetwork reports whether the event is Network Activity or HTTP Activity,
// the classes the observations are computed from.
func (e Event) IsNetwork() bool {
	return e.ClassUID == ClassNetworkActivity || e.ClassUID == ClassHTTPActivity
}

// Destination returns the destination domain, or the IP when no domain is
// recorded, or "" when the event has no destination.
func (e Event) Destination() string {
	if e.DstEndpoint == nil {
		return ""
	}
	if e.DstEndpoint.Domain != "" {
		return e.DstEndpoint.Domain
	}
	return e.DstEndpoint.IP
}

// ParseStats counts what a Reader saw. Lines equals Events plus Skipped;
// Oversized is the subset of Skipped that exceeded MaxLineBytes.
type ParseStats struct {
	Lines     int
	Events    int
	Skipped   int
	Oversized int
}

// Reader decodes OCSF events from a JSONL file or from supervisor stderr.
type Reader struct {
	br    *bufio.Reader
	line  []byte
	stats ParseStats
	// invalidOCSF is deliberately separate from the legacy public counters.
	// The corrected evidence path cannot safely attribute a discarded audit line.
	invalidOCSF   int
	oversizedOCSF int
	truncatedTail int
}

// auditInputHealth counts audit lines the corrected evidence path could not use.
type auditInputHealth struct {
	// unreadable lines are malformed or oversized audit records in the body of the input.
	unreadable int
	// truncatedTail counts an undecodable final line without a newline, which
	// a collector is usually still writing.
	truncatedTail int
}

// NewReader returns a Reader over r.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, readChunkBytes)}
}

func (r *Reader) auditHealth() auditInputHealth {
	return auditInputHealth{unreadable: r.invalidOCSF + r.oversizedOCSF, truncatedTail: r.truncatedTail}
}

// Read returns the next event. It returns io.EOF once the input is exhausted
// and any other error only when the underlying reader fails; lines that do
// not hold an event are skipped and counted.
func (r *Reader) Read() (Event, error) {
	for {
		line, oversized, err := r.readLine()
		if err != nil {
			return Event{}, err
		}
		r.stats.Lines++
		if oversized {
			r.stats.Oversized++
			r.stats.Skipped++
			continue
		}
		ev, ok := decodeLine(line)
		if !ok {
			r.countUndecodable(line)
			r.stats.Skipped++
			continue
		}
		r.stats.Events++
		return ev, nil
	}
}

// Stats returns the counters accumulated so far.
func (r *Reader) Stats() ParseStats {
	return r.stats
}

// readLine returns the next line and whether it exceeded MaxLineBytes, in
// which case the line content is discarded.
func (r *Reader) readLine() ([]byte, bool, error) {
	r.line = r.line[:0]
	oversized := false
	for {
		chunk, err := r.br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return nil, false, fmt.Errorf("hydrator: read input: %w", err)
		}
		if !oversized {
			if len(r.line)+len(chunk) > MaxLineBytes {
				if looksLikeAudit(r.line) {
					r.oversizedOCSF++
				}
				oversized = true
				r.line = r.line[:0]
			} else {
				r.line = append(r.line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(chunk) == 0 && len(r.line) == 0 && !oversized {
			return nil, false, io.EOF
		}
		return r.line, oversized, nil
	}
}

// countUndecodable records an audit-looking line that did not decode. Only the
// final line can lack its newline, since readLine splits on newlines.
func (r *Reader) countUndecodable(line []byte) {
	if !looksLikeAudit(line) {
		return
	}
	if !bytes.HasSuffix(line, []byte("\n")) {
		r.truncatedTail++
		return
	}
	r.invalidOCSF++
}

// looksLikeAudit reports whether decodeLine would have tried to parse the line
// as an audit record: a JSON object, or the supervisor's OCSF-JSON marker
// followed by an object or by nothing at all.
func looksLikeAudit(line []byte) bool {
	payload, ok := auditPayload(line)
	return ok && (len(payload) == 0 || payload[0] == '{')
}

// auditPayload returns the JSON payload of an audit line: a bare JSONL object,
// or the object after the supervisor's "{ts} OCSF-JSON " framing, which a log
// collector may prefix with its own timestamp. The marker must be a whole
// token preceded only by timestamp text; shorthand lines carry a bracketed
// severity tag before any request-derived text, so a copy of a record inside
// a shorthand line never looks like the record.
func auditPayload(line []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed, true
	}
	marker := bytes.TrimSpace([]byte(ocsfJSONMarker))
	idx := bytes.Index(trimmed, marker)
	if idx < 0 || (idx > 0 && trimmed[idx-1] != ' ') || bytes.IndexByte(trimmed[:idx], '[') >= 0 {
		return nil, false
	}
	payload := trimmed[idx+len(marker):]
	if len(payload) > 0 && payload[0] != ' ' {
		return nil, false
	}
	return bytes.TrimSpace(payload), true
}

// decodeLine extracts the JSON payload from a JSONL or stderr line and
// decodes it. It reports false for blank, shorthand and malformed lines.
func decodeLine(line []byte) (Event, bool) {
	payload, ok := auditPayload(line)
	if !ok || len(payload) == 0 || payload[0] != '{' {
		return Event{}, false
	}
	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return Event{}, false
	}
	return ev, true
}
