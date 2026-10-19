package logging

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		level      string
		format     string
		wantErr    bool
		debugShown bool
		jsonOut    bool
	}{
		{name: "defaults", jsonOut: true},
		{name: "debug text", level: "debug", format: "text", debugShown: true},
		{name: "warn json", level: "WARN", format: "JSON", jsonOut: true},
		{name: "error", level: "error", format: "text"},
		{name: "warning alias", level: "warning", format: "text"},
		{name: "bad level", level: "loud", wantErr: true},
		{name: "bad format", format: "xml", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger, err := New(tt.level, tt.format, &buf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			logger.DebugContext(context.Background(), "dbg")
			logger.ErrorContext(context.Background(), "boom", "k", "v")
			out := buf.String()
			if strings.Contains(out, "dbg") != tt.debugShown {
				t.Fatalf("debug shown = %v, want %v; output %q", !tt.debugShown, tt.debugShown, out)
			}
			if !strings.Contains(out, "boom") {
				t.Fatalf("error line missing from %q", out)
			}
			if tt.jsonOut != strings.HasPrefix(out, "{") {
				t.Fatalf("json = %v, want %v; output %q", strings.HasPrefix(out, "{"), tt.jsonOut, out)
			}
		})
	}
}
