package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogPathAllowed(t *testing.T) {
	allow := []string{"/var/log/auth.log", "/var/log/app/"}
	cases := []struct {
		path string
		want bool
	}{
		{"/var/log/auth.log", true},                 // exact file
		{"/var/log/app/web.log", true},              // inside a dir prefix
		{"/var/log/app/sub/deep.log", true},         // deeper inside a dir prefix
		{"/var/log/syslog", false},                  // not allowlisted
		{"/etc/shadow", false},                      // not allowlisted
		{"/var/log/app", false},                     // the dir itself, not strictly inside
		{"/var/log/auth.log.1", false},              // near-miss on an exact entry
		{"/var/log/app/../../etc/passwd", false},    // traversal is refused outright
		{"", false},                                 // empty
	}
	for _, c := range cases {
		if got := logPathAllowed(c.path, allow); got != c.want {
			t.Fatalf("logPathAllowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestRunReadLogs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	var b strings.Builder
	for i := 1; i <= 50; i++ {
		if i == 42 {
			b.WriteString("Failed password for root from 203.0.113.9\n")
			continue
		}
		b.WriteString("Accepted password for deploy line ")
		b.WriteByte(byte('0' + i%10))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	allow := []string{logPath}

	// A non-allowlisted path is refused, never opened.
	res := runReadLogs(json.RawMessage(`{"path":"/etc/shadow"}`), allow)
	if res.Status != "failed" {
		t.Fatalf("non-allowlisted path should fail, got %q", res.Status)
	}

	// A grep returns only matching lines.
	params, _ := json.Marshal(map[string]any{"path": logPath, "grep": "failed password", "maxLines": 100})
	res = runReadLogs(params, allow)
	if res.Status != "done" {
		t.Fatalf("expected done, got %q (%v)", res.Status, res.Result)
	}
	out, _ := res.Result["output"].(string)
	if !strings.Contains(out, "203.0.113.9") {
		t.Fatalf("grep should have matched the failed-password line, got %q", out)
	}
	if strings.Contains(out, "Accepted password") {
		t.Fatalf("grep should have excluded non-matching lines, got %q", out)
	}
	if m, _ := res.Result["matched"].(int); m != 1 {
		t.Fatalf("expected 1 matched line, got %v", res.Result["matched"])
	}

	// maxLines tails: with a tiny cap only the last N lines come back.
	params, _ = json.Marshal(map[string]any{"path": logPath, "maxLines": 3})
	res = runReadLogs(params, allow)
	out, _ = res.Result["output"].(string)
	if got := strings.Count(out, "\n"); got != 2 { // 3 lines -> 2 newlines
		t.Fatalf("maxLines=3 should tail 3 lines (2 newlines), got %d in %q", got, out)
	}
	if lines, _ := res.Result["lines"].(int); lines != 3 {
		t.Fatalf("expected lines=3, got %v", res.Result["lines"])
	}
}
