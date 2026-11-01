package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// collect_memory is DFIR > Memory Analysis: READ-ONLY live triage of volatile process
// memory. Like collect_artifacts, the command carries fixed TYPE names only and every
// type maps to a reader compiled in here. Everything is read from /proc with the
// standard library: no full RAM image is taken, no kernel module is loaded, nothing is
// executed or written. The agent's own process is always skipped (its memory and
// environment hold its key and the signed command). Memory strings are filtered to
// indicator-looking text from suspicious regions, heap and stack, and secrets are
// redacted before anything leaves the host.

const (
	memMaxProcesses       = 2000
	memRegionReadCap      = 2 << 20  // bytes read from one memory region
	memProcessReadCap     = 16 << 20 // bytes read from one process
	memMaxStringsPerProc  = 150
	memMinStringLen       = 6
	memMaxStringLen       = 400
	memSuspectStringsKept = 25 // plain strings kept from a writable+executable region
	clockTicks            = 100
)

var memorySpecs = map[string]artifactSpec{
	"mem_process_tree": {gen: collectProcessTree},
	"mem_maps":         {gen: collectMemoryMaps},
	"mem_fileless":     {gen: collectFileless},
	"mem_environ":      {gen: collectProcEnviron},
	"mem_strings":      {gen: collectMemoryStrings},
	"mem_sockets":      {gen: collectConnections},
}

func runCollectMemory(rawParams json.RawMessage) execResult {
	return runCollect(rawParams, memorySpecs)
}

// selfPID is the agent's own pid; a var so tests can pretend to be another process.
var selfPID = os.Getpid()

type procInfo struct {
	pid     int
	ppid    string
	uid     string
	comm    string
	cmdline string
	exe     string
	started string
	threads string
	rssKB   string
}

func procBase(pid int) string { return rooted("/proc/" + strconv.Itoa(pid)) }

// listPIDs returns the numeric /proc entries, skipping the agent itself.
func listPIDs() ([]int, error) {
	entries, err := os.ReadDir(rooted("/proc"))
	if err != nil {
		return nil, err
	}
	out := []int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == selfPID {
			continue
		}
		out = append(out, pid)
		if len(out) >= memMaxProcesses {
			break
		}
	}
	sort.Ints(out)
	return out, nil
}

func readProc(pid int) procInfo {
	base := procBase(pid)
	p := procInfo{pid: pid}
	status, _ := os.ReadFile(base + "/status")
	p.ppid, p.uid = statusField(status, "PPid:"), statusField(status, "Uid:")
	p.threads, p.rssKB = statusField(status, "Threads:"), statusField(status, "VmRSS:")
	comm, _ := os.ReadFile(base + "/comm")
	p.comm = strings.TrimSpace(string(comm))
	cmd, _ := os.ReadFile(base + "/cmdline")
	p.cmdline = strings.TrimSpace(string(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '})))
	if p.cmdline == "" {
		p.cmdline = "[" + p.comm + "]"
	}
	p.cmdline = redactSecrets(clipStr(p.cmdline, 500))
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		p.exe = exe
	} else {
		p.exe = "-"
	}
	p.started = processStart(base)
	return p
}

// processStart turns /proc/<pid>/stat starttime (clock ticks since boot) into a UTC
// timestamp using btime from /proc/stat.
func processStart(base string) string {
	stat, err := os.ReadFile(base + "/stat")
	if err != nil {
		return "-"
	}
	s := string(stat)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return "-"
	}
	f := strings.Fields(s[i+1:])
	// fields after ")" start at stat field 3 (state); starttime is field 22.
	if len(f) < 20 {
		return "-"
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return "-"
	}
	btime := bootTime()
	if btime == 0 {
		return "-"
	}
	return time.Unix(btime+ticks/clockTicks, 0).UTC().Format(time.RFC3339)
}

func bootTime() int64 {
	data, err := os.ReadFile(rooted("/proc/stat"))
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "btime ") {
			v, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(l, "btime ")), 10, 64)
			return v
		}
	}
	return 0
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// collectProcessTree lists every process with its start time (first column, so a
// timeline can be built), parent, user, threads, RSS, executable link and command line.
func collectProcessTree() (string, string, error) {
	pids, err := listPIDs()
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	b.WriteString("STARTED\tPID\tPPID\tUID\tTHREADS\tRSS_KB\tEXE\tCOMMAND\n")
	for _, pid := range pids {
		p := readProc(pid)
		fmt.Fprintf(&b, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", p.started, p.pid, p.ppid, p.uid, p.threads, p.rssKB, p.exe, p.cmdline)
	}
	return b.String(), "/proc/*/{stat,status,exe,cmdline}", nil
}

type memRegion struct {
	start, end uint64
	perms      string
	path       string
	flags      []string
}

var unusualExecDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/", "/root/"}

// parseMaps reads /proc/<pid>/maps and flags the regions a forensic analyst cares
// about: writable+executable, anonymous executable, memfd-backed, deleted and
// executable mappings from unusual directories.
func parseMaps(pid int) ([]memRegion, error) {
	data, err := os.ReadFile(procBase(pid) + "/maps")
	if err != nil {
		return nil, err
	}
	out := []memRegion{}
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		addr := strings.SplitN(f[0], "-", 2)
		if len(addr) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(addr[0], 16, 64)
		end, err2 := strconv.ParseUint(addr[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		r := memRegion{start: start, end: end, perms: f[1]}
		if len(f) > 5 {
			r.path = strings.Join(f[5:], " ")
		}
		if r.path == "[vdso]" || r.path == "[vsyscall]" || r.path == "[vvar]" {
			continue
		}
		exec := strings.Contains(r.perms, "x")
		if exec && strings.Contains(r.perms, "w") {
			r.flags = append(r.flags, "RWX")
		}
		if exec && (r.path == "" || (strings.HasPrefix(r.path, "[") && r.path != "[vdso]")) {
			r.flags = append(r.flags, "ANON_EXEC")
		}
		if strings.Contains(r.path, "memfd:") {
			r.flags = append(r.flags, "MEMFD")
		}
		if strings.HasSuffix(r.path, "(deleted)") {
			r.flags = append(r.flags, "DELETED")
		}
		if exec {
			for _, d := range unusualExecDirs {
				if strings.HasPrefix(r.path, d) {
					r.flags = append(r.flags, "UNUSUAL_PATH")
					break
				}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func (r memRegion) label() string {
	p := r.path
	if p == "" {
		p = "[anon]"
	}
	return fmt.Sprintf("%x-%x %s %s", r.start, r.end, r.perms, p)
}

// collectMemoryMaps lists the flagged memory regions of every process, one region per
// line, plus a summary line per process so a clean process is visible too.
func collectMemoryMaps() (string, string, error) {
	pids, err := listPIDs()
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	unreadable := 0
	for _, pid := range pids {
		regions, err := parseMaps(pid)
		if err != nil {
			unreadable++
			continue
		}
		p := readProc(pid)
		flagged := 0
		for _, r := range regions {
			if len(r.flags) == 0 {
				continue
			}
			flagged++
			fmt.Fprintf(&b, "pid=%d comm=%s region=%s flags=%s\n", pid, p.comm, r.label(), strings.Join(r.flags, ","))
		}
		fmt.Fprintf(&b, "pid=%d comm=%s summary regions=%d flagged=%d exe=%s\n", pid, p.comm, len(regions), flagged, p.exe)
	}
	if unreadable > 0 {
		fmt.Fprintf(&b, "note: %d process(es) had unreadable memory maps (permission or exited)\n", unreadable)
	}
	return b.String(), "/proc/*/maps", nil
}

// collectFileless reports processes whose executable is deleted, memfd-backed or in a
// temp/home directory, and processes masquerading as kernel threads.
func collectFileless() (string, string, error) {
	pids, err := listPIDs()
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	b.WriteString("PID\tPPID\tUID\tREASONS\tEXE\tCOMMAND\n")
	for _, pid := range pids {
		p := readProc(pid)
		reasons := []string{}
		if strings.Contains(p.exe, "memfd:") {
			reasons = append(reasons, "MEMFD_EXE")
		} else if strings.HasSuffix(p.exe, "(deleted)") {
			reasons = append(reasons, "DELETED_EXE")
		}
		for _, d := range unusualExecDirs {
			if strings.HasPrefix(p.exe, d) {
				reasons = append(reasons, "TEMP_OR_HOME_EXE")
				break
			}
		}
		// A user process (it has an executable) whose command line looks like a kernel
		// thread, e.g. "[kworker/0:1]", is a classic disguise.
		if p.exe != "-" && strings.HasPrefix(p.cmdline, "[") && strings.HasSuffix(p.cmdline, "]") {
			reasons = append(reasons, "KERNEL_THREAD_NAME")
		}
		if len(reasons) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\t%s\n", pid, p.ppid, p.uid, strings.Join(reasons, ","), p.exe, p.cmdline)
	}
	return b.String(), "/proc/*/exe", nil
}

var notableEnv = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "HISTFILE": true, "HISTSIZE": true,
	"HISTFILESIZE": true, "HISTCONTROL": true, "PROMPT_COMMAND": true, "http_proxy": true, "https_proxy": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "PYTHONPATH": true, "PATH": true,
}

var secretEnvName = regexp.MustCompile(`(?i)pass|token|secret|key|credential|auth`)

// collectProcEnviron prints only notable variables; any variable whose name looks
// like a secret is listed with its value redacted.
func collectProcEnviron() (string, string, error) {
	pids, err := listPIDs()
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	unreadable := 0
	for _, pid := range pids {
		data, err := os.ReadFile(procBase(pid) + "/environ")
		if err != nil {
			unreadable++
			continue
		}
		comm, _ := os.ReadFile(procBase(pid) + "/comm")
		name := strings.TrimSpace(string(comm))
		for _, kv := range bytes.Split(data, []byte{0}) {
			k, v, ok := strings.Cut(string(kv), "=")
			if !ok || k == "" {
				continue
			}
			switch {
			case secretEnvName.MatchString(k):
				v = "[REDACTED]"
			case notableEnv[k]:
				v = redactSecrets(clipStr(v, 300))
			default:
				continue
			}
			fmt.Fprintf(&b, "pid=%d comm=%s %s=%s\n", pid, name, k, v)
		}
	}
	if unreadable > 0 {
		fmt.Fprintf(&b, "note: %d process environment(s) unreadable (permission or exited)\n", unreadable)
	}
	return b.String(), "/proc/*/environ", nil
}

// indicatorString matches memory strings worth an analyst's attention.
var indicatorString = regexp.MustCompile(`(?i)https?://|/dev/tcp/|/dev/udp/|\bbash\s+-i\b|\bsh\s+-i\b|\bnc(?:at)?\s+-[a-z]*e\b|` +
	`socat\s|mkfifo|\bwget\s|\bcurl\s|base64\s+-d|LD_PRELOAD|stratum\+tcp|xmrig|\.onion\b|` +
	`BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|pass(?:word|wd)?\s*[=:]|\btoken\s*[=:]|secret\s*[=:]|` +
	`\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b|/(?:tmp|dev/shm|var/tmp)/\S+|\bchmod\s+\+x\b|\bcrontab\b|/etc/(?:passwd|shadow)`)

var privateKeyPattern = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----.*`)
var awsKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

func redactMemoryString(s string) string {
	s = privateKeyPattern.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	s = awsKeyPattern.ReplaceAllStringFunc(s, func(k string) string { return k[:4] + "[REDACTED]" })
	return redactSecrets(s)
}

// printableRuns extracts printable ASCII runs of at least memMinStringLen bytes.
func printableRuns(data []byte, emit func(string) bool) {
	start := -1
	for i := 0; i <= len(data); i++ {
		printable := i < len(data) && (data[i] >= 0x20 && data[i] < 0x7f || data[i] == '\t')
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= memMinStringLen {
			s := string(data[start:i])
			if len(s) > memMaxStringLen {
				s = s[:memMaxStringLen]
			}
			if !emit(s) {
				return
			}
		}
		start = -1
	}
}

// stringRegion reports whether a region is scanned for strings, and whether it is a
// suspicious one (from which a few plain strings are kept even without an indicator).
func stringRegion(r memRegion) (scan, suspect bool) {
	if !strings.HasPrefix(r.perms, "r") {
		return false, false
	}
	if len(r.flags) > 0 {
		return true, true
	}
	switch {
	case r.path == "[heap]" || r.path == "[stack]":
		return true, false
	case r.path == "" && strings.Contains(r.perms, "w"):
		return true, false // anonymous writable memory: interpreter heaps, buffers
	}
	return false, false
}

// collectMemoryStrings reads the scanned regions through /proc/<pid>/mem (bounded per
// region and per process) and keeps indicator strings, redacted. Reading another
// process's memory needs ptrace-read access; a refused process is counted, not fatal.
func collectMemoryStrings() (string, string, error) {
	pids, err := listPIDs()
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	unreadable := 0
	for _, pid := range pids {
		regions, err := parseMaps(pid)
		if err != nil {
			unreadable++
			continue
		}
		mem, err := os.Open(procBase(pid) + "/mem")
		if err != nil {
			unreadable++
			continue
		}
		comm, _ := os.ReadFile(procBase(pid) + "/comm")
		name := strings.TrimSpace(string(comm))
		seen := map[string]bool{}
		kept, budget, readOK := 0, memProcessReadCap, false
		for _, r := range regions {
			scan, suspect := stringRegion(r)
			if !scan || budget <= 0 || kept >= memMaxStringsPerProc {
				continue
			}
			size := r.end - r.start
			if size > memRegionReadCap {
				size = memRegionReadCap
			}
			if int(size) > budget {
				size = uint64(budget)
			}
			buf := make([]byte, size)
			n, _ := mem.ReadAt(buf, int64(r.start))
			if n <= 0 {
				continue
			}
			readOK = true
			budget -= n
			plain := 0
			printableRuns(buf[:n], func(s string) bool {
				hit := indicatorString.MatchString(s)
				if !hit && !(suspect && len(s) >= 8 && plain < memSuspectStringsKept) {
					return true
				}
				s = redactMemoryString(strings.TrimSpace(s))
				if s == "" || seen[s] {
					return true
				}
				seen[s] = true
				if !hit {
					plain++
				}
				kept++
				fmt.Fprintf(&b, "pid=%d comm=%s region=%s | %s\n", pid, name, r.label(), s)
				return kept < memMaxStringsPerProc
			})
		}
		mem.Close()
		if !readOK {
			unreadable++
		}
	}
	if unreadable > 0 {
		fmt.Fprintf(&b, "note: %d process(es) had unreadable memory (needs ptrace read access, or exited)\n", unreadable)
	}
	return b.String(), "/proc/*/mem (suspicious regions, heap, stack)", nil
}

// memoryPathsForTest lists the per-process files the collectors read; used by tests
// to build a fake /proc. Kept here so the list cannot drift from the readers.
var memoryPathsForTest = []string{"stat", "status", "comm", "cmdline", "maps", "environ", "mem"}
