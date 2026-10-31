package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// collect_artifacts is DFIR > Artifact Analysis: a READ-ONLY, bounded collection of a
// FIXED set of named host artifacts. The command carries artifact TYPE names only; each
// name maps to sources compiled in here, so the platform can never name a path, a glob
// or a command. Nothing is executed and nothing on the host is changed: every artifact
// is read from files or /proc with the standard library. Each artifact is capped
// (keeping the most recent tail), hashed (sha256 of the returned bytes, for chain of
// custody) and obvious secrets in shell history are redacted before they leave the host.

const (
	defaultArtifactBytes = 256 * 1024
	maxArtifactBytes     = 512 * 1024
	maxCollectionBytes   = 4 << 20
	recentFilesWindow    = 7 * 24 * time.Hour
	maxRecentFiles       = 2000
	maxProcesses         = 3000
)

// collectRoot prefixes every path read, so tests can point the collector at a fake
// filesystem. Empty in production (the real root).
var collectRoot = ""

func rooted(p string) string { return collectRoot + p }

type artifactSpec struct {
	sources []string // fixed path globs; read in order, existing ones concatenated
	first   bool     // only the first existing source (a log with distro aliases)
	redact  bool
	gen     func() (string, string, error) // generated artifact: content, source label
}

var artifactSpecs = map[string]artifactSpec{
	"auth_log":       {sources: []string{"/var/log/auth.log", "/var/log/secure"}, first: true},
	"syslog":         {sources: []string{"/var/log/syslog", "/var/log/messages"}, first: true},
	"web_access_log": {sources: []string{"/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"}},
	"shell_history": {sources: []string{"/root/.bash_history", "/root/.zsh_history", "/root/.ash_history",
		"/home/*/.bash_history", "/home/*/.zsh_history", "/home/*/.ash_history"}, redact: true},
	"cron": {sources: []string{"/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"}},
	"ssh_authorized_keys": {sources: []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2",
		"/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2"}},
	"users":               {sources: []string{"/etc/passwd", "/etc/group"}},
	"processes":           {gen: collectProcesses},
	"network_connections": {gen: collectConnections},
	"recent_files":        {gen: collectRecentFiles},
}

type collectedArtifact struct {
	Type      string `json:"type"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
	Content   string `json:"content"`
}

func runCollectArtifacts(rawParams json.RawMessage) execResult {
	var p struct {
		Types    []string `json:"types"`
		MaxBytes int      `json:"maxBytes"`
	}
	_ = json.Unmarshal(rawParams, &p)
	if len(p.Types) == 0 {
		return execResult{"failed", map[string]any{"error": "no artifact types given"}}
	}
	if len(p.Types) > len(artifactSpecs) {
		return execResult{"failed", map[string]any{"error": "too many artifact types"}}
	}
	for _, t := range p.Types {
		if _, ok := artifactSpecs[t]; !ok {
			return execResult{"failed", map[string]any{"error": "unknown artifact type: " + t}}
		}
	}
	limit := p.MaxBytes
	if limit <= 0 {
		limit = defaultArtifactBytes
	}
	if limit > maxArtifactBytes {
		limit = maxArtifactBytes
	}
	host, _ := os.Hostname()
	out := []collectedArtifact{}
	seen := map[string]bool{}
	total := 0
	for _, t := range p.Types {
		if seen[t] {
			continue
		}
		seen[t] = true
		a := collectOne(t, limit)
		if total+len(a.Content) > maxCollectionBytes {
			keep := maxCollectionBytes - total
			if keep < 0 {
				keep = 0
			}
			a.Content = a.Content[len(a.Content)-keep:]
			a.Truncated = true
			a.SHA256 = sha256Hex(a.Content)
		}
		total += len(a.Content)
		out = append(out, a)
	}
	return execResult{"done", map[string]any{"hostname": host, "collectedAt": time.Now().UTC().Format(time.RFC3339), "artifacts": out}}
}

func collectOne(t string, limit int) collectedArtifact {
	spec := artifactSpecs[t]
	a := collectedArtifact{Type: t}
	var content string
	if spec.gen != nil {
		c, src, err := spec.gen()
		a.Source = src
		if err != nil {
			a.Error = err.Error()
		}
		content = c
	} else {
		c, srcs, trunc := readSources(spec.sources, spec.first, limit)
		content = c
		a.Truncated = trunc
		a.Source = strings.Join(srcs, ",")
		if len(srcs) == 0 {
			a.Error = "not present on this host"
		}
	}
	if spec.redact {
		content = redactSecrets(content)
	}
	a.Size = len(content)
	if len(content) > limit {
		content = content[len(content)-limit:] // keep the most recent tail
		a.Truncated = true
	}
	a.Content = content
	a.SHA256 = sha256Hex(content)
	return a
}

// readSources reads every existing file matched by the fixed globs. A multi-file
// artifact gets a "==> path <==" header per file so a finding can name its source.
func readSources(globs []string, first bool, limit int) (string, []string, bool) {
	var b strings.Builder
	used := []string{}
	truncated := false
	for _, g := range globs {
		matches, _ := filepath.Glob(rooted(g))
		sort.Strings(matches)
		for _, m := range matches {
			st, err := os.Stat(m)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			data, err := readTail(m, limit)
			if err != nil {
				continue
			}
			if st.Size() > int64(limit) {
				truncated = true
			}
			rel := strings.TrimPrefix(m, collectRoot)
			used = append(used, rel)
			if !first {
				fmt.Fprintf(&b, "==> %s <==\n", rel)
			}
			b.Write(data)
			if len(data) > 0 && data[len(data)-1] != '\n' {
				b.WriteByte('\n')
			}
			if first {
				return b.String(), used, truncated
			}
		}
	}
	return b.String(), used, truncated
}

// readTail reads at most limit bytes from the end of a file, so a huge log never
// exhausts memory.
func readTail(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > int64(limit) {
		if _, err := f.Seek(st.Size()-int64(limit), io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}

var secretPattern = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|token|secret|api[_-]?key)\s*[=:]\s*|--password[= ]\s*)(\S+)`)

// redactSecrets masks the value after an obvious credential key in shell history.
func redactSecrets(s string) string {
	return secretPattern.ReplaceAllString(s, "${1}[REDACTED]")
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// collectProcesses lists processes from /proc: pid, ppid, uid and command line.
func collectProcesses() (string, string, error) {
	entries, err := os.ReadDir(rooted("/proc"))
	if err != nil {
		return "", "/proc", fmt.Errorf("process list unavailable: %v", err)
	}
	var b strings.Builder
	b.WriteString("PID\tPPID\tUID\tCOMMAND\n")
	n := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if n >= maxProcesses {
			break
		}
		base := rooted("/proc/" + e.Name())
		status, _ := os.ReadFile(base + "/status")
		ppid, uid := statusField(status, "PPid:"), statusField(status, "Uid:")
		cmd, _ := os.ReadFile(base + "/cmdline")
		line := strings.TrimSpace(string(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '})))
		if line == "" {
			comm, _ := os.ReadFile(base + "/comm")
			line = "[" + strings.TrimSpace(string(comm)) + "]"
		}
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\n", pid, ppid, uid, line)
		n++
	}
	return b.String(), "/proc", nil
}

func statusField(status []byte, key string) string {
	for _, l := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(l, key) {
			f := strings.Fields(strings.TrimPrefix(l, key))
			if len(f) > 0 {
				return f[0]
			}
		}
	}
	return "-"
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// collectConnections reads /proc/net/{tcp,tcp6,udp,udp6} and resolves each socket
// inode to its owning process through /proc/<pid>/fd.
func collectConnections() (string, string, error) {
	owners := socketOwners()
	var b strings.Builder
	b.WriteString("PROTO\tLOCAL\tREMOTE\tSTATE\tPID/PROGRAM\n")
	found := false
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(rooted("/proc/net/" + proto))
		if err != nil {
			continue
		}
		found = true
		for i, l := range strings.Split(string(data), "\n") {
			f := strings.Fields(l)
			if i == 0 || len(f) < 10 {
				continue
			}
			state := tcpStates[f[3]]
			if strings.HasPrefix(proto, "udp") {
				state = "-"
			}
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", proto, hexAddr(f[1]), hexAddr(f[2]), state, firstNonEmpty(owners[f[9]], "-"))
		}
	}
	if !found {
		return "", "/proc/net", fmt.Errorf("socket table unavailable")
	}
	return b.String(), "/proc/net", nil
}

func socketOwners() map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(rooted("/proc"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		base := rooted("/proc/" + e.Name())
		fds, err := os.ReadDir(base + "/fd")
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(base + "/comm")
		for _, fd := range fds {
			link, err := os.Readlink(base + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			out[inode] = e.Name() + "/" + strings.TrimSpace(string(comm))
		}
	}
	return out
}

// hexAddr renders a /proc/net "ADDR:PORT" pair (little-endian hex) as ip:port.
func hexAddr(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s
	}
	port, _ := strconv.ParseUint(parts[1], 16, 32)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return s
	}
	var ip string
	switch len(raw) {
	case 4:
		ip = fmt.Sprintf("%d.%d.%d.%d", raw[3], raw[2], raw[1], raw[0])
	case 16:
		b := make([]byte, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				b[i*4+j] = raw[i*4+3-j]
			}
		}
		groups := make([]string, 8)
		for i := 0; i < 8; i++ {
			groups[i] = strconv.FormatUint(uint64(b[i*2])<<8|uint64(b[i*2+1]), 16)
		}
		ip = "[" + strings.Join(groups, ":") + "]"
	default:
		return s
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// collectRecentFiles lists files modified within the window under fixed directories
// attackers commonly drop into or tamper with. Metadata only, never file content.
func collectRecentFiles() (string, string, error) {
	roots := []string{"/tmp", "/var/tmp", "/dev/shm", "/etc", "/var/www"}
	cutoff := time.Now().Add(-recentFilesWindow)
	type entry struct {
		mod  time.Time
		line string
	}
	items := []entry{}
	for _, r := range roots {
		base := rooted(r)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(strings.TrimPrefix(p, base), "/") > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(cutoff) {
				return nil
			}
			rel := strings.TrimPrefix(p, collectRoot)
			items = append(items, entry{info.ModTime(), fmt.Sprintf("%s\t%s\t%d\t%s",
				info.ModTime().UTC().Format(time.RFC3339), info.Mode().String(), info.Size(), rel)})
			return nil
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.After(items[j].mod) })
	if len(items) > maxRecentFiles {
		items = items[:maxRecentFiles]
	}
	var b strings.Builder
	b.WriteString("MODIFIED\tMODE\tSIZE\tPATH\n")
	for _, it := range items {
		b.WriteString(it.line + "\n")
	}
	return b.String(), strings.Join(roots, ","), nil
}
