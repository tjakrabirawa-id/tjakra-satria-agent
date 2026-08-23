package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// The executor runs the allowlisted actions and never a free-form shell command.
// Targets are validated to a strict character set and passed as argv (not through a
// shell), so a crafted target cannot inject. Destructive actions are a dry-run
// unless the agent was started with -enforce, so a test run never touches a live
// firewall or account by accident.

type execResult struct {
	Status string
	Result map[string]any
}

func executeCommand(cmd command, enforce, console bool) execResult {
	var params map[string]any
	_ = json.Unmarshal(cmd.Params, &params)
	target, _ := params["target"].(string)

	switch cmd.Action {
	case "block_ip":
		return runFirewall("block", target, enforce)
	case "revert_block":
		return runFirewall("revert", target, enforce)
	case "disable_user":
		return runDisableUser(target, enforce)
	case "isolate_host":
		return execResult{"done", map[string]any{"note": "host isolation is recorded but not enforced in this agent build"}}
	case "run_collector":
		return runCollector()
	case "run_probe":
		return runProbe(cmd.Params)
	case "run_command":
		return runCommand(cmd.Params, console)
	}
	return execResult{"failed", map[string]any{"error": "unknown action"}}
}

func validIPTarget(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for _, r := range t {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '.' || r == ':' || r == '/') {
			return false
		}
	}
	return true
}

func validUsername(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func iptablesArgs(op, target string) []string {
	if op == "revert" {
		return []string{"-D", "INPUT", "-s", target, "-j", "DROP"}
	}
	return []string{"-I", "INPUT", "-s", target, "-j", "DROP"}
}

func runFirewall(op, target string, enforce bool) execResult {
	if !validIPTarget(target) {
		return execResult{"failed", map[string]any{"error": "invalid target"}}
	}
	args := iptablesArgs(op, target)
	if runtime.GOOS != "linux" {
		return execResult{"done", map[string]any{"note": "recorded on a non-linux host, no firewall change", "op": op, "target": target}}
	}
	if !enforce {
		return execResult{"done", map[string]any{"note": "dry-run: start the agent with -enforce to apply", "op": op, "target": target, "wouldRun": append([]string{"iptables"}, args...)}}
	}
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return execResult{"failed", map[string]any{"error": err.Error(), "output": string(out)}}
	}
	return execResult{"done", map[string]any{"op": op, "target": target, "output": string(out)}}
}

func runDisableUser(user string, enforce bool) execResult {
	if !validUsername(user) {
		return execResult{"failed", map[string]any{"error": "invalid username"}}
	}
	if runtime.GOOS != "linux" {
		return execResult{"done", map[string]any{"note": "recorded on a non-linux host, no account change", "user": user}}
	}
	if !enforce {
		return execResult{"done", map[string]any{"note": "dry-run: start the agent with -enforce to apply", "wouldRun": []string{"usermod", "-L", user}}}
	}
	out, err := exec.Command("usermod", "-L", user).CombinedOutput()
	if err != nil {
		return execResult{"failed", map[string]any{"error": err.Error(), "output": string(out)}}
	}
	return execResult{"done", map[string]any{"user": user, "output": string(out)}}
}

func runCollector() execResult {
	host, _ := os.Hostname()
	return execResult{"done", map[string]any{"hostname": host, "os": runtime.GOOS, "arch": runtime.GOARCH}}
}

// runProbe fires a RedTeam technique's benign attack-signature requests at the
// agent's own resource so a simulation reaches a target the platform cannot (one
// bound to localhost for isolation). It is hard-restricted to a loopback or private
// target, so the platform can never turn an agent into a probe against an arbitrary
// host on the internet. The requests are plain GETs whose query string carries the
// signature the detection rules match in the access log; nothing is exploited.
func runProbe(rawParams json.RawMessage) execResult {
	var p struct {
		Target string   `json:"target"`
		Paths  []string `json:"paths"`
	}
	_ = json.Unmarshal(rawParams, &p)
	if p.Target == "" {
		p.Target = "http://127.0.0.1"
	}
	base, err := url.Parse(p.Target)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return execResult{"failed", map[string]any{"error": "probe target must be an http(s) URL"}}
	}
	if !isLocalProbeHost(base.Hostname()) {
		return execResult{"failed", map[string]any{"error": "probe target must be a loopback or private address"}}
	}
	if len(p.Paths) == 0 {
		return execResult{"failed", map[string]any{"error": "no probe paths given"}}
	}
	if len(p.Paths) > 20 {
		p.Paths = p.Paths[:20]
	}
	client := &http.Client{Timeout: 6 * time.Second}
	fired := 0
	for _, path := range p.Paths {
		target := strings.TrimRight(base.String(), "/") + "/" + strings.TrimPrefix(path, "/")
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "tjakra-ap-redteam/1.0 (agent probe)")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			fired++
		}
	}
	return execResult{"done", map[string]any{"fired": fired, "target": base.String()}}
}

// runCommand is the remote console: it runs an operator-typed command through the
// OS shell and returns its combined output. It is the one action outside the
// allowlisted, deterministic model, so it is inert unless the agent was started with
// -console. The platform still signs it and admin-gates it; -console is the local
// operator's own consent that this host may be driven interactively. A non-zero exit
// is a normal result (status done, with exitCode), not a dispatch failure; only a
// command that could not start or timed out is failed. Output is capped and the run
// is bounded by a timeout so a runaway command cannot pin the agent.
func runCommand(rawParams json.RawMessage, console bool) execResult {
	if !console {
		return execResult{"failed", map[string]any{"error": "remote console is disabled on this agent (start it with -console to enable)"}}
	}
	var p struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(rawParams, &p)
	cmdStr := strings.TrimSpace(p.Command)
	if cmdStr == "" {
		return execResult{"failed", map[string]any{"error": "empty command"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ec *exec.Cmd
	if runtime.GOOS == "windows" {
		ec = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
	} else {
		ec = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	out, err := ec.CombinedOutput()
	const outCap = 64 * 1024
	truncated := false
	if len(out) > outCap {
		out = out[:outCap]
		truncated = true
	}
	result := map[string]any{"command": cmdStr, "output": string(out), "truncated": truncated}
	if ctx.Err() == context.DeadlineExceeded {
		result["error"] = "command timed out after 30s"
		return execResult{"failed", result}
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			result["exitCode"] = ee.ExitCode()
			return execResult{"done", result} // ran, exited non-zero: a normal shell result
		}
		result["error"] = err.Error()
		return execResult{"failed", result} // could not start
	}
	result["exitCode"] = 0
	return execResult{"done", result}
}

// isLocalProbeHost admits only a loopback or RFC1918 private target, so a probe can
// never leave the host's own network. A bare "localhost" is allowed; any other
// hostname is refused rather than resolved, because a name could point anywhere.
func isLocalProbeHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
