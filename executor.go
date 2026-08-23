package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
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

func executeCommand(cmd command, enforce bool) execResult {
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
