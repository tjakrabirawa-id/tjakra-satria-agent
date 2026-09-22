package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The wire protocol between the platform and the agent. The signing payload format
// is frozen and must match the platform's internal/agentcmd.SigningPayload byte for
// byte: the agent verifies every command against the platform public key it pinned
// at enrollment, so a stolen agent key or a tampered command cannot make the agent
// act.

// allowedActions is the agent's fixed action table. A command naming anything else
// is refused even if its signature is valid.
var allowedActions = map[string]bool{
	"block_ip":      true,
	"revert_block":  true,
	"isolate_host":  true,
	"disable_user":  true,
	"run_collector": true,
	"run_probe":     true,
	// run_command is the admin remote console. It is allowlisted so a signed command
	// reaches the executor, but the executor runs it only when the agent was started
	// with -console (off by default); otherwise it returns a disabled result.
	"run_command": true,
	// read_logs is the per-agent log chat (plan F4): a read-only, allowlisted-path,
	// bounded log read. It is a sibling of run_command with no shell path, so a chat
	// can never reach the console. It runs unconditionally (not console-gated): reading
	// an allowlisted log is the whole point, and it can never mutate or execute.
	"read_logs": true,
}

type command struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agentId"`
	Action    string          `json:"action"`
	Params    json.RawMessage `json:"params"`
	Status    string          `json:"status"`
	Signature string          `json:"signature"`
	Nonce     string          `json:"nonce"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

// Command signing prefix. The platform signs with this prefix and the agent
// verifies against it using the pinned platform key. The pre-rebrand dual-verify
// window is closed: every backend now signs this prefix, so the legacy prefix is
// no longer accepted.
const signingPrefix = "tjakra-satria-agent-cmd-v1\n"

// signingPayload rebuilds the exact bytes the platform signed. Field order and the
// separator are frozen. params must be the raw JSON bytes as received (the platform
// signed the canonical stored form, which is what the agent gets on the wire).
func signingPayload(prefix, id, agentID, action string, params []byte, nonce string, expiresUnix int64) []byte {
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(id)
	b.WriteByte('|')
	b.WriteString(agentID)
	b.WriteByte('|')
	b.WriteString(action)
	b.WriteByte('|')
	b.Write(params)
	b.WriteByte('|')
	b.WriteString(nonce)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(expiresUnix, 10))
	return []byte(b.String())
}

func verifySignature(pubB64 string, payload []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}

// verifyCommand checks a command is well-formed, unexpired, allowlisted, and
// correctly signed by the pinned platform key. It returns a reason on refusal so
// the agent can report why it declined rather than silently dropping a command.
func verifyCommand(cmd command, platformPub string) (ok bool, reason string) {
	if platformPub == "" {
		return false, "no pinned platform key"
	}
	if !allowedActions[cmd.Action] {
		return false, "action not allowlisted: " + cmd.Action
	}
	if cmd.Signature == "" {
		return false, "unsigned command"
	}
	if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
		return false, "command expired"
	}
	// Verify against the single current prefix with the pinned key; the payload
	// cannot be forged without that key.
	payload := signingPayload(signingPrefix, cmd.ID, cmd.AgentID, cmd.Action, cmd.Params, cmd.Nonce, cmd.ExpiresAt.Unix())
	if verifySignature(platformPub, payload, cmd.Signature) {
		return true, ""
	}
	return false, "signature does not verify against the pinned platform key"
}
