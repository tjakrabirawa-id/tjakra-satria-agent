package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// The signing prefixes are wire format shared with the platform. Pinning the
// literals here means a rename on either side shows up as a failing test rather
// than as commands silently failing to verify on customer machines.
func TestSigningPrefixLiterals(t *testing.T) {
	if signingPrefix != "tjakra-satria-agent-cmd-v1\n" {
		t.Fatalf("current signing prefix changed: %q", signingPrefix)
	}
}

func signedCommand(t *testing.T, priv ed25519.PrivateKey, prefix string) command {
	t.Helper()
	cmd := command{
		ID:        "cmd_1",
		AgentID:   "agt_1",
		Action:    "block_ip",
		Params:    json.RawMessage(`{"ip":"198.51.100.7"}`),
		Nonce:     "n1",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	payload := signingPayload(prefix, cmd.ID, cmd.AgentID, cmd.Action, cmd.Params, cmd.Nonce, cmd.ExpiresAt.Unix())
	cmd.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return cmd
}

// The dual-verify window is closed: a command signed with the current prefix is
// accepted, and one signed with the pre-rebrand legacy prefix is now rejected.
func TestVerifyCommandAcceptsCurrentRejectsLegacy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	cmd := signedCommand(t, priv, signingPrefix)
	if ok, reason := verifyCommand(cmd, pubB64); !ok {
		t.Fatalf("current prefix rejected: %s", reason)
	}

	legacy := signedCommand(t, priv, "tjakra-ap-agent-cmd-v1\n")
	if ok, _ := verifyCommand(legacy, pubB64); ok {
		t.Fatal("a legacy-prefix command still verified after the dual-verify window closed")
	}
}

// Accepting two prefixes must not weaken the check: a signature from a
// different key, or over different bytes, still has to fail closed.
func TestVerifyCommandStillRejectsForgeries(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	otherB64 := base64.StdEncoding.EncodeToString(otherPub)

	cmd := signedCommand(t, priv, signingPrefix)
	if ok, _ := verifyCommand(cmd, otherB64); ok {
		t.Fatal("a command verified against the wrong pinned key")
	}

	tampered := signedCommand(t, priv, signingPrefix)
	tampered.Params = json.RawMessage(`{"ip":"10.0.0.1"}`)
	if ok, _ := verifyCommand(tampered, pubB64); ok {
		t.Fatal("a tampered command verified")
	}

	unsigned := signedCommand(t, priv, signingPrefix)
	unsigned.Signature = ""
	if ok, _ := verifyCommand(unsigned, pubB64); ok {
		t.Fatal("an unsigned command verified")
	}
}
