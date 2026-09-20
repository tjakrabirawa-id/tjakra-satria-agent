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
	if legacySigningPrefix != "tjakra-ap-agent-cmd-v1\n" {
		t.Fatalf("legacy signing prefix changed: %q", legacySigningPrefix)
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

// The whole point of the dual-verify window: a platform still signing the
// pre-rebrand prefix and one already signing the new prefix must both be
// accepted by this build, or the rename bricks every deployed agent.
func TestVerifyCommandAcceptsBothPrefixes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	for name, prefix := range map[string]string{
		"current": signingPrefix,
		"legacy":  legacySigningPrefix,
	} {
		cmd := signedCommand(t, priv, prefix)
		if ok, reason := verifyCommand(cmd, pubB64); !ok {
			t.Fatalf("%s prefix rejected: %s", name, reason)
		}
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
