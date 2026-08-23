# tjakra-ap-agent

The customer-installed patrol agent for the tjakra-ap platform (Defence and
Response, Model B). It enrolls with a one-time token from the platform, ships logs
up so the platform can detect attacks, and runs allowlisted, platform-signed
commands down (block an IP, revert a block, isolate a host, disable a user, run a
collector). It is a single static Go binary with no dependencies beyond the
standard library.

## Security model

This is effectively an EDR/C2 agent, so the trust rules are strict:

- The enrollment token is one-time and is not the operating credential. On enroll
  the platform returns a separate scoped agent key and the platform signing public
  key, which the agent pins.
- Every command is verified against the pinned platform key over a frozen signing
  payload that binds the command id, action, canonical params, a nonce, and an
  expiry. A stolen agent key or a tampered command cannot make the agent act.
- The agent runs only the fixed allowlist of named actions, never a free-form
  shell command. Targets are validated to a strict character set and passed as
  argv, so a crafted target cannot inject.
- Destructive actions are a dry-run unless the agent is started with `-enforce`,
  so a test run never touches a live firewall or account by accident.
- A platform-side per-agent and global kill switch stop the command channel; a
  killed or revoked agent is served nothing.

## Usage

Build:

```bash
go build -o tjakra-ap-agent .
```

Enroll (the token comes from the platform console, NSOC / Patrol, "Enroll agent"):

```bash
./tjakra-ap-agent enroll -server https://pentest-api.tjakrabirawa.id -token <enroll-token>
```

Run (polls for commands; optionally tails a log file to ship):

```bash
./tjakra-ap-agent run -log-file /var/log/app/access.log -enforce -poll 5s
```

Flags: `-config` (config path, default `tjakra-ap-agent.json`), `-server`,
`-token` (enroll only), `-log-file` (tail and ship), `-enforce` (apply destructive
actions instead of dry-run), `-poll` (command poll interval), `-insecure` (skip TLS
verification, dev only).

## What it is not, yet

- Cert-pinned mTLS on the transport is a Phase 2 hardening; today it authenticates
  with the scoped bearer key over TLS.
- Log rotation handling in the tailer is minimal.
- `isolate_host` is recorded but not enforced in this build.
