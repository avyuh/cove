# cove BUILD STATUS — shared team tracker

Source of truth for the build. Spec: `docs/SPEC.md` (implement from §11–§16;
§9 is the milestone plan, §15 the test plan). Update the Status column and
append to the Progress log as milestones complete. Statuses: TODO → IN PROGRESS
→ IN REVIEW → DONE (or BLOCKED — see Gates).

## Environment prerequisites

- **Go toolchain NOT installed** (`go` missing). First action of M0: install Go
  ≥1.22 (e.g. `sudo apt install golang-go` or official tarball) and verify
  `go version`. `go.mod`: `module cove`.
- **Sanctioned deps (exactly two beyond stdlib + x/sys):**
  `github.com/BurntSushi/toml` and `golang.org/x/net/http2` (§16 guardrails).
  Nothing else. `golang.org/x/sys/unix` allowed for syscalls.
- **`cove setup` needs one-time `sudo`** — Ubuntu 24.04 AppArmor userns profile
  (`/etc/apparmor.d/cove`, §7.2–7.3). Root step is ONLY the AppArmor
  write+reload (`cove __apparmor`); everything else runs as the user (B5).
- **M4 make-or-break test needs a valid Claude OAuth token.** It IS on this box
  at `~/.claude/.credentials.json` (verified present) — M4 is testable locally.
- Target platform: this box (Ubuntu 24.04, KVM guest, no `/dev/kvm`).

## Milestones

| M | Goal (one line) | Spec sections | Acceptance test | Status |
|---|---|---|---|---|
| M0 | Single binary skeleton + argv role dispatch (launcher/proxyd/__init/__apparmor/setup/log) | §2.2, §9/M0, §11.1, §11.2 | `cove --help`/`--version` work; dispatch routes each verb correctly; `go build ./cmd/cove` clean | DONE |
| M1 | `cove setup`: AppArmor profile, userns probe, CA gen, seed config, dirs (split-privilege) | §4.7, §5.5, §7.2–7.5, §9/M1 | `sudo cove setup` → probe `unshare(CLONE_NEWUSER)` succeeds where it failed before; `ca.pem` 0644 / `ca-key.pem` 0600 user-owned; re-run reports "no changes" (idempotent) | TODO |
| M2 | The box, no proxy: namespaces, full mount plan, pivot_root, cap-drop, lo-up, pty, exec shell | §3.1–3.6, §9/M2, §13.1–13.3 | `cove -- sh -c 'cat ~/.ssh/id_rsa'` → absent; `ls /work` shows project; `curl https://1.1.1.1` → ENETUNREACH; interactive `cove -- bash` with TTY; `/proc` shows only in-box PIDs, PID 1 = cove-init (e2e §15.2 steps 1–3, minus proxy deny) | TODO |
| M3 | Minimal allow-only proxy (Unix accept, CONNECT parse, allowlist, opaque tunnel, host DNS, audit) — **first milestone that beats bare YOLO** | §4.1–4.4, §4.6, §4.9, §9/M3 | `cove -- codex exec 'say ok'` completes via allow hosts (needs `cred_mount ["~/.codex"]`); CONNECT to non-allowed host → 403 + audit deny record; secrets still absent; raw egress still fails | TODO |
| M4 | **h2 MITM inject (make-or-break, gates the whole inject feature)**: leaf minting, client-facing h2 TLS termination, ReverseProxy strip+inject, FlushInterval=-1, upstream h2 | §4.5, §4.7, §4.8, §9/M4, §14 | `cove -- claude -p "reply with exactly: COVE-OK"` → real streamed 200 through MITM+inject over h2, token host-side only, box holds dummy `ANTHROPIC_API_KEY` (dummy `x-api-key` stripped); audit shows `POST /v1/messages` status 200; if h2 misbehaves, prove `alpn="http/1.1"` downgrade (e2e step 4) | TODO |
| M5 | Interactive polish: signal forwarding, SIGWINCH resize via control pipe, termios save/restore, exit-code propagation, cap-drop verified | §3.4–3.5, §6.1, §9/M5, §13.2 steps 12a–13 | `cove -- claude` TUI resizes on window change; Ctrl-C hits the agent not the launcher; exit codes match bare runs (incl. status-pipe/75 disambiguation); agent has empty cap bounding set + no_new_privs | TODO |
| M6 | Full proxy/config: base_url rewrites, kimi plain-HTTP loopback, cred_mount/env_passthrough, all seed stanzas, Validate() | §3.7b, §3.8, §5 (all), §9/M6, §12.1 | Kimi flow works via dynamic-port `KIMI_BASE_URL` loopback with injected key; each seed inject stanza round-trips against a stub upstream; config with host in both allow+inject fails to load; embedded seed passes `Validate()` (§15.1 B1 test) | TODO |
| M7 | Lifecycle/robustness: auto-spawn + PING/PONG, flock singleton, SIGHUP reload, per-session sockets/REGISTER, crash sweep, fail-closed, audit rotation | §3.9, §4.1, §4.10, §9/M7 | Kill proxy mid-session → egress fails closed; next run auto-spawns fresh proxy; 20 concurrent sessions all proxy correctly (20/20 200s); no leaked `/tmp/cove-root.*` or `sessions/*.sock` after `kill -9` of a launcher | TODO |
| M8 | `cove log` verb + docs/positioning copy | §6.4, §8.4, §9/M8 | `cove log --follow --deny-only` shows denials live; filters (`--session`, `--host`) work; NO string anywhere says "secure sandbox" | TODO |

Ship gate (§9): M3 solid + M4 proven → shippable; M5–M8 harden and complete.
Unit tests per §15.1 land with their milestone (config/allowlist → M6 or
earlier, secret/ca/audit → M3/M4, inject httptest C1 flow + bufConn → M4).
Full acceptance = `scripts/e2e.sh` (§15.2).

## Gates requiring main/human

- **Final `git push`** — main handles (commits per-milestone are main's call
  too; never auto-commit).
- **Any milestone still failing after ~3 codex attempts** → mark BLOCKED here,
  escalate to main with the failure evidence; do not weaken tests to pass.
- `sudo` steps (Go install if via apt, `cove setup` AppArmor grant) — main/human
  runs or approves them.

## Progress log

(append one line per event: date — M# — status change — note)

- 2026-07-05 — tracker created; all milestones TODO. Env verified: `go` missing,
  Claude OAuth creds present at `~/.claude/.credentials.json`.
- 2026-07-05 — ENV — DONE — installed official Go tarball `go1.26.4.linux-arm64`
  to `/usr/local/go`; verified `/usr/local/go/bin/go version` reports
  `go version go1.26.4 linux/arm64`.
- 2026-07-05 — M0 — DONE — `go build ./...`, `go vet ./...`, and
  `go test ./...` passed; installed the verification binary to
  `/usr/local/bin/cove`; verified `cove --version`, `cove --help`,
  `cove proxyd --help`, launcher `--dry-run`, and internal `__init` probe
  dispatch.
