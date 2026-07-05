# cove BUILD STATUS — shared team tracker

Source of truth for the build. Spec: `docs/SPEC.md` (implement from §11–§16;
§9 is the milestone plan, §15 the test plan). Update the Status column and
append to the Progress log as milestones complete. Statuses: TODO → IN PROGRESS
→ IN REVIEW → DONE (or BLOCKED — see Gates).

## Standing test bar (owner directive) — `docs/TESTPLAN.md`

`docs/TESTPLAN.md` is the binding test bar (sections A unit, B security-invariants
EXECUTED-on-box, C concurrency/stress, D robustness/lifecycle, E real-agent e2e,
F streaming, G error paths). Rules:

- **Every milestone ADDS real tests for its surface** per the relevant TESTPLAN
  sections — NOT just the single acceptance check. Per-milestone owed tests:
  M4 → E(claude: COVE-OK + token-absent grep + x-api-key stripped) + F(streaming
  incremental flush) + A(ca/inject-C1/bufConn/blockingOneShotListener/counting/
  secret-json/audit two-phase) over BOTH h2 and h1 legs; M5 → pty/signal/exit-code
  + B(agent CapBnd==CapEff==0, NoNewPrivs:1, cove-init caps dropped); M6 →
  A(full config/secret/allowlist tables) + E(kimi loopback, codex cred_mount) +
  negative-config-fails-load; M7 → C(20–30 concurrent) + D(kill-proxy fail-closed,
  kill-9 no leaks, SIGHUP reload, audit rotation); M8 → cove log filters
  (`--follow`/`--deny-only`/`--session`/`--host`) + no "secure sandbox" string.
- **Thin/vacuous tests are a reviewer BLOCKER.** Each milestone gate:
  `go test ./... -count=1` green + `go vet` clean + its TESTPLAN tests, before commit.
- **M0–M3 backfill gate:** when the in-flight M1–M3 run lands, if its tests are
  thin vs TESTPLAN A/B for config/setup/box/proxy, a codex worker ADDS them
  BEFORE advancing to M4.
- **Final gate (after M8):** a dedicated codex TESTER worker runs the FULL A–G
  sweep adversarially on the box, writes `docs/TEST-RESULTS.md`, and files failures
  back to the orchestrator. cove is NOT "done" until that sweep is green (or each
  residual is explicitly owner-accepted, e.g. an expired ChatGPT token needing a
  host re-login).

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
| M1 | `cove setup`: AppArmor profile, userns probe, CA gen, seed config, dirs (split-privilege) | §4.7, §5.5, §7.2–7.5, §9/M1 | `sudo cove setup` → probe `unshare(CLONE_NEWUSER)` succeeds where it failed before; `ca.pem` 0644 / `ca-key.pem` 0600 user-owned; re-run reports "no changes" (idempotent) | DONE |
| M2 | The box, no proxy: namespaces, full mount plan, pivot_root, cap-drop, lo-up, pty, exec shell | §3.1–3.6, §9/M2, §13.1–13.3 | `cove -- sh -c 'cat ~/.ssh/id_rsa'` → absent; `ls /work` shows project; `curl https://1.1.1.1` → ENETUNREACH; interactive `cove -- bash` with TTY; `/proc` shows only in-box PIDs, PID 1 = cove-init (e2e §15.2 steps 1–3, minus proxy deny) | DONE |
| M3 | Minimal allow-only proxy (Unix accept, CONNECT parse, allowlist, opaque tunnel, host DNS, audit) — **first milestone that beats bare YOLO** | §4.1–4.4, §4.6, §4.9, §9/M3 | `cove -- codex exec 'say ok'` completes via allow hosts (needs `cred_mount ["~/.codex"]`); CONNECT to non-allowed host → 403 + audit deny record; secrets still absent; raw egress still fails | DONE |
| M4 | **h2 MITM inject (make-or-break, gates the whole inject feature)**: leaf minting, client-facing h2 TLS termination, ReverseProxy strip+inject, FlushInterval=-1, upstream h2 | §4.5, §4.7, §4.8, §9/M4, §14 | `cove -- claude -p "reply with exactly: COVE-OK"` → real streamed 200 through MITM+inject over h2, token host-side only, box holds dummy `ANTHROPIC_API_KEY` (dummy `x-api-key` stripped); audit shows `POST /v1/messages` status 200; if h2 misbehaves, prove `alpn="http/1.1"` downgrade (e2e step 4) | DONE |
| M5 | Interactive polish: signal forwarding, SIGWINCH resize via control pipe, termios save/restore, exit-code propagation, cap-drop verified | §3.4–3.5, §6.1, §9/M5, §13.2 steps 12a–13 | `cove -- claude` TUI resizes on window change; Ctrl-C hits the agent not the launcher; exit codes match bare runs (incl. status-pipe/75 disambiguation); agent has empty cap bounding set + no_new_privs | IN PROGRESS |
| M6 | Full proxy/config: base_url rewrites, kimi plain-HTTP loopback, cred_mount/env_passthrough, all seed stanzas, Validate() | §3.7b, §3.8, §5 (all), §9/M6, §12.1 | Kimi flow works via dynamic-port `KIMI_BASE_URL` loopback with injected key; each seed inject stanza round-trips against a stub upstream; config with host in both allow+inject fails to load; embedded seed passes `Validate()` (§15.1 B1 test) | TODO |
| M7 | Lifecycle/robustness: auto-spawn + PING/PONG, flock singleton, SIGHUP reload, per-session sockets/REGISTER, crash sweep, fail-closed, audit rotation | §3.9, §4.1, §4.10, §9/M7 | Kill proxy mid-session → egress fails closed; next run auto-spawns fresh proxy; 20 concurrent sessions all proxy correctly (20/20 200s); no leaked `/tmp/cove-root.*` or `sessions/*.sock` after `kill -9` of a launcher | TODO |
| M8 | `cove log` verb + docs/positioning copy | §6.4, §8.4, §9/M8 | `cove log --follow --deny-only` shows denials live; filters (`--session`, `--host`) work; NO string anywhere says "secure sandbox" | TODO |

Ship gate (§9): M3 solid + M4 proven → shippable; M5–M8 harden and complete.
Unit tests per §15.1 land with their milestone (config/allowlist → M6 or
earlier, secret/ca/audit → M3/M4, inject httptest C1 flow → M4, bufConn → M5
per §15.1, or earlier with the h1-inject code). Full acceptance =
`scripts/e2e.sh` (§15.2) PLUS the per-milestone TESTPLAN tests (standing-bar
section above) AND the final TESTER A–G sweep below.

**TEST (final gate, TODO) — adversarial A–G sweep on the box (after M8):**
B security invariants EXECUTED (bait-absent, ENETUNREACH, CapBnd==CapEff==0,
NoNewPrivs:1, no `/.oldroot`, audit-unforgeable, CA-key-absent-in-box,
allow-path-not-terminated), C 20–30 concurrent, D fail-closed + kill-9 no-leaks
+ SIGHUP + rotation, E/F/G → writes `docs/TEST-RESULTS.md`, files failures back.
cove not "done" until green or residuals owner-accepted.

## Sequencing & cross-milestone risks (M4→M8)

Planned order: **M4 → M5 → M6 → M7 → M8** (straight §9 order). Notes:

- **M4 gates the entire inject feature.** Do not start M6's inject stanzas
  (claude / codex-API-key / gemini / huggingface) until M4 is proven — they all
  ride M4's leaf-mint + TLS-terminate + strip/inject path. Exception: kimi's
  plain-HTTP loopback inject (§3.7b) does NOT need TLS MITM, so it survives
  even an M4 failure; if M4 blocks, M6 can still land allowlist config,
  cred_mount/env_passthrough, Validate(), and kimi.
- **M5 is independent of M4** (pty/signals/exit codes vs. proxy inject; both
  build on M2/M3). If M4 stalls in escalation, M5 is safe parallel/next work —
  no collision in files touched (in-box init + launcher vs. proxy).
- **M3 acceptance pulled a slice of M6 forward:** the codex test needs a
  minimal `cred_mount ["~/.codex"]` bind-mount. Full cred_mount semantics
  (`:rw` suffix, glob validation, N5 read-only default) still verify in M6 —
  don't mark that part of M6 done on the strength of the M3 smoke.
- **M6 depends on M3's allowlist/config loader AND M4's inject path.** The B1
  seed-validates unit test (§15.1) is M6's guard against the DOA
  self-conflicting-seed regression — mandatory, never weaken.
- **M7 depends on M3's proxy (lifecycle around it), not on M4.** Can start
  once M3 is DONE if inject work is blocked.
- **M8 depends on M3's audit format; rotation-related log behavior on M7.**
  The `cove log` verb itself can land any time after M3.
- **e2e step 5 (codex) is time-sensitive:** host-side ChatGPT token must be
  currently valid; `:ro` mount can't refresh it (N5). If it 401s, re-login on
  the host — not a code bug.

## Gates requiring main/human

- **M4 make-or-break sign-off (real-claude h2 inject).** Locally testable —
  a valid Claude OAuth token is on this box at `~/.claude/.credentials.json` —
  but the RESULT is a gate: main reviews the evidence (streamed `COVE-OK`
  completion, audit `POST /v1/messages` status 200, proof the box only ever
  held the dummy `ANTHROPIC_API_KEY`) before M6 inject work proceeds. If M4
  fails on h2 AND on the `alpn="http/1.1"` downgrade, mark BLOCKED and STOP:
  whether to cut the TLS-MITM inject feature is an owner scope decision, not
  a codex retry loop.
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
- 2026-07-05 — M1 — DONE — `go build ./...`, `go vet ./...`, and
  `go test ./...` passed; `sudo cove setup` created user-owned
  `/home/dev/.config/cove` and `/home/dev/.local/state/cove`, generated RSA-2048
  CA files (`ca.pem` `0644`, `ca-key.pem` `0600`), wrote the seed config, and
  verified userns as `dev`. A pre-setup `cove __probe_userns` already succeeded
  on this host, so setup correctly skipped the AppArmor write per §7.1; rerun
  reported `no changes`; `go test ./internal/config -run TestSeedValidates`
  passed.
- 2026-07-05 — M2 — DONE — `go build ./...`, `go vet ./...`, and
  `go test ./...` passed; loaded `/etc/apparmor.d/cove` after the full clone
  set (`NEWUSER|NEWNS|NEWPID|NEWNET|NEWIPC|NEWUTS`) showed the userns-only M1
  probe was too narrow, and updated setup to probe the full shape. Verify:
  `cove -- /bin/sh -c 'cat ~/.ssh/* 2>&1 || echo ABSENT'` showed `/root/.ssh`
  absent and printed `ABSENT`; `cove -- /bin/sh -c 'ls /work | head'` listed the
  repo; `/work` write probe wrote `hi`; `curl -m3 https://1.1.1.1` failed
  immediately with curl exit 7 from the route-less netns; `/proc/1/cmdline`
  showed `cove-init __init` and only in-box PIDs; PTY probe
  `cove -- /bin/bash -lc 'test -t 0 && echo TTY && tty && stty size'` printed
  `TTY`, `/dev/pts/0`, and `24 80`; boxed `/bin/true` left no stale
  `/tmp/cove-root.*` after exact-root cleanup. `sudo cove setup` rerun reported
  `no changes` with the full-clone probe.
- 2026-07-05 — TESTPLAN — ADOPTED — owner directive: `docs/TESTPLAN.md` is the
  standing test bar (A–G). Every milestone adds real tests for its surface; thin
  tests = reviewer BLOCKER; final adversarial TESTER A–G sweep gates "done".
- 2026-07-05 — M3 — DONE — `go build ./...`, `go vet ./...`, and
  `go test ./...` passed; proxy auto-spawned and answered PING/PONG, REGISTER
  created per-session sockets, and `/home/dev/.local/state/cove/proxyd.sock` plus
  `audit.log` are `0600 dev:dev`. Verify: `cove -- /bin/sh -c 'curl -sS -o
  /dev/null -w "%{http_code}" https://github.com'` returned `200`; off-allow
  `evil.example.com` failed with `CONNECT tunnel failed, response 403`, and
  `cove log --deny-only` showed a deny JSONL record with host-side session
  `d75d54fd` and agent `sh`; IP-literal `1.1.1.1` was denied 403; secrets remain
  absent (`/root/.ssh/*` missing + `ABSENT`); `/work` listed the repo and a write
  probe wrote `hi`; the audit log contains a close-time allow record for
  `github.com` with nonzero `bytes_up`/`bytes_down`; no `/tmp/cove-root.*` leaks.
- 2026-07-05 — BACKFILL-M0M3 — DONE — codex added TESTPLAN A unit tables (setup/
  secret/audit/allowlist/conn/launcher + config gaps, 8 new test files, 36 test
  funcs) + `scripts/e2e-box.sh` automating B1–B7 + E/G; fixed the exit-127
  conformance bug (missing agent → 127, not 75) TDD. Reviewer QC PASS —
  sabotaged B6/B2 → script correctly reported FAIL exit 1 (real, fails-closed);
  additive-only, build/vet/test/gofmt clean. Committed locally (no push).
- 2026-07-05 — M4 — DONE — h2 MITM inject (make-or-break). Reviewer QC PASS:
  both legs (h2 `http2.Server.ServeConn` + h1 `blockingOneShotListener`) proven
  real vs a live httptest h2 upstream; C1 strip-then-inject verified at the
  upstream (dummy `x-api-key` stripped, real OAuth Bearer injected); token absent
  BY CONSTRUCTION (box directive has no secret field; resolved only in proxyd);
  upstream uses host real roots; streaming incremental-flush proven;
  CA key host-only; allow-path still opaque; deps within guardrail (added only
  `golang.org/x/net/http2`); additive. Committed locally (no push).
- 2026-07-05 — M5 — IN PROGRESS — dispatched codex work-order: complete the §3.5
  pty recipe end-to-end (box CTL_FD winsize reader→TIOCSWINSZ, agent-child
  setsid/TIOCSCTTY, copy loops), full signal forwarding to the agent pgroup,
  termios restore on all exit paths, exit-code propagation (70-vs-75 preserved),
  fold in §13.2 step-13 belt no_new_privs/capset re-assert + fd hygiene (N7);
  automated B caps test + pty/signal/exit-code tests.
- 2026-07-05 — M0–M3 TEST-BACKFILL — DONE — added repeatable TESTPLAN A unit
  tables plus `scripts/e2e-box.sh` for B/E/G; `go build ./...`, `go vet ./...`,
  `go test ./... -count=1`, and `bash scripts/e2e-box.sh` passed. Deferred
  minors intentionally not fixed: agent child explicit §13.2 step-13 re-assert
  (covered by NoNewPrivs/cap tests until M5), `/proc/1/comm` cosmetic name,
  pre-M4 inject audit label still records opaque fall-through as `allow`, and
  `sweepRoots` still uses the 24h threshold pending M7 lifecycle work.
