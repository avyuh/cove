# cove — heavy test plan (the bar every milestone must clear)

Testing is not an afterthought: cove's security guarantees are only real if a test
**executes** and observes them. Every milestone MUST add real tests for its
surface (not just the one acceptance check), and a final codex TESTER sweep runs
the whole thing adversarially. "Green build" is not "tested." Security invariants
must be **exercised on a real box**, not asserted in prose.

## A. UNIT (go test, table-driven, meaningful coverage)
- config: seed Validate() passes (B1); bare `*` rejected; host in both allow+inject rejected; wildcard exact/non-match (`objects.githubusercontent.com` ✓, `githubusercontent.com` ✗, `a.b.…` ✗); IP-literal handling; port rules; `header_template` missing `{secret}` rejected; missing-secret → inert-inject (tunnel, warn).
- runtime path: fake nvm tree (`bin/node`, `bin/claude` symlink to `lib/node_modules/.../cli.js`) resolves to the node version root; HOME-or-above widening aborts with `runtime_mount`/system-install guidance and never returns HOME; `options.runtime_mount` rejects `*`, bare `~`, `/`, `/home`, `/root`, `/etc`, HOME, and HOME ancestors.
- secret: `file:` read + mtime-cache invalidation; `json:<path>#<dotted>` extraction from a fixture credentials.json; `env:` capture; missing file → warn+inert; never logs secret values.
- allowlist matcher: every §4.3 case.
- CA: leaf SAN matches host; leaf verifies against the CA pool; per-host cache returns same cert; RSA-2048; CA key never serialized into box artifacts.
- audit: record marshals to expected JSON; size rotation; two-phase emit — `allow`/`inject` bytes+dur finalized at close (non-zero), `deny` immediate.
- bufConn drains buffered bytes before raw; blockingOneShotListener returns conn once then blocks until Close then EOF (no double-close panic, no goroutine leak); countingReadCloser counts + single Close.
- exit-code mapping (§16.1): 64/66/69/70/75/77/78/127/128+sig.

## B. SECURITY INVARIANTS (must EXECUTE on the box and observe the result)
- Secret ABSENCE: plant bait files in ~/.ssh/, ~/.aws/credentials, ~/.claude/, ~/.config/gh/, a fake browser profile; in the box each is **absent** (`cat` → no such file). Deny-by-default (not a denylist).
- Egress fail-closed: raw `connect()` to a literal IP → ENETUNREACH; a DNS query → fails (no resolver in box); off-allowlist CONNECT → 403; IP-literal CONNECT → denied; a process that ignores HTTPS_PROXY cannot reach the net.
- Privilege: read the agent's `/proc/self/status` — `CapBnd`/`CapEff` == 0 (empty), `NoNewPrivs: 1`. cove-init likewise dropped its caps (step 12a).
- pivot_root, no chroot: no `/.oldroot` remains; the host root is NOT mounted anywhere in the box; a chroot-escape attempt (chdir("..") loop / second chroot) reaches nothing host-side.
- Audit unforgeable: an in-box process connecting directly to /proxy/proxy.sock cannot spoof another session's identity (identity is host-side, per-session socket); a garbage/absent preamble does not crash the proxy.
- CA key: `grep -r` the box mount for the CA private key material → absent; only the CA public cert is present.
- allow path is opaque: for an `allow` host, the client sees the REAL upstream certificate (cove does NOT TLS-terminate). Only `inject` hosts get the cove leaf.
- Runtime mount containment: after a runtime mount is active, re-run the bait
  absence checks; assert `/home/<user>` contains only the mounted toolchain path
  component and not HOME dotfiles; assert raw egress still fails
  `ENETUNREACH`, off-allowlist still returns 403, allow-path cert issuer is the
  real upstream issuer, and writes into the runtime mount fail with `EROFS`.

## C. CONCURRENCY / STRESS
- 20–30 concurrent `cove -- …` sessions all succeed (spec M7 target: 20/20 200s); verify per-session sockets isolate correctly.
- Many parallel requests through one session's proxy (socat/shim + proxy hold up).
- No fd/goroutine/socket leak under load.

## D. ROBUSTNESS / LIFECYCLE
- Kill proxyd mid-session → box egress fails **closed** (not open); next launch auto-spawns a fresh proxy (PING/PONG); flock singleton holds.
- `kill -9` a launcher → no leaked `/tmp/cove-root.*` mountpoints, no leaked `sessions/*.sock`; the sweep reclaims them.
- SIGHUP config reload; audit log rotates at size; stale-socket detection unlinks + respawns.
- Token expiry: expired host token → upstream 401 → clear "re-login on host" hint; the box never held the token.

## E. REAL-AGENT E2E (the point of the tool)
- claude (M4 + runtime path): `cove -- claude -p "reply with exactly: COVE-OK"` resolves from the host nvm/volta/asdf install via the read-only runtime mount, returns `COVE-OK`, and `cove log --host api.anthropic.com` shows `POST /v1/messages status 200`; **grep the box for the token prefix → absent** (key never in box); confirm x-api-key dummy was stripped.
- codex: resolves from the host runtime path; with `cred_mount ["~/.codex:rw"]`, runs contained through allow hosts (chatgpt.com/auth.openai.com); token in box but egress-bounded (can't exfil to an off-allowlist host). The writable mount is required by current Codex CLI init and carries the §5.7 concurrency caveat. If the ChatGPT token is expired, record that as an ops residual, not a runtime-path code failure.
- kimi: runs via `KIMI_BASE_URL` plain-HTTP loopback with injected key (no MITM).
- git/gh: clone/push work through the allow hosts + registries.

## F. STREAMING
- An SSE/streamed completion through the inject path flushes incrementally (FlushInterval=-1), not buffered to the end — verify token-by-token arrival.

## G. NEGATIVE / ERROR PATHS
- Malformed config → exit 78 with parse error; missing agent binary → 127; `cove` before `cove setup` (userns denied) → 77 with the "run cove setup" message; proxy can't start → 69; bad `--project` → 66.

## Process
- Each milestone: land its own A/B/E/G tests as applicable + `go test ./...` green + `go vet` clean, before commit. Thin/vacuous tests are a reviewer BLOCKER.
- After M8: a dedicated codex TESTER worker runs the FULL A–G sweep adversarially on the box, writes results to a `TEST-RESULTS.md`, and files any failure back to the orchestrator. cove is not "done" until this sweep is green (or residuals are explicitly owner-accepted, e.g. an expired ChatGPT token needing host re-login).
