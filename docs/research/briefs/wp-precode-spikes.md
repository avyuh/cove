You are a systems engineer running the pre-code spike batch that must PASS/settle before a tool called "cove" is built. Be ruthlessly empirical: real containers, real agents, real numbers, clear PASS/FAIL/DATA per item. This informs a singular, no-hedge design decision, so precision matters. You have passwordless sudo; rootless podman works; a gVisor `runsc` runtime is registered (`podman --runtime runsc`, systrap+ignore-cgroups). claude and codex CLIs are on the host.

SECURITY RULE: the owner's real creds are in ~/.claude/.credentials.json and ~/.codex/auth.json. Use them only as needed to make agents authenticate; NEVER print full tokens (redact to 4 chars); NEVER write real creds to a file you leave behind. Clean up all temp images/containers/files. Log to /tmp/precode-changes.txt.

SETUP: Build ONE minimal throwaway image for the tests — a slim node base with: node, npm, git, curl, socat, and the two agent CLIs installed (`npm i -g @anthropic-ai/claude-code @openai/codex` or the correct package names — verify). Do NOT use the 6GB polyglot Dockerfile. Tag it `cove-spike:latest`. Also have a plain `alpine` for pure-network tests.

Run these SIX spikes:

=== SPIKE 1 (CRITICAL): Codex wss:// through the --network=none socket bridge ===
This gates the whole Codex story. Architecture: container runs `--network=none`, a unix socket is bind-mounted in, socat bridges 127.0.0.1:3128 -> the socket, a host-side deny-by-default CONNECT proxy sits on the socket with allowlist {chatgpt.com, ab.chatgpt.com, auth.openai.com, github.com, registry.npmjs.org}. HTTP(S)_PROXY=http://127.0.0.1:3128 set in the container. Mount the real ~/.codex so codex can auth.
Test: run `codex exec -s danger-full-access "reply with the single word: ok"` inside that container. 
OBSERVE: Does codex's ChatGPT WebSocket (wss://chatgpt.com/backend-api/codex/responses) actually traverse the proxy? Does codex HONOR HTTPS_PROXY for the wss connection, or does it try direct (and fail, since --network=none)? Does the long-lived tunnel survive the socat+unix-socket hop? Capture the CONNECT log and whether codex returned a real completion.
VERDICT 1: PASS (codex works fully contained) / FAIL (wss bypasses or breaks proxy) — with evidence. If FAIL, note exactly how it fails (proxy ignored? tunnel drops?).

=== SPIKE 2: credential-overlay mount (file-over-dir under --userns=keep-id) ===
The inject design mounts the real ~/.claude dir rw, then bind-mounts a DUMMY ~/.claude/.credentials.json :ro ON TOP. Test whether podman honors a file-over-dir bind overlay with `--userns=keep-id`: mount a temp dir at /home/node/.claude and a dummy file at /home/node/.claude/.credentials.json:ro, then inside `cat` the credentials file (should show dummy) and confirm the rest of the .claude dir is the real rw content.
VERDICT 2: PASS/FAIL. If FAIL, note the fallback (synthesized ~/.claude with symlinks).

=== SPIKE 3: Claude OAuth token-refresh seam under inject ===
Run claude inside the container with a DUMMY .credentials.json whose access token is expired (past expiresAt) + ANTHROPIC_BASE_URL pointed at a host reverse-proxy that injects the REAL token. Issue one prompt. OBSERVE: does claude try to REFRESH the (dummy) token itself, and against what host (via ANTHROPIC_BASE_URL, or a fixed host like console.anthropic.com / claude.ai)? Does it choke writing to the :ro credentials file? Does the request still succeed because the proxy injects a valid real token regardless?
VERDICT 3: does inject mode survive token expiry? Describe the failure/success path and whether coved needs a refresh handler or just a "re-login on host" error is fine.

=== SPIKE 4: socat bridge under concurrency ===
Inside the --network=none + socat-bridge container, fire 20 concurrent `curl https://github.com` through the proxy. Confirm socat `fork` mode holds up (all succeed, no dropped/mixed connections).
VERDICT 4: PASS/FAIL with success count.

=== SPIKE 5: allowlist vs real tool chatter ===
Run claude (inject) and codex (egress) under a TIGHT allowlist and harvest the DENY log. Identify: (i) telemetry/analytics endpoints each tool hits (statsig, sentry, segment, etc.) and whether being DENIED breaks the tool or fails gracefully; (ii) the exact host codex uses for token refresh (confirm auth.openai.com or other); (iii) any host a tool genuinely needs. Produce the minimal correct allowlist per tool.
VERDICT 5: the required per-tool host list + confirmation that denying telemetry is graceful.

=== SPIKE 6 (for the isolation decision): crun vs runsc on a REAL workload ===
This settles podman-default vs gVisor-default with data. In cove-spike image, run the SAME representative workload under `--runtime crun` and `--runtime runsc`: e.g. `git clone` a small repo + `npm install` a modest dependency (or `pip install`), doing real file/network churn. Measure: wall-clock time each, peak RSS (host-side, gofer+sandbox for runsc), and cold-start latency. THEN estimate max concurrent sessions in 7.5GB for each (a real agent session ~= node + agent ~ few hundred MB + runtime overhead). Note the file-IO/network overhead gVisor imposes on this exact workload.
OUTPUT 6: a data table [runtime | clone+install wall time | peak RSS | cold start | est. max parallel in 7.5GB] + a one-line read on which better serves "many parallel low-friction YOLO sessions" vs "kernel-escape isolation for a YOLO (arbitrary-code) agent."

=== FINAL OUTPUT ===
Six verdicts with hard evidence/numbers. A short "implications" note: which spikes passed clean, which force a design change (esp. spike 1), and the crun-vs-runsc data. Clean up everything (remove cove-spike image, containers, temp files, temp homes). Confirm no real creds left on disk.