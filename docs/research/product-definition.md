# cove — product definition (fable ideation, prior pass)

Name/tagline: cove — "YOLO the agents, not your keys." (a cove = sheltered harbor with one narrow mouth = the architecture.)

## Thesis (committed): "Safe-YOLO launcher" (framing C, chosen over A "session manager" and B "pure proxy")
cove is the way you START a YOLO agent. It runs the agent unrestricted inside a rootless-podman box whose ONLY exit is a host-side proxy that injects your credentials (agent gets dummies) and enforces a per-project domain allowlist — so "full permissions inside" costs nothing outside. The container is plumbing; the product is the proxy. A pure proxy is theater (nothing forces the agent through it); a session manager targets the part with zero security payoff + a graveyard of competitors. The launcher exists to make the firewall MANDATORY.

## MVP ("the harbor mouth") — ~500 lines Go + ~150 lines bash delta
1. coved — one host daemon, two jobs: (a) credential injection reverse proxy (container gets ANTHROPIC_BASE_URL->proxy + dummy key; proxy injects real Authorization; real keys never enter container); (b) egress allowlist forward proxy (HTTP CONNECT, per-project domain allowlist, deny-by-default + logged; defaults: github.com, api.anthropic.com, api.openai.com, registry.npmjs.org, pypi.org, proxy.golang.org, crates.io, objects.githubusercontent.com).
2. Structural deny-by-default rootless-proof: container runs --network=none, bind a unix socket at /run/cove/proxy.sock, entrypoint bridges 127.0.0.1:3128 -> socket via socat, HTTP(S)_PROXY set globally. No route out except the socket. Escape hatch: `cove --net=open <tool>` -> pasta with loud warning.
3. Free hardening: --cap-drop=ALL, --security-opt no-new-privileges, delete image's NOPASSWD:ALL sudo, drop unused config mounts, DELETE GPU variants + Modal/RunPod/Vast key-passing/mounts (kills 8 of 12 leaked keys by deletion).
4. gh via scoped fine-grained PAT per project (not raw ~/.config/gh mount).
5. Command surface (delta): `cove claude|codex|shell [path]` (unchanged UX = the point); `cove allow <domain> [--project P]`; `cove log [name]`; `cove proxy status|restart`.
NOT in MVP: session persistence/naming, per-project containers, TUI, notifications, spend caps, runsc, canonical /work, config beyond one TOML. If MVP takes >~2-3 focused days, that's a signal.

## Roadmap
P1 = the proxy (MVP). Why now: it's the whole thesis; first thing cove ships that bare YOLO can't answer; the cred/egress helper IS the product.
P2 = per-project persistent containers (installs accrete; reuse-if-exists else create, attach via podman exec, ~40 lines) + ntfy needs-input pager (~50-line Notification/Stop hook). Both afternoon-sized.
P3 = gated on a NAMED incident, else never: per-session spend caps, opt-in runsc if it ever works, read-only rootfs. Entry criterion: owner names a specific session where absence cost him.

## Substrate: HYBRID — keep bash launcher, write only proxy in Go. The 408 debugged bash lines (worktree gitdir, gitconfig credential override, keep-id quirks) are the paid-for part; rewriting buys zero. MVP launcher delta ~100-150 lines bash. Proxy = long-running/concurrent/CONNECT/header-injection/logging = Go stdlib (~400-600 lines, one static ARM64 binary). Go was right for the DAEMON, not the glue.

## 4 decisions (fable recommended defaults)
(a) topology: per-project shared container (P2), --fresh for throwaway; MVP keeps per-invocation --rm (orthogonal to proxy).
(b) workspace: KEEP identity mount as default, don't build canonical /work (one-VPS YAGNI; /work orphans Claude Code cwd-keyed session history). [design brief recommended the opposite; fable deliberately reversed.]
(c) gh creds: scoped fine-grained PAT (broker = toolmaker trap for one user).
(d) runsc: defer (broken here, last-5% threat); leave COVE_RUNTIME=runsc env passthrough as courtesy.

## Anti-scope (tripwire vs the toolmaker trap / 3-month dormancy): no session manager/TUI/kanban; no pluggable backends; no microVM/gvisor roadmap; no Go launcher rewrite; no GPU/Modal/RunPod/Vast; no MITM/TLS interception; no multi-user/packaging; no second daemon ever. RULE: every feature must name the bare-YOLO failure it prevents, or it's rejected.

## Kill gate: if after 2 weeks owner still types `claude` not `cove claude`, it failed on friction -> archive without sentiment.

## SPIKE RESULTS (after this definition was written — UPDATES it):
- Claude Code cred injection: PASS (OAuth via ANTHROPIC_BASE_URL, proxy injects real bearer, 200).
- Codex ChatGPT-auth cred injection: FAIL — ignores OPENAI_BASE_URL, hits fixed chatgpt.com/backend-api/codex HTTP + wss:// WebSocket; only injectable via API-key (owner REJECTS switching off ChatGPT sub) or TLS-MITM (anti-scope forbids). So Codex = egress-only containment, token stays in container, MUST keep working on ChatGPT subscription.
- Egress socket-bridge: PASS (curl allow/deny/no-bypass confirmed). NOTE: tested with https curl/CONNECT only, NOT yet with Codex's wss:// WebSocket through the socket bridge — unverified.
- Owner directive: it MUST work with claude, codex, etc. on their native CLIs/subscriptions. Do not force API-key.
