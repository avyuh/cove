# Evidence digest for the singular-design pass (all spikes on the real box)

BOX: ARM64 Ubuntu 24.04 KVM guest, no /dev/kvm, 4 cores / 7.5GB. Owner runs claude (Claude Code, OAuth sub) + codex (Codex, ChatGPT sub) + likely kimi, in full YOLO, MANY parallel sessions. He turned OFF native sandboxes — painful on all 4 axes (blocked files, blocked net, permission prompts, setup). Objective: personal utility; archive was on the table and rejected only because of this concrete pain. Kill gate: if he keeps typing `claude` not `cove claude`, archive.

## Isolation feasibility (spikes):
- Docker sbx: IMPOSSIBLE (needs /dev/kvm). Can't buy.
- Rootless podman (crun): WORKS. The container manager.
- gVisor runsc: unblockable rootless (systrap+ignore-cgroups) BUT measured cost vs crun on a real clone+install workload: 1.64x slower (8.5s vs 5.2s), ~6x RSS (903MB vs 150MB), max parallel ~6-8 vs ~25-30 in 7.5GB. Buys down kernel-escape only (the last-5% threat).
- bubblewrap: unblockable (narrow AppArmor userns profile) but it's a namespace primitive not a container manager (no images/volumes/exec/lifecycle) — you'd reimplement podman.

## Credential + egress (spikes, all PASS):
- Claude Code = INJECT works: OAuth via ANTHROPIC_BASE_URL; host proxy swaps dummy->real bearer; agent never holds real token. Survives expired dummy (proxy injects real regardless); host token invalidity => "re-login on host" error. Minimal egress for claude inject: proxy needs only api.anthropic.com host-side.
- Codex = EGRESS-ONLY (ChatGPT auth ignores OPENAI_BASE_URL, hits fixed chatgpt.com HTTP+wss). Owner REJECTS switching to API-key. Codex works fully contained: --network=none forces even the wss WebSocket through the socat+unix-socket CONNECT proxy. Minimal allowlist: chatgpt.com + auth.openai.com (token refresh). Token stays in its container, bounded by allowlist.
- Egress mechanism: container --network=none + bind unix socket + socat bridge 127.0.0.1:3128->socket + host CONNECT proxy with per-project allowlist. Deny-by-default, no bypass (raw IP fails), immune to rootless-iptables gap. socat fork holds 20-way concurrency. Telemetry denials (datadog, platform.claude.com, files.openai.com, api.github.com) fail GRACEFULLY.
- Real threat = voluntarily-granted secrets + open egress, NOT kernel escape.

## Existing asset: /home/dev/cove/cove = 408-line DEBUGGED bash launcher (worktree gitdir resolution, gitconfig credential-helper override, --userns=keep-id, named cache volume, smoke tests). Dockerfile = polyglot image w/ npm supply-chain hardening + (to-delete) GPU/Modal/RunPod/Vast + a NOPASSWD:ALL sudo line.

## Prior fable outputs (may over-scope; reconsider freely):
- Thesis "safe-YOLO launcher": run agent full-YOLO inside podman whose only exit is a host proxy doing credential-injection + egress-allowlist. "The container is plumbing; the product is the proxy." Tagline "YOLO the agents, not your keys."
- A detailed build plan exists: per-tool profile (inject vs egress mode), coved Go daemon (~500 lines: CONNECT allowlist proxy + inject reverse proxy + per-project unix sockets + control API), bash launcher delta with line numbers, Dockerfile strip, 9-step build sequence (~2-2.5 days). Substrate: hybrid (keep bash launcher, coved in Go).
