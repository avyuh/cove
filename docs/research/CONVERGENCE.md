# Owner's convergence (final simplification) — 2026-07-05

Through iterative pushback the owner collapsed the object model to the bottom:
- ALL projects owned by him. He does NOT need project-from-project isolation.
- He considered privilege tiers (some sessions higher-priv, protected from others) but then rejected even that: "All my credentials are at same level and I want to protect them all. So maybe I need only ONE sandbox, to basically protect my keys?"
- So: no per-project boxes, no privilege tiers, no agent-vs-agent isolation. ONE box.
- The PURPOSE of cove = protect his credentials from theft/exfiltration by a compromised YOLO agent. Not workload isolation.

Reframe: cove is a CREDENTIAL FIREWALL, not a sandbox manager. The single hardened box exists to make the proxy UNBYPASSABLE (a bare process ignores HTTP_PROXY and reads env directly; a --network=none box cannot). The proxy:
- INJECTS keys that can be injected (Claude OAuth via ANTHROPIC_BASE_URL — spike PASS) so they are NEVER in the box.
- EGRESS-CONTAINS keys that can't be injected (Codex ChatGPT-auth, kimi, gh) so a compromised agent can't exfiltrate them (allowlist: chatgpt.com, auth.openai.com, github.com, registries...).
The box boundary also protects the host (better than his current bare-on-host setup) and forces all traffic through the one exit.

Owner reality: ~30 concurrent sessions, 5-7 active, 10+ projects, full YOLO, claude(OAuth)/codex(ChatGPT)/kimi, ARM64 KVM-less VPS 4c/7.5GB. Runs bare today, no burns; stated fear is KEY THEFT, not host damage or workload collisions. Kill gate: if he keeps typing bare `claude`, archive.
