# cove — consolidated final design decisions (authoritative brief for the spec)

## Mission & positioning
cove is a CREDENTIAL FIREWALL for locally-run YOLO AI coding agents. It protects the owner's credentials from a compromised/prompt-injected agent. It is NOT a sandbox manager, session manager, dev-environment, or host-hardening tool. Position honestly: "cove stops key THEFT and EXFILTRATION; it does NOT stop MISUSE of an allowed credential at an allowed host, and it is not a defense against kernel escape." Never say "secure sandbox."
It is the self-hosted, KVM-less, CLI-agnostic realization of the SOTA pattern (sandbox + deny-by-default egress + host-side injection broker) — same architecture as Docker Sandboxes, rebuilt as one Go binary on a cheap ARM VPS with no hypervisor.

## Owner context
~30 concurrent agent sessions, 5-7 active, 10+ projects, full YOLO, claude(Claude Max OAuth)/codex(ChatGPT OAuth)/kimi + potentially others. ARM64 Ubuntu 24.04 KVM guest, no /dev/kvm, 4c/7.5GB. Runs bare today. All projects same trust (no project/agent/tier isolation wanted). Kill gate: if he keeps typing bare `claude`, archive.

## Architecture (one sentence)
An unprivileged Go binary runs each agent in an ephemeral kernel-namespace box with no secrets and no network route except one host-side proxy that allowlists every destination and injects the keys the agent must never hold.
Shape: a box with no keys and no way out but one door; at the door a guard who checks where you're going and hands you the key only if you're going somewhere already trusted.

## Substrate decision: OWN GO BINARY on kernel namespaces. NOT podman. NOT gVisor. NOT bubblewrap.
- Rationale: mission is narrow (key protection, not a dev env), so no image to amortize; kernel-direct is smaller and holdable-in-head; podman's only unique value (rootless networking) is designed away by loopback-only netns + unix socket. gVisor deleted (1.64x CPU tax on 100% of work, ~6x RSS; kernel-escape is not the threat). bubblewrap = podman-minus-manager, would reimplement it.
- Proven by spike: 221-line C prototype does single-UID userns map, deny-by-default mount root (secrets ABSENT), loopback-only netns (raw egress -> ENETUNREACH, unbypassable), unix-socket proxy channel across netns. Code in /home/dev/cove/spikes/lockbox/.

## Object model & lifecycle
- EPHEMERAL PER-SESSION namespaces: each `cove -- <agent>` forks, unshares USER|MOUNT|PID|NET, builds a fresh tmpfs deny-root, execs the agent. On exit everything evaporates. Nothing persists by construction. Agent installs land in the mounted /work (host-persistent); system tools come from host /usr bind (no accretion problem).
- ONE long-lived thing: the shared host-side proxy daemon (holds keys + CA in memory), serves all sessions, auto-spawned on first use.
- ONE one-time thing: `cove setup` installs an AppArmor profile granting `userns` (required by Ubuntu 24.04 apparmor_restrict_unprivileged_userns=1; same requirement podman/bwrap have). Single `sudo`, once. Single-UID map => no newuidmap/setuid, no /etc/subuid. Files in /work owned by the owner.

## Box mechanics (the launcher builds these)
- USER ns: map only the current uid/gid (box-root -> host uid). No range, no setuid helper.
- MOUNT ns: fresh tmpfs root; bind-ro /usr (+ /bin,/lib,/sbin symlinks); synthesized minimal /etc (passwd, group, hosts, EMPTY resolv.conf); tmpfs /tmp; tmpfs /dev with null/zero/random/urandom (+ptmx/pts for tty); /proc via PID ns; project bind at /work (identity path acceptable OR /work — spec must pick; note Claude Code cwd-history implication); proxy socket bind at /proxy/proxy.sock. Secrets are ABSENT (deny-by-default construction, not a denylist) — ~/.ssh, ~/.aws, ~/.claude, dotfiles simply do not exist in the box.
- PID ns: for correct /proc + reaping; in-box init is PID 1.
- NET ns: loopback only, no veth/route/gateway. Only egress = the bind-mounted unix socket to the host proxy.
- IN-BOX INIT (PID 1, part of the same binary): reap zombies; forward signals + SIGWINCH; allocate pty for interactive agents; run a ~30-line TCP(127.0.0.1:8080)<->unix-socket shim so proxy-env clients work. Agent gets HTTPS_PROXY=http://127.0.0.1:8080 (+ lowercase), NODE_EXTRA_CA_CERTS/SSL_CERT_FILE/etc pointing at the in-box CA cert, and per-tool base_url_env where configured.

## The proxy (one shared host process; EXPLICIT not transparent)
- Rejected transparent capture (TPROXY/nft/SNI/DNS-intercept): loopback-only already makes egress unbypassable (proxy-ignoring tools FAIL CLOSED, which is safe), so transparency's only benefit is moot and it would drag back podman-class net complexity.
- Routing: box reaches proxy over bind-mounted unix socket /proxy/proxy.sock (proven to cross netns). In-box shim maps 127.0.0.1:8080 TCP -> unix socket 1:1.
- Two jobs, one process: (1) for ALL traffic, match CONNECT target host against the allowlist (allow | inject | deny-default); (2) for `inject` hosts, terminate TLS with cove's CA and add the credential header; for `allow` hosts, tunnel the CONNECT opaquely (no TLS termination).
- DNS ELIMINATED: with explicit proxy, clients send CONNECT host:443 BY NAME; the proxy resolves host-side and enforces the allowlist BEFORE resolving. Box has no resolver (empty resolv.conf).
- CA: cove generates its own CA into ~/.config/cove/ca.pem (host-side, NEVER in a box); the box trusts it via env for TLS-terminated inject hosts. Only the inject hosts are MITM'd; allow hosts are opaque tunnels.
- AUDIT LOG (v0 feature): append-only log of every proxied request (host, method, path, timestamp, bytes) to ~/.local/state/cove/. Nearly free; the only answer to the misuse/oracle residual.
- Lifecycle: auto-spawned on first use (or a systemd user unit); shared by all sessions; keys+CA in memory. Fail-closed if it dies.

## Credential model: two-value host->policy table {allow | inject}
- Classes (from SOTA research): A=injectable simple bearer (key kept OUT of box via host-keyed inject); B=OAuth-session-local (token in box, egress-contained via allow); C=request-signed SigV4 (key MUST stay in box, allow-contain only; user pairs with short-lived STS creds — cove doesn't build a signing broker).
- {allow | inject} covers all three: A->inject, B&C->allow. NO third policy value (a `sign` broker = a project, not a feature; reserved, not shipped).
- `inject` is a STANZA: {host, header template (Authorization/x-api-key/x-goog-api-key), secret ref (host file/keystore), dummy value exposed in box, OPTIONAL base_url_env rewrite}. `allow` is just a host (or host list).
- base_url_env: generalizes the claude ANTHROPIC_BASE_URL mechanism; also rescues kimi (client ignores HTTPS_PROXY but honors KIMI_BASE_URL). For a base_url tool, box gets a plain-HTTP loopback endpoint; proxy adds key + upstream TLS (no CA distribution needed for that tool).
- Adding a new CLI = config only, zero code: A-class = one inject stanza + one base_url/proxy env; B/C = one/two allow lines.
- Pre-seeded default config ships with the per-CLI table below.

## Per-CLI seed (default config content)
INJECT (key out of box): claude(OAuth via ANTHROPIC_BASE_URL, host holds access token + does refresh — SPIKE PROVEN), any API-key mode (codex/kimi/gemini/hf), hcloud, wrangler(token), runpodctl, gh(PAT), api.anthropic.com.
ALLOW/contain (token in box, exfil-blocked): codex(chatgpt.com,auth.openai.com), kimi(OAuth via KIMI_BASE_URL/KIMI_CODE_OAUTH_HOST), gemini(Google OAuth), wrangler(OAuth), gh(OAuth github.com,codeload.github.com), plus registries: registry.npmjs.org, pypi.org, files.pythonhosted.org, proxy.golang.org, sum.golang.org, index/static.crates.io, objects.githubusercontent.com, huggingface.co.
SIGNED/allow-only (can't inject ever): s5/S3, aws — key stays in box, allowlist endpoint, user supplies STS short-lived creds.
Ecosystem facts: NOBODY on the list pins certs; everything except kimi honors HTTPS_PROXY; every API-key mode honors a base-URL override.

## Command surface (tiny)
- `cove [--project DIR] -- <agent> [args...]` — run an agent in a fresh box (default project = cwd).
- `cove setup` — one-time, needs sudo (installs AppArmor profile, generates CA).
- config file ~/.config/cove/hosts (or config.toml) — the host->policy table.
- (spec decides if `cove log` to tail audit log is worth a verb, or just a file path.)
- NO ls/attach/session-names/TUI. cove is not a session manager.

## Artifact & language
One static Go binary `cove`, dispatched by argv into three roles: launcher (build ns, exec agent), proxy daemon (`cove proxyd`, auto-spawned), in-box init (PID1: reap + signal/SIGWINCH + pty + TCP<->unix shim). Embeds the CA generation + the proxy. Go stdlib only (net, net/http, net/http/httputil, crypto/tls, crypto/x509, os, syscall/x/sys/unix for namespaces). No runtime dep but the kernel + the one-time AppArmor profile.

## Anti-scope (standing rejections)
No host-protection-as-a-goal (side effect only), no tmux-for-agents/session manager/TUI/kanban/notifications, no per-project/per-agent/tier isolation, no pluggable backends, no podman/gVisor/bwrap, no microVM roadmap, no transparent redirect/TPROXY/DNS-interceptor/SNI parser, no SigV4 signing broker, no WIF minting in v0 (keep the seam), no per-host method/path policy or rate limits in v0 (audit log instead), no multi-user, no GPU, no macOS. Standing rule: every feature must name the bare-YOLO failure it prevents.

## Success metric (one)
30 days from install, the owner's count of bare `claude`/`codex` invocations is zero — reflex replacement. Else archive without sentiment. Friction is the only axis measured.

## Complexity budget (~1200-1500 lines Go + 1 AppArmor file, one binary)
namespace setup ~300 (proven), in-box init ~200, host proxy daemon ~500-700 (the meat: unix accept, CONNECT parse, allowlist, TLS-terminate+inject for inject-hosts, opaque tunnel for allow-hosts, audit log), CA gen + config loader ~150, AppArmor writer + setup ~50.

## Known risks / OPEN ITEMS the spec must nail
1. MITM HTTP/2 injection correctness: claude speaks h2; terminating+re-originating h2 while injecting a header (streaming/keepalive/chunking) is fiddly. UNPROVEN STEP: a real claude 200 completion THROUGH MITM+injection over h2 was not yet spiked (only CA-acceptance to a synthetic 401 was). Spec must specify the h2 handling and mark this as the first thing to prove in implementation. Mitigation: MITM only the 1-2 inject hosts; everything else opaque tunnel; if a provider ever pins, fall back to allow+in-box key.
2. Scope-creep back into rootless networking (veth/pasta) — forbidden; proxy-by-name only; a tool that won't honor HTTPS_PROXY or a base-URL is out of scope, not a reason to grow the substrate.
3. pty + SIGWINCH for interactive TUI agents — ours to implement, ~80 lines, known recipe.
4. proc/pidns correctness; /dev construction; teardown/cleanup on crash.
5. Claude OAuth token refresh: host-side ~/.claude holds real token; proxy reads it per-request (mtime-cached); on host-token expiry, surface "re-login on host" cleanly.
6. AppArmor profile exact content + the `cove setup` UX (and behavior if not run / on non-AppArmor distros — spec should at least note portability boundary: Ubuntu 24.04 target).

## Evidence files (for detail)
spikes proven in: EVIDENCE-DIGEST.md, wp-precode-out.md (crun/runsc data + credential/wss/overlay), wp-foundational-out.md (kernel-ns feasibility + AppArmor requirement), wp-generic-cred-out.md (transparent egress + MITM CA acceptance), wp-sota-methods-out.md, wp-cli-auth-ai-out.md, wp-cli-auth-infra-out.md (SOTA + per-CLI classes). Prototype: /home/dev/cove/spikes/lockbox/.
