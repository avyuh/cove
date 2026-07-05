# cove v0 — Design Spec DRAFT (Opus architect, 2026-07-05)

Status: **draft — pending adversarial review and owner rearchitecture pass. Not
approved.** Companion docs: `HANDOFF.md` (constraints), `RESEARCH.md` (findings),
`UX-TEARDOWN.md` (competitor ergonomics).

Positioning tagline (internal): **"tmux for sandboxed agents."** We sell *session
operations* (start / attach / detach / review / reap), not "a security sandbox."

Salvage note: the old repo is a single bash wrapper over `podman run --rm -it` —
ephemeral, single-agent, host-CWD identity-mounted, no persistence, no network
policy, no cap-drop. We keep its *knowledge* (worktree detection, gitconfig
credential-helper trick, npm hardening ENV, SELinux lessons, variant mechanism)
and throw away its *architecture*. Greenfield Go binary.

---

## 0. Reference hardware & frame

Target: KVM guest, **no `/dev/kvm`**, ~4 vCPU, ~8 GB RAM, cheap VPS; identical
behavior on a fat workstation. Anything assuming a hypervisor, Docker Desktop, or
>8 GB RAM is out of scope for v0.

Isolation tiers (pluggable from day one):
1. rootless Podman + runc — v0 default.
2. rootless Podman + gVisor (`runsc`) — flagship tier, v0.2; recommended default
   once validated on target kernel.
3. microVM (libkrun/microsandbox) — opportunistic, only where `/dev/kvm` exists.

## 1. Architecture — daemon vs daemonless

**Recommendation: daemonless-first, evolving to sidecars; central `coved` deferred
until a concrete forcing function lands.**

- Persistence does NOT require a daemon: named container + restart policy + tmux
  inside survives client disconnect, SSH death, and cove binary upgrades. Podman's
  `conmon` is the per-container supervisor.
- Session state lives in **Podman labels** (`cove.managed`, `cove.name`,
  `cove.project`, `cove.agent`, `cove.created`, `cove.branch`); listing =
  `podman ps --filter label=cove.managed=1 --format json`. Runtime is the single
  source of truth — more crash-robust than a daemon's SQLite that can desync.
- Long-lived concerns (credential proxy, egress filter) run as **per-session
  sidecar containers in the same Podman pod**, torn down with the session.
- What forces a `coved` later (don't build before one lands): (1) central
  credential broker holding secrets in RAM; (2) web UI / remote API (strongest);
  (3) cross-session audit/policy/global-kill; (4) scheduled orchestration.
- Daemon-readiness tax paid now: core Go packages (`session`, `backend`, `attach`,
  `secrets`, `netpolicy`) free of CLI-only assumptions so a future coved imports
  them unchanged.

## 2. Session / attach mechanism

Options: (a) tmux INSIDE each sandbox (attach = `podman exec -it <ctr> tmux
attach`); (b) host-side tmux over `podman attach`; (c) custom Go attach with own
scrollback.

**Recommendation v0: (a) tmux-in-sandbox.**
- Free: reconnect robustness over flaky SSH (the single most important property),
  battle-tested scrollback/copy-mode, multi-client attach (phone + laptop).
- (b) couples session survival to host process tree — the fragility we're killing.
- (c) is the right *long-term* answer (independent viewports, server-side
  scrollback, web-UI path) but weeks of work; not a v0 fight.
- Costs: tmux in image (trivial); ship a controlled `/etc/cove/tmux.conf` (status
  line, big history-limit, sane detach, nested-tmux-safe prefix — OD-6); container
  `--init` (tini) reaps zombies; agent lifetime = tmux server lifetime.
- v0.2 bridge to (c): thin Go layer attaching programmatically (spawn `tmux
  attach` under a PTY we own via creack/pty) so the same stream can later fan out
  to a web UI.
- Go attach impl: allocate PTY, raw mode via x/term, forward SIGWINCH →
  TIOCSWINSZ, copy both directions; refuse attach without a TTY (suggest
  `cove logs`).

## 3. Workspace model

**Canonical-path rule (locked): sandbox contains workspace at `/work/<project>`.
No host-CWD identity mount.**

Sources via `--from`:
1. `--from git:<url>` — clone into a **named volume** at `/work/<project>`;
   VPS-native default; nothing touches host FS.
2. `--from path:<dir>` (default when run inside a dir) — two sub-modes (OD-3):
   **copy-in** (default, safe): git worktree/`clone --local` into the session
   volume; agent writes never touch host tree. **`--live`**: RW bind-mount at
   `/work/<project>` (lower isolation, opt-in).
3. `--from empty` — blank volume for greenfield.

Git worktrees, inverted from old cove: cove *creates* a worktree per session off
the primary repo with branch `cove/<session>` (claude-squad's model — but WITH
sandboxing, which is our differentiation). Steal old cove's `.git`-file
`gitdir:` parser (cove:170-190).

Review from host:
- `cove diff [session]` — runs `git -C /work/<project> diff` INSIDE the sandbox
  via podman exec, through git-delta, to host stdout. Instant, read-only, no
  attach. Pass-throughs: `--stat`, `--name-only`, `<ref>`.
- `cove export [session]` (v0.2) — push session branch / format-patch / bundle.

Claude Code session-path compat (the deliberate break): Claude keys history by
absolute CWD (`~/.claude/projects/<path-slug>`). Old cove identity-mounted so
native and containerized sessions shared history; we break cross-boundary
continuity, and mitigate IN-cove:
- Deterministic stable `/work/<project>` → a session's own history stable across
  detach/stop/start.
- Per-session persistent config volume at `~/.claude` (survives stop/start,
  `rm --keep-data`) — old cove shared host `~/.claude` across ALL runs
  (cross-contamination); we isolate per-session (OD-4).
- One-time `cove import --claude-history <hostpath>` helper (copies + rewrites
  path slug). Low priority; document the break honestly.

## 4. Secrets model

v0 (pragmatic, scoped): per-session mounts of agent config dirs at container-home
paths; env passthrough list from old cove (each var only if set); keep the
gitconfig/gh credential-helper trick verbatim (cove:192-217). Honest limitation:
v0 agent DOES hold raw keys — README must say so.

v1 credential proxy (per-session sidecar, agents never hold raw keys):
- **Anthropic/Claude Code — clean**: `ANTHROPIC_BASE_URL` → sidecar reverse-proxy
  injects `x-api-key`/`Authorization`, strips agent-set headers; agent gets dummy
  key. Verify OAuth-token flow separately; static API key is the guaranteed v1
  target.
- **OpenAI/Codex — interceptable**: `OPENAI_BASE_URL`, same pattern (verify Codex
  CLI honors it).
- **git/gh over HTTPS**: `git-credential-cove` helper in sandbox → sidecar mints
  short-lived scoped tokens, or proxy fronts github.com and injects.
- **NOT cleanly interceptable**: cert-pinning tools; tools reading keys from
  files without base-URL override → fallback: cove-minted short-lived rotated
  on-disk tokens. Enumerate per-tool support matrix; don't over-claim.
- Transport: TLS-terminating forward proxy with a cove-generated CA trusted only
  inside the sandbox (`NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`). Same sidecar does
  egress filtering AND credential injection.

## 5. Network policy

Rootless reality: pasta/slirp4netns give no unprivileged host-firewall egress
allowlisting. The enforceable rootless primitive: an **internal Podman network
whose only route is the proxy sidecar** — topology, not env vars, is the boundary.
In-container nftables is tamperable unless caps dropped; don't rely on it.

- **v0: no allowlist; full egress, documented.** Instead ship the hardening old
  cove never had: `--cap-drop=ALL` + curated add-backs, cove seccomp profile,
  `no-new-privileges`, remove default passwordless sudo from image (real
  regression to fix; `--privileged-shell` opt-in). Achievable in a weekend;
  already beats every listed competitor.
- **v0.2: allowlist via forced egress proxy** on internal network; per-session
  domain allowlist (agent API + git host + opted-in registries); refused + logged
  otherwise; HTTP(S)_PROXY env + trusted CA for well-behaved clients, topology
  for the rest.
- gVisor: own userspace netstack; still exits via pasta; proxy remains the
  allowlist mechanism. **Validate runsc + internal network + pasta compose on
  target kernel (known integration risk).**
- Flags: `--net open|none|allow:<csv>` (v0 default `open` — OD-7).

## 6. Image story

**Recommendation: slim-default + fat-optional under a devcontainer-aware
resolver.** Old fat 6 GB polyglot default (decision 004) was premised on a 2.4 TB
workstation — hostile on a cheap VPS.
- `cove-base` (default): Debian slim + Node + Python/uv + Go + Rust +
  git/gh/ripgrep/fzf/jq/delta/**tmux**/zsh + claude + codex. ~1–1.5 GB.
- `cove-full`: the old polyglot image (Java/.NET/Elixir/OCaml), `--image full`;
  reuse old variant mechanism (decision 002) with default flipped.
- v0.2: `--image devcontainer` builds/uses the project's
  `.devcontainer/devcontainer.json` — beats "weird toolchain" without a 6 GB
  default; real differentiator vs claude-squad.
- Keep verbatim: npm supply-chain hardening ENV (decision 003 — extra valuable
  unattended), tini, cache-redirect ENV with the runtime-vs-buildtime split
  (decision 006 — the CARGO_HOME bug; don't relearn), persistent `/cache` volume.
- Drop/fix: passwordless sudo default; blanket `label=disable` (decision 005 was
  Bazzite-specific — re-test SELinux labeling on generic VPS, OD-8).

## 7. CLI surface (v0)

Single binary `cove`; sessions named (auto-generated if omitted).

```
cove new [name]    --from git:<url>|path:<dir>|empty   --live   --agent claude|codex|shell|none
                   --image base|full|devcontainer|<name>   --net open|none|allow:<csv>
                   --detach   --branch <name>   --multi   -e VAR[=val]
cove ls [-a]       name, agent, status, project, net, age
cove attach [name] reconnect-safe tmux attach
cove detach [name] server-side detach of all clients
cove logs [-f]     scrollback without attaching
cove diff [name] [-- git-args]     delta-colored, from inside, read-only
cove exec [name] -- <cmd>          one-shot, non-interactive
cove run  [name] -- <cmd>          add command as new tmux window (multi-agent)
cove stop / start / rm [--keep-data] [--force]
cove export [name]                 push branch / patch / bundle    (v0.2)
cove images / build                reuse old build + CACHE_BUST
cove doctor                        preflight: podman, rootless, subuid, runsc, pasta
```

Golden-path transcript (the product thesis — must be dramatically smoother than
hand-rolled tmux+podman, else we've failed):

```
vps$ cove new billing --from git:git@github.com:me/billing --agent claude \
       --net allow:api.anthropic.com,github.com
     [attached: Claude Code in tmux]   ^b d
vps$ cove ls
     billing  claude  running  billing  allow(2)  3m
vps$ logout                    # SSH dies — agent unaffected
phone$ ssh vps && cove attach billing    # full scrollback, agent mid-task
vps$ cove diff billing         # glance without attaching
vps$ cove export billing       # push branch when happy (v0.2)
```

## 8. Milestones (each independently dogfoodable)

- **M0 — walking skeleton (weekend 1):** Go binary shelling to podman;
  new/ls/attach/stop/rm; labels as DB; tmux-in-image; `path:` copy-in worktree +
  `empty`; slim cove-base; old-style secrets mounts + git trick. Owner can: ssh
  VPS, start Claude session, detach, reconnect from phone.
- **M1 — daily driver (weekend 2):** diff, logs -f, exec, start; `git:`
  clone-into-volume; per-session `~/.claude` volume; **hardening pass**
  (cap-drop/seccomp/no-new-privileges/no default sudo); doctor; `--multi` +
  `run`; shipped tmux.conf.
- **v0.2 — moat starts:** gVisor tier (`--runtime runsc`, default if stable);
  egress allowlist via proxy sidecar + internal network; export; devcontainer
  images; cove-full variant.
- **v1 — differentiated:** credential proxy sidecar (Anthropic/OpenAI header
  injection + git broker) — flagship claim goes live; optional coved + minimal
  web UI (reusing core packages); microVM backend iff /dev/kvm.

## 9. Risks & kill criteria

Risks: (1) gVisor rootless + pasta + internal network may not compose on target
kernel → runc fallback, validate early in v0.2, weaker headline not dead product;
(2) tmux attach jank on high-latency mobile SSH → controlled tmux.conf, test on
real phone early, Go PTY bridge is the escape hatch; (3) credential proxy fails
per-tool (pinning, no override, OAuth) → scope claims to verified matrix;
(4) podman version skew / missing subuid on fresh VPS → doctor remediates,
shell-out adapts; (5) canonical-path break annoys real Claude usage → import
helper, stable path, honest docs; (6) CLI shell-out too coarse somewhere →
escalate to bindings only for that op.

Kill criteria after ~1 month dogfooding (stop/rethink if any):
- Owner keeps reaching for raw tmux+podman (differentiation failed — PRIMARY signal).
- Attach reconnect unreliable on real flaky links and unfixable within tmux.
- gVisor unworkable AND runc+hardening indistinguishable from
  claude-squad-with-a-container (no moat).
- 8 GB VPS holds <2 useful concurrent sessions (target hardware can't run product).
- Credential interception infeasible for owner's actual tools (security
  differentiation collapses to "it's a container").

## 10. Open decisions (rec + alt)

- OD-1 Daemon: rec daemonless+labels+sidecars; alt thin coved now.
- OD-2 Attach: rec tmux-in-sandbox; alt custom Go attach (deferred).
- OD-3 `path:` semantics: rec copy-in default, `--live` opt-in; alt live default.
- OD-4 Agent config: rec per-session `~/.claude` volume; alt shared host mount
  (old cove — convenient, cross-contaminating).
- OD-5 Default image: rec slim base; alt fat 6 GB default (rejected for VPS).
- OD-6 tmux prefix: rec remap (e.g. C-a) + status line vs nested collision; alt
  keep C-b documented.
- OD-7 Net default: rec `open` in v0 (honest), allowlist v0.2; alt `none`
  default (safer, hurts first-run).
- OD-8 SELinux: rec re-test labeling on generic VPS; alt inherit blanket disable.
- OD-9 Sudo: rec none by default, `--privileged-shell` opt-in; alt keep
  passwordless sudo.
- OD-10 Multi-agent: rec both models first-class (`--multi`/`cove run` windows in
  one sandbox; separate `new` = isolated); alt 1:1 only (violates constraint).
- OD-11 Podman access: rec shell out to CLI with JSON; alt
  containers/podman bindings (needs REST socket = daemon-ish, heavy CGO tree,
  fights single-static-binary; only escalate per-op if CLI can't).

## Go libraries (dependency budget: 4)

cobra (CLI), creack/pty (attach), x/term (raw mode/size), x/sys (TIOCSWINSZ).
Everything else stdlib: net/http + httputil.ReverseProxy for the proxy sidecar
(goproxy only if MITM CONNECT demands it), encoding/json, log/slog,
text/tabwriter for `ls`. **No TUI framework in v0; no SQLite (labels are the DB);
no podman bindings.**

## Salvage sources (absolute paths)

- `/home/dev/cove/cove` — worktree detection (L170-190), gitconfig/gh credential
  trick (L196-217), env passthrough list, run invocation → port into Go `backend`.
- `/home/dev/cove/Dockerfile` — basis for slim cove-base (add tmux, drop sudo,
  keep npm-hardening + cache ENV).
- `/home/dev/cove/decisions/006` — runtime-vs-buildtime CARGO_HOME bug.
- `/home/dev/cove/decisions/005` — SELinux context (Bazzite-specific; re-decide).
- `/home/dev/cove/decisions/002` — variant mechanism (reuse for
  base/full/devcontainer).
