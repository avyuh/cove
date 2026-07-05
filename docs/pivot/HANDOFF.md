# Pivot Handoff — Session of 2026-07-05

This file is a complete handoff from the strategy session that decided cove's future.
Read this + `RESEARCH.md` (same directory) before doing anything. The old
`docs/PRODUCT-PLAN.md` and `docs/IMPLEMENTATION-PLAN.md` describe the OLD bash
product and are superseded by this direction.

**IMPORTANT: the owner said "we will rearchitect again" — the architecture sketches
below are inputs to a fresh design pass in the next session, not settled decisions.
The DECIDED items are locked; everything under "Working architecture direction" is
open for revision.**

## The decision

Retire cove's current form (408-line bash wrapper around rootless Podman that
launches AI coding CLIs in YOLO mode). Pivot to a **greenfield rewrite: a
self-hosted session manager for sandboxed coding agents** — "tmux for sandboxed
agents". Sell *agent session operations* (persistent named sessions, attach/detach,
logs, diff review, lifecycle), not "security sandbox".

Rationale in one paragraph: plain container-wrapper-for-agents is a saturated,
zero-moat category (dozens of clones; Claude Code and Codex now ship native
bubblewrap/Landlock sandboxing; Docker's official `sbx` went microVM + credential
proxy). The genuine open gap, confirmed by four independent research streams, is
**self-hosted + VPS-native + genuinely sandboxed + tmux-like multiplexing** —
claude-squad (~8k stars) has zero sandboxing, Vibe Kanban (~27k stars) is leaderless
since Bloop shut down (Apr 2026), Daytona went closed (Jun 2026), sandboxed options
are desktop apps or SaaS. Owner passed the dogfood gate: he already runs agents
semi-unattended on exactly the target hardware.

## Locked constraints (owner-decided, do not relitigate)

- **Linux-only.** No macOS/seatbelt/lowest-common-denominator compromises.
- **Go**, single binary strongly preferred. No more bash glue.
- Runs identically on local workstation and cheap VPS.
- **Primary target hardware: KVM guests WITHOUT nested virt.** Verified on the
  owner's own box (a KVM guest, no `/dev/kvm`, no vmx/svm flags exposed, 4 cores,
  7.5 GB RAM). Therefore Firecracker/Kata/libkrun are IMPOSSIBLE on default target
  hardware. **gVisor (`runsc`, systrap platform, no KVM needed) is the flagship
  isolation tier; microVM is a later opportunistic backend only where `/dev/kvm`
  exists; rootless Podman is the v0 baseline.** Pluggable backends from day one.
- **GPU support is obsolete — delete.** GPU workloads moved to separate
  remotely-operated containers (same pattern local and vast.ai/RunPod/Modal).
  `Dockerfile.gpu-amd`, provider config mounts, provider env passthrough, variant
  machinery: all dead weight (~17% of repo, ~25% of commit churn).
- **Sandbox filesystem CONTAINS the workspace** at a canonical path (e.g.
  `/work/<project>`) — do NOT identity-mount host CWD at its own path. (Old cove
  did the identity mount deliberately for Claude Code session-path compatibility —
  see `docs/PRODUCT-PLAN.md:146` and `cove:242-243`. Migration consequence must be
  handled, not ignored.)
- **Session-per-sandbox vs multiple agents sharing one sandbox = first-class user
  choice**, not hard-wired. (Old cove hard-wired 1:1 via PID-suffixed `--rm`
  containers; its `cmd_exec` at `cove:388` shows sharing is already primitive-level
  possible.)
- **Honest positioning**: "contained agent sessions", never "secure against
  malicious agents". The security features that actually matter on KVM-less
  hardware: credential proxy (agents never hold raw API keys / git credentials),
  per-session network allowlist, seccomp/cap-drop (old cove had NONE of these and
  even disabled SELinux labeling — `decisions/005`).
- Differentiation bar: **dramatically smoother than hand-rolled tmux+podman**,
  else pointless.

## Working architecture direction (OPEN — to be redone next session)

Sketch from this session, treat as strawman: single Go binary; CLI surface
`cove new / ls / attach / logs / diff / stop / rm / exec`; sessions persistent and
named, survive disconnect; golden path = ssh to VPS, `cove new`, detach, reattach
later from anywhere. Key open questions deliberately NOT settled:

1. Daemon vs daemonless (state in container runtime labels vs a small `coved`;
   credential proxy / network policy / notifications may force a daemon eventually).
2. Attach mechanism: tmux inside sandbox vs host-side tmux vs custom Go attach
   (scrollback, reconnect-over-flaky-SSH, copy-mode, multi-client are the criteria).
3. Workspace model: clone-into-volume vs overlayfs-on-checkout vs git worktree per
   session; how `cove diff`/host-side review works.
4. Secrets: v0 pragmatic config-dir mounts → v1 credential proxy (what is actually
   interceptable for Claude Code and Codex needs verification).
5. Network allowlist mechanics under rootless podman (pasta/slirp4netns limits) and
   gVisor's netstack.
6. Image story: reuse fat polyglot Dockerfile (~6 GB) vs slim base + devcontainer.

## Design-phase outputs (all captured — nothing lost)

Both design tasks completed and are saved alongside this file:

1. **`SPEC-DRAFT.md`** — v0 design spec (Opus architect): daemonless-first
   architecture (podman labels as state store, sidecars over daemon),
   tmux-in-sandbox attach, `/work/<project>` workspace model with copy-in
   worktrees, phased secrets (v0 mounts → v1 credential-proxy sidecar), network
   policy phasing (v0 hardening, v0.2 forced-proxy allowlist), slim-default image,
   full CLI surface, weekend-scale milestones, kill criteria, 11 open decisions
   with recommendations, 4-dep Go library budget. **Draft — went to adversarial
   review; NOT owner-approved; owner wants a rearchitecture pass regardless.**
2. **`UX-TEARDOWN.md`** — competitor ergonomics teardown (Sonnet): steal/avoid
   lists for claude-squad, container-use, Docker sbx, DIY tmux+VPS, Omnara, Vibe
   Kanban; top-10 UX requirements. **Verified: "knowing when an unattended agent
   needs input" is THE most-reported pain in the ecosystem** → notifications are a
   headline feature. Runner-up: scrollback/rendering wars argue for owning the
   attach/scrollback story deliberately.
3. **`SPEC-REVIEW.md`** — Codex xhigh adversarial review of the spec.
   **Verdict: major rework, do not approve.** Core criticism: the v0 cut deferred
   every differentiator (attention state, durable lifecycle, credential proxy,
   deny-by-default egress) and collapsed into "tmux plus rootless podman."
   Five mandatory changes ranked inside; three items need SPIKES before any spec
   leans on them (rootless internal-network+pasta topology, rootless runsc on
   target kernel, phone-attach resize chain through podman exec + tmux).

The rearchitecture pass should treat SPEC-DRAFT as the strawman and SPEC-REVIEW
as the constraint list, with UX-TEARDOWN's top-10 as acceptance criteria —
especially: needs-attention notifications belong in the FIRST milestone.

## Salvage from old cove (keep before deleting anything)

Per the codebase audit (full detail in RESEARCH.md §1):
- `Dockerfile` (190 lines) — polyglot agent dev image incl. npm supply-chain
  hardening block (`NPM_CONFIG_IGNORE_SCRIPTS`, `MINIMUM_RELEASE_AGE`, lines ~124-129).
- Rootless podman launch recipe — `--userns=keep-id --user $(id -u):$(id -g)` +
  scoped mounts + named cache volume (`cove:237-272`).
- Git-auth-in-container plumbing — mktemp'd `.gitconfig` neutralizing host
  credential helpers, routing through `gh auth git-credential`, SSH→HTTPS rewrite
  (`cove:192-217`). Took 5+ commits to get right.
- Git worktree detection — parses `.git` file `gitdir:` to auto-mount parent repo
  (`cove:170-190`).
- `decisions/` records — institutional memory (esp. 004 fat image, 005 SELinux).
- Home-dir refusal guard (`cove:120-128`).

## Process notes (how the owner wants this run)

- Owner acts as decision-maker; Claude acts as **manager/architect delegating to
  subagent teams** (Opus for deep/architect work, Sonnet for research/teardowns)
  plus **Codex xhigh** instances (`codex` CLI, skill at
  `~/.claude/skills/codex`) for independent/adversarial second opinions. Claude
  should not do the research/code analysis itself.
- Surface decision points with options; owner picks. Small atomic changes. Never
  auto-commit.
- Persistent memory also updated: see
  `~/.claude/projects/-home-dev-cove/memory/cove-strategic-direction.md`.

## Immediate next steps for the new session

1. Owner said "we will rearchitect again" → run a fresh architecture pass over the
   six open questions, using this file + RESEARCH.md as the brief.
2. Re-run (or re-scope) the two lost design tasks above if their input is wanted.
3. Then: v0 spec → Codex adversarial review → owner sign-off → milestone 1.
