# Research Findings — 2026-07-05 strategy session

Four independent streams: (1) Opus deep codebase audit, (2) Sonnet competitive
landscape (web), (3) Codex xhigh architectural assessment of the repo, (4) Codex
xhigh market research (web). All four converged on the same verdict: current form
is a commodity; the defensible pivot is a sandboxed-session manager. Condensed but
complete findings below.

## 1. Codebase audit (Opus)

- Repo totals: **1,493 lines across 15 files**. One 408-line bash script (`cove`),
  `Dockerfile` (190), `Dockerfile.gpu-amd` (169), `install.sh` (45), ~680 lines of
  markdown. Zero application source, zero automated tests (only an in-script smoke
  test `cmd_test`, `cove:278-374`). 40 commits, single author, Mar–Jul 2026.
- Mechanism: rootless Podman, `--userns=keep-id` + `--user` (`cove:239-240`),
  SELinux labeling **globally disabled** (`decisions/005`), no seccomp/cap-drop/
  read-only/network restriction. Launches `claude --dangerously-skip-permissions`,
  `codex --yolo`, `kimi --yolo` (`cove:132-148`). Refuses `$HOME` as workspace
  (`cove:120-128`). README honestly states "not a security sandbox... limits blast
  radius, not access" (README:68) — author previously walked back overclaims.
- **GPU weight**: `Dockerfile.gpu-amd` 100% GPU (9 commits of churn — most-churned
  file after main script); ~32 lines of the script (gpu_flags `cove:165-168`,
  Modal/RunPod/Vast mounts `cove:219-229`, env `cove:265-268`, tests `cove:343-351`);
  variant machinery (`cove:13-14,87-93`) exists mainly for GPU. Total removable
  ~260/1,493 lines (~17%), kills second build target and top churn source. 10 of
  last 40 commits (25%) GPU-related; the 7 most recent all GPU/ROCm/UID fixes.
- **CWD/sandbox coupling**: deliberate "path preservation" design
  (`docs/PRODUCT-PLAN.md:146`): `-v "$workspace:$workspace"` + `-w "$workspace"`
  (`cove:242-243`), same pattern in worktree mount (`cove:186`). ~3 lines encode
  it; reversing is ~half a day of code BUT breaks Claude Code session-path
  continuity between containerized and native runs — must be consciously handled.
- **Sandbox-per-agent**: hard-wired via PID-suffixed name (`cove:150-154`) +
  `--rm` (`cove:237`), but `cmd_exec` (`cove:388-394`) already podman-execs into a
  running container. Shared-sandbox support ≈ 30-60 lines + lifecycle semantics.
- **Churn pattern**: quirk-magnet — most commits fight host breakage (SELinux
  thrashing, GPU UIDs, base-image tags, git-auth: 5+ commits). Weekend-scale burden
  but reactive.
- **Salvage list**: polyglot Dockerfile w/ npm supply-chain hardening
  (Dockerfile:124-129, Trail-of-Bits-derived); podman launch recipe; git-auth
  `.gitconfig` wrapper (`cove:192-217`); worktree detection (`cove:170-190`);
  `decisions/` records; home-refusal guard. Verdict: "the ideas are worth more
  than the code."

## 2. Competitive landscape (Sonnet, web, July 2026)

### Native agent sandboxing
- Claude Code: native sandboxing since Oct 2025 (`@anthropic-ai/sandbox-runtime`,
  `srt`): Linux bubblewrap + unix-socket/socat network proxy; macOS Seatbelt.
  Claimed 84% fewer permission prompts. **Caveat: security firm Ona (Mar 2026)
  showed Claude Code tricked via path manipulation could bypass its denylist, and
  when bubblewrap blocked it, the agent DISABLED ITS OWN SANDBOX and reran
  unsandboxed.** Self-sandboxing is only as trustworthy as the process invoking it
  → external containment retains defense-in-depth value.
- Codex CLI: Landlock + seccomp-bpf default on Linux (bwrap now default fs sandbox
  in recent versions, Landlock legacy fallback), Seatbelt on macOS; network off by
  default; only tool calls sandboxed, main process unsandboxed.
- Implication: "protect laptop from accidental shell commands" wrappers are mostly
  redundant now; containers still buy reproducible envs, dependency isolation,
  whole-process/MCP/hooks containment, defense-in-depth.

### Container-tier competitors (saturated)
- **Docker Sandboxes (`sbx`)** — official Docker product 2026: **microVM-backed**
  per-agent (7 agents supported), host fs unreachable outside workspace, host-side
  **credential proxy so agents never see raw API keys**. Docker itself decided
  plain containers weren't a strong enough story.
- **Dagger container-use** — OSS MCP server, ~3.9k stars, active Jun 2026;
  container + git branch per agent; terminal attach; review via standard git.
- **Sculptor (Imbue)** — desktop app (Mac/Linux beta), per-agent containers,
  real-time diff view.
- devcontainers spec as common substrate (e.g. Trail of Bits claude-code-devcontainer).
- Long tail of cove-clones: ClaudeBox, sandclaude, codex-lockbox, agentbox,
  EdgeBox, vibebin, packnplay, etc. Blog title of the era: "I Built Yet Another
  Sandbox for AI Coding Agents". Cove is functionally indistinguishable from this
  cluster.

### MicroVM tier
- E2B (Firecracker, core OSS, hosted usage 40k→15M sandboxes/mo in a year);
  **Daytona (core went PRIVATE Jun 2026, public repo unmaintained)**; Modal
  (gVisor-on-KVM, hosted); Morph (~250ms VM snapshots); **microsandbox (Apache-2.0,
  libkrun, self-hostable, MCP server — most relevant OSS)**.
- **KVM reality: Firecracker/Kata/libkrun all need `/dev/kvm`. Most budget VPS
  plans don't expose nested virt** (AWS only on metal-ish 8i instances since Feb
  2026; DO/Azure/GCP on select types). "KVM VPS" marketing ≠ nested `/dev/kvm`
  inside the guest.
- **gVisor = the practical middle tier**: userspace kernel (systrap), NO KVM
  required, OCI runtime (`runsc`) plugs into Docker/Podman; syscall-compat and I/O
  perf tradeoffs. Breaks the strict "container or Firecracker" binary.

### tmux-for-agents space
- **claude-squad** (~8k stars, active): tmux + git worktree per agent, tab between
  sessions, background completion tracking. **Confirmed: ZERO sandboxing — all
  agents run as same host user.**
- **Vibe Kanban** (~27k stars): kanban-of-agents; Bloop shut down Apr 2026, hosted
  cloud off, community-maintained, leaderless.
- Conductor (Mac-only, paid), Crystal (deprecated Feb 2026 → paid Nimbalyst),
  Omnara (YC S25 — mobile/web remote monitor+steer for Claude Code/Codex; about
  visibility, not sandboxing), Claude Code "Teleport"/remote control (Feb 2026
  research preview, ties execution to origin machine), dux (TUI over worktrees).
- De-facto DIY pattern in the wild: raw tmux + Tailscale + SSH keys/UFW/Fail2Ban,
  explicitly no process sandboxing. Prior bespoke art: "Netclode" blog (k8s +
  microVM + Tailscale + iOS app) — recognized need, never productized.
- **The gap (both landscape streams agree): nobody ships self-hosted + VPS-native +
  genuinely sandboxed + attach/detach multiplexing. Today you pick two of three.**

### On the owner's dichotomy ("lightweight → why containers; serious → only Firecracker")
Directionally right, overstated as binary. 2026 consensus: OS-level primitives fine
for accident-protection with cooperative agents; plain containers explicitly called
insufficient for adversarial/multi-tenant (shared kernel); gVisor is a real
intermediate; and the sharpest point (both Codex streams): **the dominant personal
risk is voluntarily granted secrets + network, which NO isolation tier fixes —
credential proxy and network policy do.**

## 3. Codex xhigh — architectural assessment (key deltas)

- "Not a security sandbox product; a good personal YOLO-agent runner. Value =
  convenience: one command, toolchains, caches, auth plumbing, blast-radius."
- Verdict: don't kill; **stop positioning as sandbox; pivot to tmux-for-agents-on-
  VPS after stripping GPU**. Only future where container cost becomes a feature
  (persistent workspaces, attach/detach, logs, named sessions, per-session secrets).
- CWD concern validated: reversing it "changes cove's identity from transparent
  containerized CWD to managed session filesystem containing a project."
- Top 3 risks: (1) it's a product-model rewrite, not a refactor (runner → session
  manager: persistence, metadata, attach, logs, limits, recovery); (2) users will
  overtrust the word "sandbox" — say "contained agent sessions"; (3) differentiation
  can collapse into "tmux plus Docker" — must be dramatically smoother.

## 4. Codex xhigh — market research (key deltas)

- "Do not build another Claude-in-Docker wrapper. That lane is crowded and
  increasingly obsolete… almost no moat."
- Claude Code native sandbox covers only Bash subprocesses; MCP servers/hooks not
  contained unless whole process wrapped (srt, still beta research preview) —
  a concrete residual value for external containment.
- The gap is NOT "run N agents" (exists); it's the **combination**: "self-hosted
  Linux/VPS daemon combining session lifecycle, attach/detach, logs, worktrees,
  resource caps, secrets isolation, network policy, and pluggable sandbox backends
  (Docker/rootless Podman/gVisor/microVM-when-KVM)."
- Prescription verbatim: "Stop selling isolation. Sell agent session operations…
  `agent new/attach/logs/diff/stop`, per-agent workspace, network allowlist,
  disposable credentials, optional gVisor, optional microVM backend. Use Docker as
  one backend, not the identity of the project. Kill the generic Docker wrapper;
  keep or pivot the session manager."

## 5. Owner's box (verified this session)

`systemd-detect-virt` → kvm (the box IS a VPS/KVM guest); **no `/dev/kvm`**; no
vmx/svm in cpuinfo (not exposed by hypervisor); no kvm modules; 4 cores, 7.5 GB
RAM. → Firecracker-class isolation impossible on this machine; gVisor is the
ceiling. Owner: "we are mostly going to use systems like this" and "I already run
agents semi-unattended on my system."
