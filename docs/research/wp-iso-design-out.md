# Design brief (opus) — ideal shape of cove for one power user's YOLO-agent VPS

Scope: personal-utility tool, ARM64 KVM-guest VPS, no /dev/kvm, 4 cores / 7.5GB, many parallel Claude Code / Codex sessions full-access. Thesis "agent runs unrestricted inside a boundary; boundary protects host" is correct and removes all four native-sandbox pains. BLIND SPOT driving the whole design: the boundary protects the host, but the actual loss scenario lives at the boundary's SEAMS — the credentials and network egress you deliberately poke through it. No isolation tier closes those seams; only credential scoping + egress allowlist do.

## 1. Make-or-buy: build a THIN glue layer; buy everything under it. Don't adopt a competitor wholesale; don't write another container wrapper from scratch.
- Docker sbx disqualified by hardware (microVM needs /dev/kvm). COPY its ideas (host-side credential proxy so agent never sees real keys; deny-by-default egress), don't run it.
- container-use (Dagger) runs here but solves a different problem (per-agent container+worktree for parallelism/diff via MCP); plain shared-kernel Docker, NO credential proxy, NO egress allowlist, Docker-dependent, in-agent MCP not headless daemon.
- Sculptor/mngr: desktop/orchestrator, not headless self-hosted VPS.
- Gap is real but build is small: self-hosted + VPS-native + headless + credential-scoped + egress-controlled = a proxy + a few hundred lines of session glue on podman. NOT a platform.

## 2. Isolation primitive ranked for this box (secondary choice — don't over-invest; risk isn't kernel escape):
1. Rootless Podman — PRIMARY default. arm64-clean, host-UID-mapped, OCI CoW layers (cheap Nth container), named cache volume, exec-into-running already implemented. Zero per-syscall friction. Shared kernel is acceptable ceiling.
2. gVisor runsc — OPT-IN defense-in-depth, NOT default. No KVM needed (systrap) but ~10-30% overhead on net+file I/O (what agents hammer) and rootless+podman is finicky. [Probe note: actually FAILED rootless on this box — cgroup/systemd auth. So: defer, opt-in later at best.]
3. Bubblewrap-only — low-friction in principle (bwrap without landlock/seccomp = the non-painful part) BUT no image/volumes/lifecycle/exec; you'd reimplement podman. [Probe: also AppArmor-blocked unprivileged here.] Out.
4. microVM (Firecracker/Kata/libkrun) — OUT, all need /dev/kvm.
Recommended stack: rootless podman + free hardening flags + mandatory egress proxy + credential broker + optional runsc per-session. Structural advantage of EXTERNAL containment: when an agent self-disables its own sandbox (Claude Code has done this), an external podman boundary still holds.

## 3. Topology: PER-PROJECT shared sandbox with N sessions inside; separate containers ACROSS projects.
RAM argument doesn't favor one global box — a container isn't a VM; Nth container's marginal cost is the processes inside (node+agent, few hundred MB) which you pay under any topology; image layers + cache volume are shared. What differs is blast radius:
- One global shared box: cheapest but every YOLO agent shares one UID/FS/credentials/workspaces — injected agent in A reads B's secrets, sabotages B. Reject.
- Strict per-session container: max isolation but same-project sessions gain nothing (already share repo) at cost of N configs + N cold starts.
- Per-project container, N cooperating sessions inside (tmux/exec): RIGHT MIDDLE. Mirrors human workflow (one repo, several panes), matches cove's existing cmd_exec. THE PROJECT IS THE UNIT OF ISOLATION AND OF CREDENTIAL/EGRESS SCOPING. Different projects → different containers → different scoped tokens + allowlists. ~30-60 lines: reuse project container if exists else create; attach new session via podman exec.

## 4. Workspace: bind chosen dir → canonical /work (-v <dir>:/work -w /work); keep it a BIND not a copy; identity-mount as opt-in --identity flag.
Bind = zero-friction transparency (live edits, worktrees) + host-path-independent stable in-container path (works whether ~/code/foo or /srv/foo). Skip copy-in/volume workspaces. SEAM: Claude Code keys session history/todos by cwd — native-at-host-path vs cove-at-/work splits continuity. Fix: standardize on /work, always enter via cove, persist ~/.claude on per-project volume. If interchangeable native/cove runs matter, keep old identity-mount as --identity. OWNER DECISION: canonical-only (clean) vs identity-available (compatible).

## 5. 80/20 security controls (ranked by real risk reduction):
1. Credential scoping/broker — #1. Today cove mounts raw ~/.config/gh and passes ANTHROPIC/OPENAI keys as env — hands agent the crown jewels. Fix: LLM keys → tiny host-side reverse proxy, container gets proxy URL + dummy key, proxy injects real Authorization (+ per-session spend cap) [Docker-sbx pattern, ~dozens of lines or one litellm config]. git/gh → 80/20 = fine-grained PAT scoped to only repos in play, no admin/delete/workflow; better = host-socket broker vending short-lived GitHub App installation tokens (~1h expiry). Only control touching "agent abuses/exfiltrates creds you handed it" — no isolation tier addresses this.
2. Network egress allowlist — co-#1, SAME host process does both. Deny-by-default, force LLM traffic through local proxy, allowlist package registries + github. Rootless-pragmatic: drop default route, mandatory forward proxy (HTTP_PROXY) with domain allowlist = only egress. Coarse (whole domains, set once) — OPPOSITE of painful per-syscall net prompts.
3. Free podman hardening — zero friction: --cap-drop=ALL (add back needed), --security-opt no-new-privileges, read-only rootfs + tmpfs /tmp, REMOVE image's passwordless sudo (Dockerfile:100 node NOPASSWD:ALL), per-mount :z/:Z over global label=disable.
4. Filesystem boundary — already have via container; just stop over-mounting (drop unused config mounts).
5. Kernel-escape isolation (runsc/microVM) — lowest priority, last ~5%, opt-in paranoid tier, never v1 gate.
80/20 = credential proxy + mandatory egress allowlist (one small host helper does both) + free hardening flags.

## 6. Build vs buy vs skip:
- Reuse: cove's podman launch recipe; polyglot image + npm hardening; podman; litellm-or-tiny-proxy; gh fine-grained PAT / GitHub App tokens; tmux; git worktrees.
- BUILD (thin): (1) session glue — reuse-or-create per-project container, new/attach/ls/logs/stop, persistent per-project config volumes; (2) credential broker + egress allowlist host helper — small, but THIS is both the unmet gap AND the owner's 80/20; (3) canonical /work mount. ~500-1500 lines Go, mostly glue.
- SKIP (over-eng): custom OCI runtime; any microVM/Firecracker; mandatory gVisor; kanban/TUI (status file + tmux enough); GPU (delete); reimplement podman via bwrap; "pluggable microVM-when-KVM" roadmap. RESEARCH.md's session-manager+pluggable-backends+microVM framing is over-scoped for this hardware — ship podman-only + opt-in runsc, put real effort in the two proxies.

ONE-LINE VERDICT: not another sandbox platform — rootless podman + a credential/egress proxy + ~600 lines of per-project session glue, and the differentiator AND security payoff both live in the proxy, not the container.

OWNER DECISION POINTS: (a) topology per-project-shared (rec) vs strict per-session; (b) workspace canonical-only vs keep identity-mount as --identity; (c) gh creds token-broker (more build) vs scoped-PAT (80/20); (d) ship opt-in runsc now or defer.
