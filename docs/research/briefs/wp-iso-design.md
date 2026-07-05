You are an alternative-perspective systems architect doing DESIGN RESEARCH (analysis + web, no machine access) to inform a decision about the ideal shape of a personal agent-containment tool called "cove". Do not just endorse a prior plan; reason from first principles and surface tradeoffs.

THE USER & NEED (this is a personal-utility tool, external users irrelevant):
- Runs Claude Code + Codex coding agents in YOLO mode (--dangerously-skip-permissions / full-access) on a cheap ARM64 Linux KVM-guest VPS (no /dev/kvm, 4 cores, 7.5GB RAM). Linux-only is fine and even desirable.
- He turned OFF the vendors' native sandboxes because they were painful on ALL FOUR axes: blocked legitimate file access, blocked legitimate network, constant permission prompts, and fiddly setup. So he runs unprotected. He KNOWS this is a big risk (shell + gh creds + open egress + unattended agent + prompt-injection tail risk).
- He runs MANY parallel agent sessions at once.
- Insight to build on: native sandboxes are painful because they restrict PER-SYSCALL; a boundary-based approach (the agent runs UNRESTRICTED inside a container/namespace, the boundary protects the host) removes all four pains at once. That is the design thesis to pressure-test and refine.

THE OWNER'S OWN OPEN QUESTIONS — address each directly:
1. MAKE-OR-BUY: Is a custom wrapper even needed, or does Docker `sbx` / container-use / Imbue mngr already do this well enough? What specifically would they NOT do for this Linux/VPS/KVM-less/many-parallel use case? Be honest — recommend "just use X" if that's right.
2. ISOLATION PRIMITIVE: Compare, for THIS use case, rootless Podman vs bubblewrap (namespaces only, no landlock/seccomp on top) vs gVisor/runsc vs any Linux-specific combo. What does each uniquely offer? What does "building on podman, Linux-specifically" buy over Docker? Is bubblewrap-alone a viable lighter primitive (note: it's what Claude Code's native sandbox is built on — but used WITHOUT the painful landlock/seccomp layer, could it be the low-friction answer)? Consider defense-in-depth combos (e.g. bwrap or podman + optional runsc + egress proxy).
3. TOPOLOGY: per-agent sandbox (current cove) vs ONE shared sandbox hosting many agent sessions. He runs many parallel sessions on 7.5GB — analyze the RAM/overhead, blast-radius, and UX tradeoffs. When is shared right, when per-agent? Could it be a per-project shared sandbox with N sessions inside (tmux), rather than N full containers?
4. WORKSPACE MODEL: old cove fused CWD and the sandbox dir (identity-mounted host CWD at its own path). Decouple them: what's the right model (canonical /work/<project>? bind a chosen dir? copy-in worktree?) that stays low-friction and doesn't break Claude Code's session-path assumptions?
5. THE REAL SECURITY CONTROLS: given the tail risk is voluntarily-granted secrets + open egress (NOT kernel escape), what actually matters? Rank: credential scoping/proxy (agent never holds raw long-lived gh/API creds), network egress allowlist, cap-drop/no-new-privileges/seccomp, filesystem boundary. What's the 80/20 for a personal tool?

OUTPUT: A decision-grade design brief (~2 pages):
- A recommendation on make-vs-buy with a clear bottom line.
- A ranked comparison of isolation primitives for THIS box, with a recommended primary + optional defense-in-depth layers.
- A recommendation on topology (per-agent vs shared) tied to his many-parallel-sessions reality.
- A workspace model recommendation.
- The 80/20 security control set.
- Explicitly flag: what is genuinely worth building vs what already exists vs what is over-engineering. If the honest answer is "this is a thin wrapper / a set of flags / just use bwrap + a hook", say so.
Reason independently; cite sources where used. Give clear bottom lines, not a survey.