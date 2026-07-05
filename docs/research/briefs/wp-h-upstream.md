You are an independent engineer scoping whether CONTRIBUTING to an existing open-source project beats building a new one from scratch.

CONTEXT: A developer has expertise in running AI coding agents (Claude Code, Codex) inside rootless Podman containers on a cheap Linux VPS (no /dev/kvm), with git-auth plumbing and supply-chain-hardened images. He is deciding cove's future. One option is: instead of building a new Go "session manager for sandboxed agents", contribute the sandboxing/VPS value into an existing tool that already has users.

YOUR TASK — clone and analyze these repos (use git clone into /tmp; use web search for issues/PRs/maintainer activity where cloning is insufficient). Today is 2026-07-05.

PRIMARY TARGET — claude-squad (github.com/smtg-ai/claude-squad or its current home; find the canonical repo):
1. Clone it. Map the architecture: where/how does it spawn agent processes? It runs agents in tmux + git worktrees. Find the exact file/function that launches the agent subprocess.
2. Assess: how hard is it to add a pluggable "container execution backend" (run the agent inside `podman run`/`podman exec` instead of a bare subprocess)? Identify the specific integration seam by file:function. Estimate LOC and design risk.
3. Search its GitHub issues/PRs for requests for sandboxing / containers / isolation / security. Are maintainers receptive? What did they say? Is the project actively maintained (recent commits, PR merge latency, release cadence)?

SECONDARY TARGETS (lighter analysis):
4. container-use (github.com/dagger/container-use): it already containerizes agents. What is it MISSING vs the owner's goal (VPS-native? persistent named sessions? attach/detach? notifications?)? Could the owner's value be added here instead? Is it maintained?
5. Vibe Kanban: is stewardship actually available (was it forked/revived after Bloop shut down Apr 2026)? Is adopting/reviving it realistic for a solo dev, or a trap?

OUTPUT (tight memo):
- Per target: verdict = TRACTABLE+WELCOME / TRACTABLE+UNWELCOME / INTRACTABLE, with the specific integration seam (file:function) for the best target and an honest effort estimate (LOC, weekends, merge probability).
- A one-paragraph recommendation: is "contribute upstream" a serious contender vs building new, and if so which target?
Cite file paths and URLs. Be concrete.