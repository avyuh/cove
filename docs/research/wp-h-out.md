**Claude Squad**
Verdict: **TRACTABLE+UNWELCOME**

Canonical repo is `smtg-ai/claude-squad`: https://github.com/smtg-ai/claude-squad. Architecture is simple: `session.Instance.Start` creates/restores the worktree, then calls `i.tmuxSession.Start(i.gitWorktree.GetWorktreePath())` in [session/instance.go](/tmp/claude-squad/session/instance.go:202). The actual agent launch is [session/tmux/tmux.go](/tmp/claude-squad/session/tmux/tmux.go:91), where `TmuxSession.Start(workDir)` runs:

https://github.com/smtg-ai/claude-squad/blob/main/session/tmux/tmux.go#L91-L99

```go
exec.Command("tmux", "new-session", "-d", "-s", t.sanitizedName, "-c", workDir, t.program)
```

Best seam: **`session/tmux.TmuxSession.Start`**, with config flowing from `config.Profile.Program` in [config/config.go](/tmp/claude-squad/config/config.go:29). A clean upstreamable design is an `ExecutionBackend` behind tmux: default backend emits the current bare command; container backend emits `podman run -it --name ... -v worktree:/workdir -w /workdir image sh -lc <program>` or a create/start/exec sequence for persistent containers.

Effort: **MVP 300-600 LOC, 1-2 weekends** for profile-level `backend`, image, mounts, env, and tests. **Robust 800-1500 LOC, 3-5 weekends** once you handle persistent named containers, resume/restore, auth mounts, SSH/GitHub credentials, cleanup on `Kill`/`Pause`, and failure recovery. Design risk is medium: tmux stays useful as the terminal transport, but container lifecycle becomes a second managed resource alongside tmux and worktrees.

Maintainer signal is weak for this exact direction. There is a direct sandbox issue, `feat: sandboxed agents`, closed as **not planned** with no maintainer discussion: https://github.com/smtg-ai/claude-squad/issues/155. A related environment/isolation hook issue is open and popular, but has no maintainer response: https://github.com/smtg-ai/claude-squad/issues/260. The implementation PR for that hook is stale, conflicted, and unreviewed: https://github.com/smtg-ai/claude-squad/pull/270. Project activity itself is real: repo pushed June 17, 2026, release `v1.0.19` published June 17, 2026, about 8k stars, 577 forks, 52 open issues: https://github.com/smtg-ai/claude-squad/releases/tag/v1.0.19. Merge probability for a focused container backend: **25-40%** unless preceded by maintainer buy-in.

**container-use**
Verdict: **TRACTABLE+WELCOME, but not the same product**

Repo: https://github.com/dagger/container-use. It already owns “agent work in containers” better than Claude Squad: docs say it uses Dagger plus Git worktrees, gives each agent a fresh container/branch, supports logs, diff, checkout, merge/apply, terminal, and resume-by-environment-id: https://github.com/dagger/container-use/blob/main/docs/introduction.mdx and https://github.com/dagger/container-use/blob/main/docs/environment-workflow.mdx. It is maintained: pushed June 12, 2026, around 3.9k stars, 201 forks, and active recent commits in the local clone.

What it is missing vs the owner’s goal: it is **not** a tmux/session manager that launches Claude/Codex itself. The agent runs outside and uses Container Use through MCP (`container-use stdio`), per quickstart: https://github.com/dagger/container-use/blob/main/docs/quickstart.mdx. It requires the Dagger/container stack and docs still say Docker is required. It has `terminal` and `watch`, but not a Claude Squad-style attach/detach TUI for named agent subprocesses, nor a VPS-first rootless Podman hardened image story. Good upstream contribution: rootless Podman/VPS compatibility, hardened base images, git-auth/secrets recipes. Poor upstream fit: turning it into cove’s session manager. Estimate: **1 weekend for docs/templates**, **2-4 weekends for first-class rootless Podman hardening**, merge probability **50-70%** if scoped to Dagger-compatible improvements.

**Vibe Kanban**
Verdict: **INTRACTABLE**

Repo: https://github.com/BloopAI/vibe-kanban. It has users, but stewardship is the problem. README now says “Vibe Kanban is sunsetting”: https://github.com/BloopAI/vibe-kanban/blob/main/README.md#L18-L21. The repo last pushed April 24, 2026, release `v0.1.44` was April 24, 2026, and there are hundreds of open issues/PRs. The open “is this project dead?” issue has users explicitly asking for maintainers and pointing to forks: https://github.com/BloopAI/vibe-kanban/issues/3408. Issue creation is restricted in the GitHub UI, and open PRs continue piling up after shutdown.

Adopting/reviving it solo is a trap unless the goal is to own a large Rust/TypeScript product with cloud/auth/UI/history baggage. It could be forked, but that is effectively a new product plus maintenance debt, not a contribution path.

**Recommendation**
Contributing upstream is a serious contender only if the goal is narrowed. For **cove’s original VPS-native session-manager thesis**, Claude Squad has the best technical seam but the worst maintainer signal; use it as architecture leverage, not as the default business path. For upstream contribution with real acceptance odds, contribute the rootless Podman/VPS hardening to **container-use**. If the developer wants the full attach/detach named-session experience, building cove remains justified; try a small Claude Squad RFC first, but do not bet the project on that merge.