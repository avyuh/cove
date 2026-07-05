**Memo**

As of July 5, 2026, the dominant real-world pattern for high-parallelism coding-agent users is not “one VM per agent.” It is: one shared host, many terminal/tmux sessions, and one git worktree per task/session when agents touch the same repo.

Claude Code’s own docs now encode this: each session can run in its own worktree so edits “never touch files in another,” while coordination is handled separately by subagents or agent teams. It also says the desktop app creates a worktree for each new session automatically. Source: https://code.claude.com/docs/en/worktrees

**1. Topology In Practice**

The recurring topology is:

`single machine / dev server` -> `repo/project` -> `many worktrees/branches` -> `tmux pane/window or UI session per task/agent`

Concrete examples:

- `cmux`: “Run a fleet of Claude agents on the same repo — each in its own worktree.” It says Claude Code works best with “full ownership of the working directory,” and two agents in one checkout cause conflicting edits, dirty state, broken builds. https://github.com/craigsc/cmux
- `dmux`: creates a tmux pane per task, every pane gets its own git worktree and branch; supports Claude Code, Codex, OpenCode, Gemini, Copilot CLI, etc. https://github.com/standardagents/dmux
- `uzi`: explicitly targets “large numbers” of coding agents with automatic git worktree management, tmux session management, dev-server setup, and port management. https://github.com/devflowinc/uzi
- `workmux`: “Each worktree maps to a tmux window,” running the agent and configured commands, with status in the tmux window list. https://raine.dev/blog/introduction-to-workmux/
- `parallel-code`: “Ten agents. Ten branches. One afternoon,” with each task in its own git worktree. https://github.com/johannesjo/parallel-code
- Reddit user practice lines up: one r/ClaudeAI user says each task gets its own worktree/tmux session for isolation, resume, and clean review/merge. https://www.reddit.com/r/ClaudeAI/comments/1tp19x7/running_multiple_claude_code_sessions_in_parallel/
- Simon Willison describes the emerging behavior as engineers firing up several Claude Code or Codex instances “sometimes in the same repo, sometimes against multiple checkouts or git worktrees,” but flags review capacity as the natural bottleneck. https://simonwillison.net/2025/Oct/5/parallel-coding-agents/

There is a minority “shared working directory” camp. One Reddit user runs multiple Claude sessions in separate tmux windows against the same repo on `main`, trying to avoid overlapping blast radius, but others immediately point out collision risk. https://www.reddit.com/r/ClaudeCode/comments/1rae7sa/5_claude_code_worktree_tips_from_creator_of/

**2. Shared vs Isolated: What Users Want**

Users want isolation mostly for operational sanity, not because they distrust one agent more than another. The concrete fears are:

- agents overwriting each other’s files
- dirty working tree confusion
- merge conflicts discovered late
- port collisions
- shared DB/dev-service corruption
- missing `.env` / secrets / dependencies in fresh worktrees
- disk explosion from duplicated checkouts and build artifacts
- inability to review what happened

The strongest evidence: tools rarely isolate “agent identities”; they isolate the task’s filesystem/runtime.

Container tools exist, but they frame isolation as per task/environment. Dagger’s `container-use` gives each agent or task a fresh container and git branch, aimed at running multiple tasks or attempts in parallel. https://dagger.io/blog/agent-container-use/ and https://github.com/dagger/container-use

Complaints are practical. A Claude Squad issue asks for setup hooks because new worktrees lack `node_modules`, `.venv`, `.env`, secrets, unique ports, and Docker Compose namespaces. The proposer’s fix symlinks heavy dirs, copies env files, assigns ports, namespaces Compose, and creates per-worktree DB names. https://github.com/smtg-ai/claude-squad/issues/260

A Reddit port-tool author says multiple worktrees with Claude agents spinning up dev servers made them tired of hunting port conflicts and orphaned Docker containers. https://www.reddit.com/r/ClaudeCode/comments/1rxuota/i_made_a_cli_tool_to_track_the_localhost_ports/

**3. Unit Of Isolation**

The actual unit is usually:

- **per task / branch / worktree** for code edits
- **per task / worktree runtime** when services, DBs, ports, or dangerous commands matter
- **per project/repo** for shared context, credentials, setup, memory, and base environment
- rarely **per agent** as a durable object

Even when people say “each agent gets a worktree,” the worktree is tied to the task/branch. If the same agent runs another task, it gets another worktree. Claude Code docs also separate this: worktrees isolate file edits; subagents/agent teams coordinate work. https://code.claude.com/docs/en/worktrees

The cleanest community formulation from r/LocalLLaMA: “one worktree + disposable container per task,” leaving behind branch, touched-files summary, test log, and stop reason. https://www.reddit.com/r/LocalLLaMA/comments/1u99w8w/is_there_actually_a_good_way_to_orchestrate/

**4. Resource Patterns**

For ~30 sessions, the evidence argues against unconditional per-agent containers/worktrees with full dependencies.

Pain points:

- Cursor forum: a ~2GB repo created two automatic worktrees in 20 minutes totaling 9.82GB; over a week, 20+ worktrees consumed ~140GB. https://forum.cursor.com/t/windows-request-to-disable-automatic-worktree-creation-critical-disk-space-issue/146189
- Claude Squad issue: fresh worktrees can require “minutes + GBs of disk per session” for dependencies. https://github.com/smtg-ai/claude-squad/issues/260
- Users report human review as the real ceiling. One r/ClaudeCode user tried three feature agents in separate worktrees and felt stretched too thin, letting bad code through. https://www.reddit.com/r/ClaudeCode/comments/1qplamr/how_many_claude_code_instances_are_you_all_able/

So per-task isolation is popular, but only when paired with cleanup, shared caches/symlinks, port allocation, env propagation, and review tooling.

**Bottom Line**

For a single-user VPS running ~30 agent sessions across 10+ projects, the evidence favors a **flexible model with project as the stable parent and task/worktree/runtime as the isolation unit**. Do not make “agent” the primary sandbox object. A good model is: `Project` owns shared config, credentials policy, base image/dev env, caches, and memory; `Workspace/Task` owns a git worktree, branch, ports, DB namespace, logs, and optional disposable container; `AgentSession` is a process attached to a workspace. Default to per-project shared base environment plus per-task worktree. Add per-task container/runtime isolation when YOLO commands, services, DBs, ports, or untrusted code make blast radius meaningful. A single global sandbox is too coarse for multi-project secrets and runtime collisions; per-agent containers for all 30 sessions look heavier than what power users actually choose.