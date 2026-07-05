**Verdict: NARROWED, bordering on REFUTED**

The claimed “open market gap” is no longer broad. Since June 2026, the space has filled in from both sides: Docker/Anthropic/OpenAI are absorbing sandbox, cloud, remote, worktree, and notification primitives; independent tools now cover most of the four-way bundle. The remaining gap is narrower: a polished, Linux/VPS-first, self-hosted, security-serious `tmux`-style operator experience that combines Docker/microVM-grade isolation with durable multi-agent UX. That is not an empty market; it is a crowded wedge with fast vendor encroachment.

**Live Competitors**

| Tool | Stars / Activity | Self-host | VPS / remote | Sandbox | Multiplex |
|---|---:|---|---|---|---|
| [Imbue mngr](https://github.com/imbue-ai/mngr) | 387, pushed Jul 4 | Yes | Yes: SSH/remote hosts | Partial/yes: containers/sandboxes | Yes |
| [Coder Mux](https://github.com/coder/mux) | 1.9k, pushed Jul 4 | Yes | Yes: SSH remote compute | Partial: workspaces/worktrees, not clearly container isolation | Yes |
| [Dagger container-use](https://github.com/dagger/container-use) | 3.9k, pushed Jun 12 | Yes | Partial | Yes: per-agent containers/worktrees | Partial: agent env layer, not session manager |
| [Docker sbx](https://docs.docker.com/ai/sandboxes/) | 215, pushed Jul 5 | Partial: Docker account/tooling | Yes on Linux/Ubuntu | Yes: per-agent microVM, daemon/fs/network | No |
| [Sculptor](https://github.com/imbue-ai/sculptor) | 194, pushed Jul 5 | Yes | Partial: remote backend experimental | Partial/yes: isolated workspaces, container backend | Yes |
| [Conductor](https://www.conductor.build/) | closed app; releases Jul 3 | No | No/Mac-first | Partial: git worktrees | Yes |
| [amux](https://github.com/mixpeek/amux) | 279, pushed Jul 5 | Yes | Yes via browser/phone + tmux | No/partial | Yes |
| [pocketdev](https://github.com/0xMassi/pocketdev) | 92, pushed Jun 30 | Yes | Yes: VPS + Tailscale + tmux | Partial: “sandbox” setup, not clear hard isolation | Partial |
| [ACFS](https://github.com/Dicklesworthstone/agentic_coding_flywheel_setup) | 1.5k, pushed Jul 3 | Yes | Yes: Ubuntu VPS bootstrap | Partial | Yes |
| [claude-squad](https://github.com/smtg-ai/claude-squad) | 8.0k, pushed Jun 17 | Yes | Yes over SSH/tmux possible | No built-in real sandbox | Yes |
| [Vibe Kanban](https://github.com/BloopAI/vibe-kanban) | 27.3k, sunset Apr 10 | Yes/local now | Partial | Worktrees only | Yes |

GitHub stats above were checked via GitHub API on 2026-07-05.

**Vendor Obsolescence Risk: HIGH**

Anthropic is the bigger threat. Claude Code now has native sandboxed Bash on macOS/Linux/WSL2 with OS-level filesystem/network controls, `/sandbox`, Linux `bubblewrap`, and managed settings ([docs](https://code.claude.com/docs/en/sandboxing)). Claude Code desktop supports background tasks, remote cloud sessions that continue after the computer is off, monitoring from web/iOS, and moving local sessions to the web ([desktop docs](https://code.claude.com/docs/en/desktop)). Hooks include notification events for “needs input” ([hooks guide](https://code.claude.com/docs/en/hooks-guide)). Changelog entries show active investment in background agents/sessions and tmux edge cases ([changelog](https://code.claude.com/docs/en/changelog)).

OpenAI is also closing the loop. Codex has cloud tasks in containers, background/parallel cloud work, worktrees for independent tasks, remote connections, notifications when tasks need attention, SSH host support, app-server remote TUI, hooks, and `codex cloud exec` ([cloud](https://developers.openai.com/codex/cloud), [remote connections](https://developers.openai.com/codex/remote-connections), [worktrees](https://developers.openai.com/codex/app/worktrees), [CLI features](https://developers.openai.com/codex/cli/features), [hooks](https://developers.openai.com/codex/hooks)). The open opportunity is not “vendors lack this”; it is “some users distrust vendor cloud and want Linux self-hosting.”

**Graveyard Forensics**

| Tool | Status | Cause | Evidence |
|---|---|---|---|
| Vibe Kanban / Bloop | Company shut down Apr 10; project community-maintained | Business-model failure despite demand | Bloop says thousands used it daily, mostly free users, and they “couldn’t find a business model” ([announcement](https://vibekanban.com/blog/shutdown)) |
| Omnara legacy | Archived Feb 2; migrated to new platform | Execution / dependency fragility | README says wrapping Claude Code CLI became unmaintainable because Claude Code changed constantly ([repo](https://github.com/omnara-ai/omnara)) |
| Crystal | Deprecated Feb 2026, replaced by Nimbalyst | Pivot/repositioning, not demand desert | README says Crystal is now Nimbalyst; replacement keeps worktree isolation and orchestration ([repo](https://github.com/stravu/crystal)) |
| Daytona OSS | Production code closed Jun 11 | Security/business-model change, not demand failure | Daytona says open isolation code became too risky as AI finds vulns; existing OSS frozen ([post](https://www.daytona.io/dotfiles/updates/daytona-is-going-closed-source)) |
| Terragon | OSS repo says “formally known,” remote background orchestrator | Likely execution/pivot | Repo describes it as a past remote background agent orchestrator, no releases, last push Feb 2026 ([repo](https://github.com/terragon-labs/terragon-oss)) |

This does not look like a pure demand desert. It looks like demand exists, but products die from monetization, maintenance against fast-moving vendor CLIs, or security liability.

**Demand Evidence**

FOR durable demand: users are explicitly building/using VPS + tmux + remote Claude/Codex setups. A recent r/ClaudeAI post describes a VPS, Tailscale, tmux persistence, phone access, and multiple agents; commenters compare it against Anthropic remote control and note advantages like multiple VMs and tmux sessions ([Reddit](https://www.reddit.com/r/ClaudeAI/comments/1uj2tlw/i_code_from_my_phone_now_claude_code_runs_on_a/)). r/selfhosted users discuss trusting self-hosted Claude/Codex runners, Proxmox VMs, ACLs, limited Gitea users, and network allowlists ([Reddit](https://www.reddit.com/r/selfhosted/comments/1u2jcep/what_would_you_require_before_trusting_a/)). There are multiple small repos targeting VPS/tmux/multi-agent workflows, including `pocketdev`, `ACFS`, `amux`, and AWS’s `cli-agent-orchestrator`.

AGAINST broad demand: the explicit four-way ask is rare. Most users ask for one or two pieces: phone access, persistent sessions, parallel worktrees, or safer YOLO mode. Many are satisfied by official Claude Code web/cloud sessions; one HN commenter says they run 2-3 Claude Code web sessions from phone and it “works really well” ([HN](https://news.ycombinator.com/item?id=46491486)). Conductor/Sculptor/Mux users generally accept desktop/worktree isolation, not hardened VPS-native containers. The market seems fragmented into power users, not a single obvious mainstream product.

**Bet**

I would not spend solo-dev months building this as a broad product. The obvious surface is already crowded and vendors are eating it quickly. A solo dev could still win a narrow wedge: Linux/VPS-first, boringly reliable, auditable, BYO Docker/microVM isolation, works over SSH/tmux, no cloud dependency, no wrapper fragility, excellent diff/review/notification UX. But that is infrastructure plus security maintenance, not a weekend app. As a business, I’d only build it if the target is power users/teams who explicitly reject vendor cloud; otherwise I’d ship integrations around `mngr`, Docker `sbx`, or Codex/Claude hooks instead of trying to own the whole stack.