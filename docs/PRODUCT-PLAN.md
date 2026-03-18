# Cove — Product Plan

## Goal

Run AI coding tools (Claude Code, Codex, Kimi Code, etc.) in an isolated Podman container on Bazzite where they have full autonomy — install anything, modify anything, run anything — with limited blast radius on the host.

## Name

**Cove** — a sheltered inlet. A safe, enclosed space where things can operate freely without affecting the open waters. The name captures the core idea: isolation that enables autonomy.

## Decision Summary

After evaluating 8 approaches (plain Podman, Distrobox, Toolbx, Dev Containers, Nix, Flatpak, systemd-nspawn, bubblewrap) and two existing projects (con/yolo, trailofbits/claude-code-devcontainer), we decided to:

**Build our own**, stealing the best ideas from yolo and Trail of Bits.

### Why not use yolo directly?
- yolo is Claude Code-specific (hardcodes `claude --dangerously-skip-permissions`)
- We need a **tool-agnostic container** that can run Claude Code, Codex, Kimi, or drop into a shell
- We want persistent cache volumes (yolo is ephemeral `--rm` by default)

### Why not use Trail of Bits devcontainer?
- Docker-centric — needs adaptation for rootless Podman + SELinux on Bazzite
- Heavier — requires `@devcontainers/cli` (Node.js tooling) on the host
- More moving parts than needed

### Why not Distrobox / Toolbx?
- They mount `$HOME` by default — no real isolation
- Designed for human convenience, not AI containment

### Why not Nix / Flatpak / systemd-nspawn / bubblewrap?
- Nix: solves reproducibility, not isolation
- Flatpak: designed for GUI apps
- systemd-nspawn: requires root, no OCI images
- bubblewrap: too low-level alone, can't install packages

## What We're Building

### Requirements

**Must have:**
- Full network access (API calls to cloud services)
- Full filesystem access WITHIN the container
- Mount specific host directories into the container (workspace)
- NO access to host files outside mounted directories
- Ability to install project-specific deps (node_modules, uv/pip, go modules, cargo)
- Support for multiple coding tools (Claude Code, Codex, Kimi Code, etc.)
- Easy to start — one command

**Like to have:**
- Persistent cache volume (avoid reinstalling deps every session) — **done**

**Ideas:**
- `cove update` — rebuild with latest tool versions (`--no-cache`)
- Multiple workspace mounts (`-v` passthrough)
- Per-project config file (`.cove`)
- `--amd-gpu` flag for AMD ROCm GPU passthrough (`--device /dev/kfd --device /dev/dri`)
- Network restrictions / iptables lockdown
- Supply chain protections

### Architecture

#### Base Image: `cove`

- **Base:** `node:22` (Debian) — better package availability, smaller than Fedora container images, host distro match not needed
- **Pre-installed tools:**
  - Node.js 22 (from base image)
  - Python 3 + uv (fast Python package manager)
  - Go
  - Rust (rustup)
  - Git, gh CLI, jq, ripgrep, fd, fzf, vim, zsh
  - tini (init process to reap zombies)
  - git-delta (better diffs)
- **Pre-installed coding AI tools:**
  - Claude Code (`@anthropic-ai/claude-code`)
  - Codex (OpenAI)
  - Kimi Code (if available as CLI)
  - Others as they become available
- **Non-root user** with sudo inside container
- **Entrypoint:** tini -> bash (or specified tool)

#### Steal from yolo:
- Podman invocation: `--userns=keep-id`, `:Z` SELinux labels
- Path preservation: mount CWD at its real host path (session compat)
- Git worktree detection
- `.gitconfig` mounted read-only
- `~/.claude` (and similar config dirs) mounted for auth persistence

#### Steal from Trail of Bits:
- Persistent named volumes for caches (`node_modules`, `uv`, `go mod`, `cargo`)
- npm supply chain defaults (`NPM_CONFIG_IGNORE_SCRIPTS=true`, `NPM_CONFIG_MINIMUM_RELEASE_AGE=1440`)
- `NODE_OPTIONS=--max-old-space-size=4096`

#### Wrapper Script: `cove`

Location: `~/.local/bin/cove`

```
Usage:
  cove claude [path] [args...]      # Launch Claude Code with --dangerously-skip-permissions
  cove codex [path] [args...]       # Launch Codex
  cove kimi [path] [args...]        # Launch Kimi Code
  cove shell [path]                 # Drop into shell in container (default: CWD)
  cove build                        # Build/rebuild the base image
  cove ps                           # List running containers
  cove stop <name>                  # Stop a container
  cove exec <name>                  # Attach to a running container
```

#### Mounts

| Host Path | Container Path | Access | Purpose |
|-----------|---------------|--------|---------|
| CWD | Same as host (path preserved) | Read-write | Workspace |
| `~/.claude` | Same as host | Read-write | Claude Code auth/config |
| `~/.gitconfig` | `/tmp/.gitconfig` | Read-only | Git identity |
| Additional via `-v` | User's choice | User's choice | Extra dirs |

#### Volumes (persistent, named)

| Volume | Purpose |
|--------|---------|
| `cove-cache` | npm, uv, go mod, cargo caches |

#### What's NOT mounted (isolation boundary)

- `~/.ssh` — no SSH keys
- `~/.gnupg` — no GPG keys
- `~/` — no home directory access
- Other repos — only the specified workspace

### Security Model

| Resource | Isolated? | Details |
|----------|-----------|---------|
| Filesystem | YES | Only workspace + config dirs mounted |
| Network | NO | Full access (needed for API calls) |
| Processes | YES | Own PID namespace |
| Users | YES | Non-root with sudo inside container |
| GPU | NO | Not passed through (v1) |

### Key Design Decisions

1. **Debian base, not Fedora** — container distro doesn't need to match host. Debian has better package availability and smaller images.
2. **Tool-agnostic** — the container installs multiple coding tools; the wrapper script selects which one to launch (or just drops to shell).
3. **Path preservation by default** — mount CWD at its real path so Claude Code sessions are compatible between container and native.
4. **Ephemeral containers, persistent caches** — container itself is `--rm`, but cache volume persists across runs so deps don't need reinstalling.
5. **No GPU in v1** — all coding AI tools are API-based, no local inference. Easy to add `--amd-gpu` later.

## Reference Projects

- **con/yolo**: https://github.com/con/yolo — Podman wrapper for Claude Code YOLO mode
- **trailofbits/claude-code-devcontainer**: https://github.com/trailofbits/claude-code-devcontainer — Security-hardened devcontainer
- **Claude Code sandboxing docs**: https://code.claude.com/docs/en/sandboxing
- **Anthropic sandbox-runtime**: https://github.com/anthropic-experimental/sandbox-runtime — Built-in bubblewrap sandbox

## Host Environment

- OS: Bazzite 42 (immutable Fedora 42, rpm-ostree)
- Podman: 5.5.2 (rootless)
- GPU: AMD Radeon RX 9060 XT (Navi 44, RDNA 4) — not used in v1
- Disk: 2.4 TB free
- Claude Code: already installed natively at ~/.local/bin/claude
