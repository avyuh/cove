# cove

Rootless Podman container for running AI coding tools in fully autonomous mode.

## Supported tools

- **Claude Code** (`cove claude`) — runs with `--dangerously-skip-permissions`
- **Codex** (`cove codex`) — runs with `--yolo`
- **Kimi Code** (`cove kimi`) — runs with `--yolo`

All tools launch in fully autonomous mode by default. The container limits blast radius — tools can only access the mounted workspace and config directories, not the rest of your host.

## Usage

```bash
cove claude                    # Claude Code in current directory
cove codex                     # Codex in current directory
cove kimi                      # Kimi Code in current directory
cove claude ~/project          # Run in a specific directory
cove claude --resume           # Pass args through to the tool
cove shell                     # Interactive shell (no AI tool)
cove claude -e MY_KEY=secret   # Pass extra env vars
```

## GPU support

```bash
cove build gpu-amd                   # Build the AMD GPU variant
COVE_IMAGE=gpu-amd cove claude       # Run with GPU access
export COVE_IMAGE=gpu-amd            # Or set once in shell profile
```

Requires AMD GPU with ROCm support. Device passthrough (`/dev/kfd`, `/dev/dri`) is automatic. The GPU image includes ROCm 7.1.1, ollama, and GPU-relevant dev tools. Default image is unaffected — GPU base is only pulled when you build it.

## Management

```bash
cove build                     # Build/rebuild container image
cove build gpu-amd             # Build a specific variant
cove upgrade                   # Pull latest and rebuild all images
cove ps                        # List running coves
cove stop <name>               # Stop a cove
cove exec <name>               # Attach to running cove
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/avyuh/cove/master/install.sh | bash
```

Or manually:

```bash
git clone <repo> && cd cove
./cove build
ln -sf "$(pwd)/cove" ~/.local/bin/cove
```

Requires: `git`, `podman` (rootless).

## What's inside

Node 22, Python 3 + uv, Go, Rust, Java 25 + GraalVM, .NET 9, Erlang/Elixir, OCaml, Claude Code, Codex, Kimi Code, gh, ripgrep, fzf, jq, git-delta, vim, zsh.

## Trust boundary

The container is **not** a security sandbox. It limits blast radius, not access.

**What tools CAN access:**
- Workspace directory (read-write)
- `~/.claude`, `~/.codex`, `~/.kimi` (auth/config, read-write)
- `~/.gitconfig` (read-only)
- API keys passed via environment
- Full network access
- Git worktree parent repo (if workspace is a worktree)

**What tools CANNOT access:**
- Home directory (beyond the above)
- `~/.ssh`, `~/.gnupg`, host credentials
- Other projects outside the mounted workspace
- Host system files, other containers

**npm scripts** are disabled by default (`NPM_CONFIG_IGNORE_SCRIPTS=true`) as a supply chain hardening measure. Override per-install with `npm install --ignore-scripts=false` when a package needs postinstall scripts.
