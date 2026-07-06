# cove

cove is a credential firewall for locally run AI coding agents. It runs
contained agent sessions with no host HOME mount and sends outbound HTTPS
through a host-side proxy for allow/deny policy, credential injection, and audit
records.

## Supported tools

- **Claude Code** (`cove claude`) — runs with `--dangerously-skip-permissions`
- **Codex** (`cove codex`) — runs with `--yolo`
- **Kimi Code** (`cove kimi`) — runs with `--yolo`

All tools launch in fully autonomous mode by default. cove limits blast radius by
keeping the agent inside the mounted workspace and narrow configured mounts, not
the rest of your host.

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

## Runtime toolchains

For host-installed agent CLIs under nvm/volta/asdf, cove auto-resolves the
agent and `node` from your shell `PATH` and read-only mounts the narrow
toolchain directory into the box at the same absolute path. The box never mounts
your HOME. If auto-resolution misses a custom layout, add a narrow
`options.runtime_mount = ["~/.nvm/versions/node/v22.0.0"]` entry. Installing the
tool under `/usr/local/bin` is the max-isolation path and needs no runtime
mount.

## Codex ChatGPT Auth

Codex's ChatGPT login uses session files under `~/.codex`. To run current Codex
CLI versions through cove, opt in explicitly:

```toml
[options]
cred_mount = ["~/.codex:rw"]
```

The seed default remains `cred_mount = []`, and plain credential mounts remain
read-only. Use `:rw` for Codex only after accepting that concurrent cove Codex
sessions and host-side Codex can race while writing the same auth file.

## What's inside

Node 22, Python 3 + uv, Go, Rust, Java 25 + GraalVM, .NET 9, Erlang/Elixir, OCaml, Claude Code, Codex, Kimi Code, gh, ripgrep, fzf, jq, git-delta, vim, zsh.

## Trust boundary

cove is a **credential firewall** for **contained agent sessions**. It is meant
to keep host credentials out of the agent's filesystem and force network egress
through the proxy/audit path. It does not stop misuse of an allowed credential at
an allowed host, and it is not a defense against kernel escape.

**What tools CAN access:**
- Workspace directory (read-write)
- Narrow configured credential/runtime mounts
- Dummy API-key environment variables for proxy-injected services
- Allowed or injected HTTPS hosts through the cove proxy
- Git worktree parent repo metadata needed for the mounted workspace

**What tools CANNOT access:**
- Home directory outside configured narrow mounts
- `~/.ssh`, `~/.gnupg`, browser cookies, and unrelated host credentials
- Other projects outside the mounted workspace
- Arbitrary network destinations denied by policy

**npm scripts** are disabled by default (`NPM_CONFIG_IGNORE_SCRIPTS=true`) as a supply chain hardening measure. Override per-install with `npm install --ignore-scripts=false` when a package needs postinstall scripts.
