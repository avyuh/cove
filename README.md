# cove

Isolated Podman container for running AI coding tools with full autonomy — no risk to host.

## Supported tools

- **Claude Code** (`cove claude`) — runs with `--dangerously-skip-permissions`
- **Codex** (`cove codex`) — runs with `--yolo`
- **Kimi Code** (`cove kimi`) — runs with `--yolo`

All tools launch in fully autonomous mode by default. The container is the sandbox — tools get unrestricted access inside it while your host stays untouched.

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

## Management

```bash
cove build                     # Build/rebuild container image
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

## What's inside

Node 22, Python 3 + uv, Go, Rust, Java 25 + GraalVM, .NET 9, Erlang/Elixir, OCaml, Claude Code, Codex, Kimi Code, gh, ripgrep, fzf, jq, git-delta, vim, zsh.

## How it works

- Rootless Podman, `--userns=keep-id`, SELinux `:Z` labels
- Workspace mounted at real host path (session compatible)
- `~/.claude`, `~/.codex`, `~/.kimi` mounted for auth/config
- `~/.gitconfig` read-only for git identity
- Persistent cache volume (`cove-cache`) for npm/uv/go modules
- Container is ephemeral (`--rm`), cache survives
- No access to `~/.ssh`, `~/.gnupg`, or home directory
- Auto-passes `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `CODEX_API_KEY`, `KIMI_API_KEY` if set on host
- Extra env vars via `-e KEY=value` flag
