# cove

Isolated Podman container for running AI coding tools with full autonomy — no risk to host.

## Usage

```bash
cove claude                    # Claude Code in current directory
cove claude ~/project          # Claude Code in specific directory
cove claude --resume           # Pass args through to Claude
cove shell                     # Interactive shell
cove shell ~/project           # Shell in specific directory
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
git clone <repo> && cd cove
./cove build
ln -sf "$(pwd)/cove" ~/.local/bin/cove
```

## What's inside

Node 22, Python 3 + uv, Go, Rust, Java 25 + GraalVM, .NET 9, Erlang/Elixir, OCaml, Claude Code, gh, ripgrep, fzf, jq, git-delta, vim, zsh.

## How it works

- Rootless Podman, `--userns=keep-id`, SELinux `:Z` labels
- Workspace mounted at real host path (session compatible)
- `~/.claude` mounted for auth, `~/.gitconfig` read-only for git identity
- Persistent cache volume (`cove-cache`) for npm/uv/go modules
- Container is ephemeral (`--rm`), cache survives
- No access to `~/.ssh`, `~/.gnupg`, or home directory
- Auto-passes `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` if set on host
- Extra env vars via `-e KEY=value` flag
