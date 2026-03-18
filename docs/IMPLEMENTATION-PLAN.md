# Cove — Implementation Plan

## Context

Cove is an isolated Podman container for running AI coding tools with full autonomy — install anything, modify anything, run anything — with limited blast radius on the host. Built on patterns from con/yolo and trailofbits/claude-code-devcontainer, adapted for rootless Podman + SELinux on Bazzite.

See [PRODUCT-PLAN.md](PRODUCT-PLAN.md) for design rationale and product decisions.

## Status

| Feature | Status |
|---------|--------|
| Dockerfile with full dev environment | Done |
| CLI wrapper (`cove`) | Done |
| Claude Code support | Done |
| Codex (OpenAI) support | Done |
| Kimi Code support | Done |
| Env var passthrough (API keys + `-e` flag) | Done |
| Git worktree detection | Done |
| Per-project config files | Future |
| GPU passthrough (AMD/NVIDIA) | Future |

## Implementation

### 1. Dockerfile

**Base:** `node:22` (Debian bookworm) — proven by yolo, good package availability, Node.js pre-installed.

**System packages (single apt layer):**
- Core: `git`, `sudo`, `tini`, `less`, `man-db`, `procps`
- Search/nav: `ripgrep`, `fd-find`, `fzf`, `jq`, `tree`
- Editors: `vim`, `nano`
- Shell: `zsh`
- VCS: `gh` (GitHub CLI)
- Misc: `unzip`, `gnupg2`, `shellcheck`
- For Claude native sandbox (optional): `bubblewrap`, `socat`

**git-delta** — installed from GitHub release `.deb` (like yolo).

**Language runtimes:**
- Python 3 + **uv** (curl installer) — fast, modern Python tooling
- **Go** (official tarball → `/usr/local/go`) — installed as root, then PATH set
- **Rust** via **rustup** (curl installer, minimal profile) — installed as non-root user
- **JDK 25** (Eclipse Temurin tarball → `/usr/local/java/temurin`) — set `JAVA_HOME`
- **GraalVM** for JDK 25 (Oracle GraalVM tarball → `/usr/local/java/graalvm`) — includes `native-image`; set `GRAALVM_HOME`
- Default `JAVA_HOME` points to GraalVM (superset of JDK); Temurin available via `JAVA_HOME=/usr/local/java/temurin`
- **.NET SDK 9** (Microsoft APT repo) — includes C#, F#, and `dotnet` CLI
- **OCaml** via **opam** (official installer) — includes `ocaml`, `opam`, `dune`
- **Erlang/OTP + Elixir** (Erlang Solutions APT repo) — includes `erl`, `elixir`, `mix`

**Build args for versions:**
```dockerfile
ARG CLAUDE_CODE_VERSION=latest
ARG GO_VERSION=1.24
ARG GRAALVM_VERSION=25
ARG EXTRA_PACKAGES=""   # space-separated, installed via apt-get
```

**AI coding tools:**
- Claude Code: `npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}`
- Codex: `npm install -g @openai/codex`
- Kimi Code: installed via uv with Python 3.13

**Non-root user:** Use the `node` user (UID 1000) from `node:22` base, add to sudoers with NOPASSWD.

**Cache directories:** Pre-create `/cache/{npm,uv,go-mod,cargo}` owned by node user.

**Environment variables:**
```dockerfile
# Cache redirection (persisted via named volume at runtime)
ENV NPM_CONFIG_CACHE=/cache/npm
ENV UV_CACHE_DIR=/cache/uv
ENV GOMODCACHE=/cache/go-mod
ENV CARGO_HOME=/cache/cargo

# npm supply chain hardening (from Trail of Bits)
ENV NPM_CONFIG_IGNORE_SCRIPTS=true
ENV NPM_CONFIG_AUDIT=true
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_MINIMUM_RELEASE_AGE=1440

# Performance
ENV NODE_OPTIONS=--max-old-space-size=4096

# Shell
ENV SHELL=/bin/zsh
ENV EDITOR=vim
```

**PATH additions:** `/cache/cargo/bin`, `/usr/local/go/bin`, `$JAVA_HOME/bin`, `$HOME/.local/bin`

**Java env:**
```dockerfile
ENV JAVA_HOME=/usr/local/java/graalvm
ENV GRAALVM_HOME=/usr/local/java/graalvm
```

**Entrypoint:** `tini --` (reap zombie processes from Claude-spawned tools).

**Default CMD:** `zsh` (shell; wrapper script overrides with specific tool).

---

### 2. Wrapper Script: `cove`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `cove claude [path] [args...]` | Launch Claude Code with `--dangerously-skip-permissions` |
| `cove codex [path] [args...]` | Launch Codex |
| `cove kimi [path] [args...]` | Launch Kimi Code |
| `cove shell [path]` | Drop into zsh in the container |
| `cove build` | Build/rebuild the image |
| `cove ps` | List running cove containers |
| `cove stop <name>` | Stop a running container |
| `cove exec <name>` | Exec into a running container |

**Core `podman run` invocation:**

```
podman run --log-driver=none -it --rm \
    --user="$(id -u):$(id -g)" \
    --userns=keep-id \
    --name="cove-${dirname}-$$" \
    \
    # Workspace (path-preserved)
    -v "$(pwd):$(pwd):Z" \
    -w "$(pwd)" \
    \
    # Tool config (auth persistence)
    -v "$HOME/.claude:$HOME/.claude:Z" \
    -v "$HOME/.codex:$HOME/.codex:Z" \
    -v "$HOME/.kimi:$HOME/.kimi:Z" \
    \
    # Git identity (read-only)
    -v "$HOME/.gitconfig:/tmp/.gitconfig:ro,Z" \
    \
    # Persistent cache volume
    -v "cove-cache:/cache" \
    \
    # Git worktree (if detected, bind original repo)
    ${WORKTREE_MOUNT} \
    \
    # Environment: API keys auto-passed + custom -e flags
    "${ENV_ARGS[@]}" \
    \
    cove \
    "${CMD[@]}"
```

**API key auto-passthrough:** ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, CODEX_API_KEY, KIMI_API_KEY, GOOGLE_API_KEY, MISTRAL_API_KEY, CLAUDE_CODE_OAUTH_TOKEN — each passed only if set in the host environment. Additional env vars via `-e VAR=value`.

**Git worktree detection** (simplified from yolo):
- If `.git` is a file (not dir), parse `gitdir:` line
- Extract original repo path from `.git/worktrees/` structure
- Auto-bind-mount the original repo

**Container naming:** `cove-${PWD_BASENAME}-$$` (strip invalid chars).

**`cove build`:**
```bash
podman build \
    --build-arg TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo UTC) \
    -t cove \
    "$SCRIPT_DIR"
```

**`cove ps`:** `podman ps --filter name=cove-`

**`cove stop`:** `podman stop <name>`

**`cove exec`:** `podman exec -it <name> zsh`

---

### Isolation Boundary

**What's NOT mounted:**
- `~/.ssh` — no SSH keys
- `~/.gnupg` — no GPG keys
- `~/` — no home directory
- Other repos — only the specified workspace

**Security model:**

| Layer | Mechanism |
|-------|-----------|
| Filesystem | Only workspace + tool config dirs + .gitconfig mounted |
| User namespace | `--userns=keep-id` (rootless Podman) |
| SELinux | `:Z` relabeling on all bind mounts |
| Processes | Container PID namespace |
| Network | Full access (API calls needed) |
| Inside container | `--dangerously-skip-permissions` (container IS the sandbox) |

---

## Future Work

**Per-project config files:**
- Support a config file (like yolo's `.git/yolo/config`) for project-specific settings
- Mount additional config dirs as new tools are added

**GPU passthrough:**
- AMD: `--device /dev/kfd --device /dev/dri --security-opt label=disable`
- NVIDIA: `--device nvidia.com/gpu=all --security-opt label=disable`

---

## Reference Projects Studied

- **con/yolo** (https://github.com/con/yolo) — Podman wrapper for Claude Code YOLO mode. Key patterns: `--userns=keep-id`, `:Z` SELinux labels, path preservation, git worktree detection, tini init, container naming.
- **trailofbits/claude-code-devcontainer** (https://github.com/trailofbits/claude-code-devcontainer) — Security-hardened devcontainer. Key patterns: npm supply chain defaults, `NODE_OPTIONS`, persistent named volumes, bubblewrap+socat for native sandbox, git-delta.
- **Claude Code sandbox docs** (https://code.claude.com/docs/en/sandboxing) — Official docs on Linux bubblewrap+socat sandboxing.

---

## Verification

1. **Build:** `cove build` — should complete without errors
2. **Shell test:** `cove shell` — should drop into zsh inside container, verify:
   - `whoami` shows correct user
   - `pwd` matches host CWD
   - `node --version`, `python3 --version`, `go version`, `rustc --version` all work
   - `git log` works in a git repo
   - `ls ~/` does NOT show host home files
3. **Claude test:** `cove claude` — should launch Claude Code in YOLO mode, verify:
   - Auth works (uses mounted ~/.claude)
   - Can read/write files in workspace
   - Can install packages (npm, pip)
4. **Codex test:** `cove codex` — verify Codex launches and authenticates
5. **Kimi test:** `cove kimi` — verify Kimi Code launches and authenticates
6. **Cache persistence:** Stop container, re-run, verify cached packages persist
7. **Install:** Copy `cove` to `~/.local/bin/cove`, verify it works from any directory
