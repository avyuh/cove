# Coding Sandbox — Implementation Plan

## Context

We want to run AI coding tools in an isolated Podman container on Bazzite where they have full autonomy — install anything, modify anything, run anything — without risk to the host system. We studied three reference projects (con/yolo, trailofbits/claude-code-devcontainer, Anthropic sandbox docs) and are building our own tool-agnostic solution.

**Viability: HIGH** — yolo proves this exact pattern works with rootless Podman + SELinux. All host infrastructure is in place (Podman 5.5.2 rootless, SELinux enforcing, 2.4TB free disk). No novel technical challenges.

## Phased Roadmap

| Version | Scope | Status |
|---------|-------|--------|
| **v1** | Claude Code + full dev environment | **This implementation** |
| v2 | Add Codex + Kimi Code | Future |
| v3 | AMD GPU passthrough (ROCm) | Future |

## v1 Implementation

### Files to Create

```
~/kritlok/htpc/coding-sandbox/
├── Dockerfile          # ~130 lines
└── sandbox             # ~300 lines, wrapper script → install to ~/.local/bin/
```

---

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

**Claude Code:** `npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}`

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

### 2. Wrapper Script: `sandbox`

Adapted from yolo's patterns, simplified for v1, designed for v2 extension.

**Subcommands:**

| Command | Description |
|---------|-------------|
| `sandbox run [path] [claude]` | Start container. No arg = shell, `claude` = Claude Code |
| `sandbox build` | Build/rebuild the image |
| `sandbox list` | List running sandbox containers |
| `sandbox stop [name]` | Stop a running sandbox |
| `sandbox shell [name]` | Exec into a running sandbox |

**`sandbox run` — core logic (stolen from yolo + our additions):**

```
podman run --log-driver=none -it --rm \
    --user="$(id -u):$(id -g)" \
    --userns=keep-id \
    --name="sandbox-${dirname}-$$" \
    \
    # Workspace (path-preserved)
    -v "$(pwd):$(pwd):Z" \
    -w "$(pwd)" \
    \
    # Claude config (auth persistence)
    -v "$HOME/.claude:$HOME/.claude:Z" \
    \
    # Git identity (read-only)
    -v "$HOME/.gitconfig:/tmp/.gitconfig:ro,Z" \
    \
    # Persistent cache volume
    -v "sandbox-cache:/cache" \
    \
    # Git worktree (if detected, bind original repo)
    ${WORKTREE_MOUNT} \
    \
    # Environment
    -e CLAUDE_CONFIG_DIR="$HOME/.claude" \
    -e GIT_CONFIG_GLOBAL=/tmp/.gitconfig \
    -e CLAUDE_CODE_OAUTH_TOKEN \
    \
    # Extra user-provided -v and -e flags
    "${EXTRA_ARGS[@]}" \
    \
    coding-sandbox \
    "${CMD[@]}"
```

**Tool dispatch:**
- `sandbox run .` → shell (`zsh`)
- `sandbox run . claude` → `claude --dangerously-skip-permissions`
- (v2: `sandbox run . codex` → codex CLI)
- (v2: `sandbox run . kimi` → kimi CLI)

**Git worktree detection** (simplified from yolo):
- If `.git` is a file (not dir), parse `gitdir:` line
- Extract original repo path from `.git/worktrees/` structure
- Auto-bind-mount the original repo (no interactive prompt — we're tool-agnostic, the AI tool needs git access)

**Extra volume/env passthrough:**
- Any flags before `--` are passed to podman (e.g., `sandbox run . claude -v ~/data:/data -e DEBUG=1`)

**Container naming:** `sandbox-${PWD_BASENAME}-$$` (strip invalid chars).

**`sandbox build`:**
```bash
podman build \
    --build-arg TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo UTC) \
    -t coding-sandbox \
    "$SCRIPT_DIR"
```
Where `$SCRIPT_DIR` is the directory containing the Dockerfile (resolved from script location).

**`sandbox list`:** `podman ps --filter name=sandbox-`

**`sandbox stop`:** `podman stop <name>`

**`sandbox shell`:** `podman exec -it <name> zsh`

---

### What's NOT mounted (isolation boundary)

- `~/.ssh` — no SSH keys
- `~/.gnupg` — no GPG keys
- `~/` — no home directory
- Other repos — only the specified workspace

### Security Model

| Layer | Mechanism |
|-------|-----------|
| Filesystem | Only workspace + ~/.claude + .gitconfig mounted |
| User namespace | `--userns=keep-id` (rootless Podman) |
| SELinux | `:Z` relabeling on all bind mounts |
| Processes | Container PID namespace |
| Network | Full access (API calls needed) |
| Inside container | `--dangerously-skip-permissions` (container IS the sandbox) |

---

## v2 Design Notes (future — not implemented now)

- Add `codex` and `kimi` CLI installations to Dockerfile
- Extend tool dispatch in wrapper script
- Mount additional config dirs (`~/.codex`, etc.)
- Per-project config file support (like yolo's `.git/yolo/config`)

## v3 Design Notes (future — not implemented now)

- `--amd-gpu` flag: `--device /dev/kfd --device /dev/dri --security-opt label=disable`
- `--nvidia` flag: `--device nvidia.com/gpu=all --security-opt label=disable`

---

## Reference Projects Studied

- **con/yolo** (https://github.com/con/yolo) — Podman wrapper for Claude Code YOLO mode. Key patterns stolen: `--userns=keep-id`, `:Z` SELinux labels, path preservation, git worktree detection, tini init, container naming.
- **trailofbits/claude-code-devcontainer** (https://github.com/trailofbits/claude-code-devcontainer) — Security-hardened devcontainer. Key patterns stolen: npm supply chain defaults, `NODE_OPTIONS`, persistent named volumes, bubblewrap+socat for native sandbox, git-delta, `bypassPermissions` mode.
- **Claude Code sandbox docs** (https://code.claude.com/docs/en/sandboxing) — Official docs. Key info: Linux uses bubblewrap+socat, `enableWeakerNestedSandbox` for Docker (weakens security), Docker incompatible with sandbox (use `excludedCommands`), sandbox runtime available as npm package.

---

## Verification

1. **Build:** `sandbox build` — should complete without errors
2. **Shell test:** `sandbox run .` — should drop into zsh inside container, verify:
   - `whoami` shows correct user
   - `pwd` matches host CWD
   - `node --version`, `python3 --version`, `go version`, `rustc --version` all work
   - `git log` works in a git repo
   - `ls ~/` does NOT show host home files
3. **Claude test:** `sandbox run . claude` — should launch Claude Code in YOLO mode, verify:
   - Auth works (uses mounted ~/.claude)
   - Can read/write files in workspace
   - Can install packages (npm, pip)
4. **Cache persistence:** Stop container, re-run, verify cached packages persist
5. **Install:** Copy `sandbox` to `~/.local/bin/sandbox`, verify it works from any directory
