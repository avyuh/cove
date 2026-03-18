FROM node:22

# ============================================================
# Build arguments
# ============================================================
ARG TZ
ARG CLAUDE_CODE_VERSION=latest
ARG GIT_DELTA_VERSION=0.18.2
ARG EXTRA_PACKAGES=""

ENV TZ="${TZ}"

# ============================================================
# System packages
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    sudo tini less man-db procps \
    # Search and navigation
    ripgrep fd-find fzf jq tree \
    # Editors
    vim nano \
    # Shell
    zsh \
    # Build tools (needed for language package compilation)
    build-essential pkg-config libssl-dev m4 \
    # Python development
    python3-dev python3-venv \
    # Misc
    unzip gnupg2 shellcheck \
    # Claude Code native sandbox support (optional)
    bubblewrap socat \
    # Erlang/OTP and Elixir
    erlang elixir \
    # OCaml
    ocaml opam \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# GitHub CLI (not in standard Debian repos)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && apt-get install -y --no-install-recommends gh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Extra packages (user-specified at build time)
RUN if [ -n "${EXTRA_PACKAGES}" ]; then \
        apt-get update && apt-get install -y --no-install-recommends ${EXTRA_PACKAGES} \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ============================================================
# Developer tools (installed as root)
# ============================================================

# git-delta (better diffs)
RUN ARCH="$(dpkg --print-architecture)" && \
    curl -fsSL "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" \
        -o /tmp/git-delta.deb && \
    dpkg -i /tmp/git-delta.deb && rm /tmp/git-delta.deb

# Go (auto-detect latest stable version)
RUN ARCH="$(dpkg --print-architecture)" && \
    GO_DL="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)" && \
    curl -fsSL "https://go.dev/dl/${GO_DL}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz

# JDK 25 (Eclipse Temurin)
RUN ARCH="$(dpkg --print-architecture)" && \
    case "${ARCH}" in amd64) JARCH=x64 ;; arm64) JARCH=aarch64 ;; esac && \
    mkdir -p /usr/local/java && \
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/25/ga/linux/${JARCH}/jdk/hotspot/normal/eclipse" \
        -o /tmp/temurin.tar.gz && \
    tar -C /usr/local/java -xzf /tmp/temurin.tar.gz && \
    mv /usr/local/java/jdk-* /usr/local/java/temurin && \
    rm /tmp/temurin.tar.gz

# GraalVM for JDK 25
RUN ARCH="$(dpkg --print-architecture)" && \
    case "${ARCH}" in amd64) GARCH=x64 ;; arm64) GARCH=aarch64 ;; esac && \
    curl -fsSL "https://download.oracle.com/graalvm/25/latest/graalvm-jdk-25_linux-${GARCH}_bin.tar.gz" \
        -o /tmp/graalvm.tar.gz && \
    tar -C /usr/local/java -xzf /tmp/graalvm.tar.gz && \
    mv /usr/local/java/graalvm-jdk-* /usr/local/java/graalvm && \
    rm /tmp/graalvm.tar.gz

# .NET SDK 9
RUN curl -fsSL https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb \
        -o /tmp/msft.deb && \
    dpkg -i /tmp/msft.deb && rm /tmp/msft.deb && \
    apt-get update && apt-get install -y --no-install-recommends dotnet-sdk-9.0 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================
# User and directory setup
# ============================================================

# node user gets passwordless sudo
RUN echo "node ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/node && \
    chmod 0440 /etc/sudoers.d/node

# npm global directory (writable by non-root user)
RUN mkdir -p /usr/local/share/npm-global && \
    chown -R node:node /usr/local/share/npm-global

# Persistent cache directories (volume-mounted at runtime)
RUN mkdir -p /cache/npm /cache/uv /cache/go-mod && \
    chown -R node:node /cache

# ============================================================
# Environment variables
# ============================================================

# Java
ENV JAVA_HOME=/usr/local/java/graalvm
ENV GRAALVM_HOME=/usr/local/java/graalvm

# Caches → persistent named volume at runtime
ENV NPM_CONFIG_CACHE=/cache/npm
ENV UV_CACHE_DIR=/cache/uv
ENV GOMODCACHE=/cache/go-mod

# npm supply chain hardening (from Trail of Bits)
ENV NPM_CONFIG_IGNORE_SCRIPTS=true
ENV NPM_CONFIG_AUDIT=true
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_MINIMUM_RELEASE_AGE=1440
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global

# Performance
ENV NODE_OPTIONS=--max-old-space-size=4096

# .NET
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1

# Shell
ENV SHELL=/bin/zsh
ENV EDITOR=vim
ENV DEVCONTAINER=true

# PATH
ENV PATH="/usr/local/share/npm-global/bin:/home/node/.cargo/bin:/usr/local/go/bin:${JAVA_HOME}/bin:/home/node/.local/bin:/home/node/.opam/default/bin:${PATH}"

# ============================================================
# Non-root installations
# ============================================================

USER node
WORKDIR /home/node

# uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Rust (minimal profile — keeps image smaller)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal

# Claude Code
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# Codex (OpenAI)
RUN npm install -g @openai/codex

# Kimi Code (requires Python 3.13)
RUN uv python install 3.13 && \
    uv tool install --python 3.13 kimi-cli

# OCaml: initialize opam and install dune build system
RUN opam init --auto-setup --disable-sandboxing -y && \
    opam install dune -y && \
    opam clean -a -c -s --logs

# ============================================================
# Entrypoint
# ============================================================

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["zsh"]
