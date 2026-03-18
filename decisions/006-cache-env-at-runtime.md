---
title: Set cache path env vars at runtime, not in Dockerfile
date: 2026-03-19
status: accepted
---

`CARGO_HOME` is set via `-e CARGO_HOME=/cache/cargo` in the `podman run` command, not as `ENV CARGO_HOME` in the Dockerfile.

## Context

Setting `CARGO_HOME=/cache/cargo` as a Dockerfile `ENV` caused the `uv` installer and `rustup` to write binaries to `/cache/cargo/bin/` during `podman build` instead of `~/.local/bin/` and `~/.cargo/bin/`. Since PATH points to the default locations, `uv` and `cargo` became unfindable in subsequent build steps.

## Decision

Cache directory env vars that redirect tool storage should only be set at runtime (via `-e` in `podman run`), not at build time (via `ENV` in Dockerfile). At build time, tools should install to their default locations on PATH. At runtime, when the `/cache` volume is mounted, the env vars redirect caches to persistent storage.

**Build-time safe (set in Dockerfile):** `NPM_CONFIG_CACHE`, `UV_CACHE_DIR`, `GOMODCACHE` — these only affect package download caches, not where binaries are installed.

**Runtime only (set in podman run):** `CARGO_HOME` — this changes where `rustup`, `cargo`, and the `uv` installer place binaries, breaking PATH.

## Debugging note

This bug was hard to diagnose because podman's layer cache masked it. Cached layers from before the `CARGO_HOME` change had `uv` in the correct location. The bug only appeared on cache-busted rebuilds, and stale cached layers with the wrong `uv` location persisted across multiple `--no-cache` attempts due to `--build-arg TZ` differences between manual builds and `cmd_build()`.
