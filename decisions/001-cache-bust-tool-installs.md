---
title: Cache-bust only tool install layers on build
date: 2026-03-18
status: accepted
---

`cove build` should always get latest tool versions (Claude Code, Codex, Kimi). Users expect "build" to mean "give me the current thing."

Podman caches layers by instruction text. `npm install -g @anthropic-ai/claude-code@latest` looks identical across builds, so the cached (stale) layer is reused.

**Decision:** Use a `CACHE_BUST` build arg placed just before tool install layers. `cove build` passes `--build-arg CACHE_BUST=$(date +%s)`, invalidating only those layers. Heavy stable layers (Go, Java, Rust, system packages) stay cached.

**Rejected:** `--no-cache` on every build — wasteful, re-downloads everything. Separate `cove update` command — unnecessary if build does the right thing by default.
