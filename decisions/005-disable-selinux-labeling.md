---
title: Disable SELinux labeling for all containers
date: 2026-03-19
status: accepted
---

All `podman run` and `podman build` commands use `--security-opt label=disable`. No `:Z` suffixes on bind mounts.

## Context

Bazzite (Fedora 42 + SELinux enforcing) blocks RELRO memory protection in rootless containers. This causes `tini`, `libc`, and `libcrypto` to fail with "cannot apply additional memory protection after relocation." The issue affects all containers, not just GPU variants.

Additionally, mounting `$HOME/.claude` (or any subdirectory of home) with `:Z` triggers "SELinux relabeling of /home/user is not allowed" because SELinux won't relabel paths under `/home`.

## Decision

Disable SELinux container labeling globally rather than trying to make `:Z` labels work conditionally.

## What we tried first

1. **`:Z` on all mounts** — failed when mounting home subdirectories and when running GPU containers with `--security-opt label=disable` (the two are incompatible).
2. **Conditional `:Z` via `zopt` variable** — only disabled for `gpu-*` variants. Added complexity (`:Z` vs `,Z` separator issues with `:ro` mounts) and still failed for the default image after a `podman system prune`.
3. **`:Z` for default, no `:Z` for GPU** — four iterations of variable naming (`selinux_suffix`, `slabel`, `zlabel`, `zopt`) trying to get the separator logic right. All unnecessary.

## Why this is acceptable

The `:Z` label's purpose is to relabel bind-mounted files so the container's SELinux context can access them. With `label=disable`, the container runs without an SELinux context, so relabeling is unnecessary. The container still runs rootless with user namespace isolation (`--userns=keep-id`), which provides the meaningful security boundary. SELinux labeling on top of that added no practical protection for this use case while causing persistent breakage.

## Build-time too

`podman build` also needs `--security-opt label=disable`. Without it, `apt-get install` of packages that trigger `systemctl` (like `systemd`) fails during post-install scripts with the same RELRO error. This only surfaces on full rebuilds (`--no-cache`), not cached builds.
