---
title: Image variants via separate Dockerfiles and env var selection
date: 2026-03-18
status: accepted
---

## Context

Adding GPU support raises a broader question: how should cove support multiple container image variants without accumulating per-variant complexity in the script and CLI?

GPU images differ from the default in fundamental ways — different base image, different package set, device passthrough at runtime. Future variants (GPU-NVIDIA, minimal, etc.) will diverge further. We need a design that scales.

## Decision

### Separate Dockerfiles per variant

Each variant gets its own Dockerfile following the naming convention `Dockerfile.<variant>`. The default remains `Dockerfile`. Each builds to image `cove-<variant>` (default builds to `cove`).

```
Dockerfile              → cove
Dockerfile.gpu-amd      → cove-gpu-amd
Dockerfile.gpu-nvidia   → cove-gpu-nvidia  (future)
```

Adding a new variant means adding a file. No script changes required for build.

### Image selection via `COVE_IMAGE` env var

```bash
cove claude                          # uses cove (default)
COVE_IMAGE=gpu-amd cove claude       # uses cove-gpu-amd
export COVE_IMAGE=gpu-amd            # set in profile for persistent use
```

The script resolves the image name as `cove${COVE_IMAGE:+-$COVE_IMAGE}`. GPU users set it once in their shell profile and forget about it.

### GPU device passthrough via prefix match

Variants starting with `gpu-` automatically get `--device /dev/kfd --device /dev/dri --security-opt label=disable` added to `podman run`. This is one `if` statement in the script and covers both AMD and NVIDIA.

### GPU Dockerfiles drop irrelevant languages

The default image includes Erlang, Elixir, OCaml, etc. — languages nobody uses for GPU/LLM work. GPU variants include only GPU-relevant tooling (Python, CUDA/ROCm, Go, Rust) and drop the rest to offset the size of GPU runtime libraries.

### ROCm base image uses Ubuntu, not Debian

ROCm officially supports Ubuntu 22.04/24.04 and RHEL 8/9. Debian is not supported. Since the container only needs ROCm userspace libraries (the kernel driver runs on the host), the container OS must be one AMD builds packages for. The default image staying on Debian (node:22) is fine — they are independent images with no shared layers.

## Deliberations

### Single parameterized Dockerfile vs separate files

A single `Dockerfile` with `ARG BASE_IMAGE` and conditionals (`if [ "$BASE" = "rocm" ]...`) was considered. Rejected because:

- GPU and default images differ in base OS (Ubuntu vs Debian), installed languages, and package names. Conditionals would proliferate.
- NVIDIA would add a third branch with its own base and packages.
- Separate files are easier to read, test, and modify independently.
- No shared-layer benefit anyway since base images differ.

### `--gpu` / `--image` CLI flag vs env var

A `--gpu` flag was the initial proposal. Problems:

- GPU users would need it on every invocation — tedious.
- `--gpu` is too specific; `--image gpu-amd` is more general but still per-invocation friction.
- A flag implies per-run choice, but image selection is really a user/machine preference.

`COVE_IMAGE` env var is better: set once, applies everywhere, zero ongoing friction. One-off use is still easy (`COVE_IMAGE=gpu-amd cove claude`).

### Bind-mounting host GPU libraries vs including them in the image

Considered mounting host ROCm libraries into the container to avoid a separate image. Rejected because:

- Host (Bazzite/Fedora) uses non-standard ROCm paths (`/usr/lib64/rocm/`) vs the canonical `/opt/rocm` that tools expect.
- Version coupling between host and container is fragile.
- Different distro library layouts cause hard-to-debug failures.

### Config file per variant vs prefix-match for runtime flags

Considered placing a `cove.conf` alongside each Dockerfile to declare extra `podman run` flags. Rejected as overengineered for now — the only runtime difference is GPU device passthrough, and a prefix match on `gpu-*` handles it. Can revisit if a non-GPU variant needs custom runtime flags.

### NVIDIA support scope

Deferred. NVIDIA uses a completely different mechanism (CDI via `nvidia-container-toolkit`, `--device nvidia.com/gpu=all`). No hardware to test. The variant system accommodates it — `Dockerfile.gpu-nvidia` and `COVE_IMAGE=gpu-nvidia` will work without design changes. The `gpu-*` prefix match for device flags will need a branch for NVIDIA-specific flags, but that is one `case` statement.
