---
title: Default image includes broad language coverage
date: 2026-03-19
status: accepted
---

The default image ships with Node.js, Python, Go, Rust, Java/GraalVM, .NET, Erlang/Elixir, and OCaml. This makes the image ~6 GB.

The purpose of cove is to let AI coding agents work autonomously on arbitrary projects. An agent asked to fix a bug in a Java project needs `javac`. An agent working on an Elixir project needs `mix`. If the toolchain isn't pre-installed, the agent either fails or wastes time installing it — both break the "just works" promise.

**Tradeoff:** Image size (~6 GB), build time (~10 min first build), and attack surface are all larger than a minimal image. Most users won't need every language in every session.

**Mitigations:**
- Heavy layers are cached by Podman and only rebuilt when `cove build` is run.
- The GPU variant (`Dockerfile.gpu-amd`) already demonstrates the pattern of dropping irrelevant languages — it excludes Java, .NET, Erlang, and OCaml since they're unused in GPU/ML workflows.
- A `minimal` variant could be added in the future following the same pattern.

**Rejected:** Minimal default image with on-demand language installation. This shifts the cost to every session rather than paying it once at build time, and relies on the AI agent successfully installing toolchains — which is fragile and slow.
