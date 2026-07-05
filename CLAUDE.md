# cove — project context for Claude

## Current state (2026-07-05): PIVOT IN PROGRESS

The bash tool in this repo is being retired. Decision made 2026-07-05 after a
four-stream research pass: pivot to a **greenfield Go rewrite — a self-hosted,
Linux-only session manager for sandboxed coding agents** ("tmux for sandboxed
agents"). Architecture is NOT settled — owner wants a fresh rearchitecture pass.

**Start here, in order:**
1. `docs/pivot/HANDOFF.md` — the decision, locked constraints, open questions,
   salvage list, process notes, next steps. Read this before doing anything.
2. `docs/pivot/RESEARCH.md` — full condensed findings from the research streams
   (codebase audit, competitive landscape, two Codex xhigh assessments).
3. `docs/pivot/UX-TEARDOWN.md` — competitor UX evidence; top-10 UX requirements;
   verified #1 ecosystem pain = knowing when an unattended agent needs input.
4. `docs/pivot/SPEC-DRAFT.md` — v0 spec draft (strawman for rearchitecture, NOT
   approved).
5. `docs/pivot/SPEC-REVIEW.md` — adversarial review of the draft: major-rework
   verdict, 5 mandatory changes, 3 required spikes. Treat as constraints.

Superseded (describe the OLD bash product; historical context only):
`README.md`, `docs/PRODUCT-PLAN.md`, `docs/IMPLEMENTATION-PLAN.md`,
`docs/runpod-vast-auth.md`. The `decisions/` records remain useful history.

## Hard constraints (owner-locked — see HANDOFF.md for the full list)

- Linux-only. Go, single binary preferred. Runs identically on workstation and VPS.
- Target hardware has NO `/dev/kvm` (cheap KVM-guest VPSes): rootless Podman v0
  backend, gVisor flagship tier, microVM only opportunistically. Pluggable backends.
- GPU support is obsolete — delete, don't extend.
- Sandbox filesystem CONTAINS the workspace at a canonical path (no host-CWD
  identity mount). Shared-vs-dedicated sandbox per agent is a user choice.
- Position honestly: "contained agent sessions", never "secure sandbox".
  Credential proxy + network allowlist are the security features that matter.

## Process (owner preference)

Claude acts as manager/architect and DELEGATES: Opus subagents for deep/design
work, Sonnet subagents for research, Codex xhigh (`codex exec -s
danger-full-access -c model_reasoning_effort=xhigh`, skill in
`~/.claude/skills/codex`) for adversarial second opinions. Surface decision points
with options — the owner decides. Never auto-commit.
