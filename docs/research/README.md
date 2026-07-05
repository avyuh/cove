# cove — research & design trail

This directory is the full record behind [`../SPEC.md`](../SPEC.md), produced in a
single strategy-through-spec session (2026-07-05). It was run as a manager +
subagent-team process: a **fable** planner/architect, **OpenAI Codex xhigh**
workers for spikes and research, **Opus** subagents for alternative
exploration, and a second **fable** as adversarial reviewer.

**If you only read one thing:** [`../SPEC.md`](../SPEC.md) — the finished,
watertight engineering spec (verdict: IMPLEMENTABLE-AS-IS after 3 review rounds).
**If you want the "why":** [`FINAL-DESIGN.md`](FINAL-DESIGN.md) — the consolidated
locked decisions the spec was written from.

## How the design landed (the short version)
Started as an open "archive vs pivot" reassessment; converged, through repeated
owner pushback, to: **cove is a credential firewall** — a single unprivileged Go
binary that runs each YOLO agent in an ephemeral kernel-namespace box (no podman,
no gVisor) with no secrets and no network route except one host-side proxy that
allowlists every destination by name and injects the keys the agent must never
hold, keyed by destination host so it is CLI-agnostic. Validated as the SOTA
pattern (= Docker Sandboxes' credential proxy), self-hosted and KVM-less.

## Consolidated design docs
| File | What it is |
|---|---|
| [`FINAL-DESIGN.md`](FINAL-DESIGN.md) | Authoritative locked decisions — the spec's source of truth |
| [`EVIDENCE-DIGEST.md`](EVIDENCE-DIGEST.md) | All spike facts in one place |
| [`CONVERGENCE.md`](CONVERGENCE.md) | The "one box, protect my keys" collapse |
| [`product-definition.md`](product-definition.md) | Earlier "safe-YOLO launcher" thesis |
| [`SYNTHESIS.md`](SYNTHESIS.md) | Wave-1 evidence + the (rejected) draft archive recommendation |

## Research & spike outputs (`*-out.md`)
Strategy / market
- [`wp-b-out.md`](wp-b-out.md) — market-gap refutation (narrowed→refuted; HIGH vendor-obsolescence)
- [`wp-h-out.md`](wp-h-out.md) — contribute-upstream recon (claude-squad, container-use, Vibe Kanban)

Feasibility envelope
- [`wp-probe-out.md`](wp-probe-out.md) — box capability probe (Docker sbx/gVisor/bwrap all blocked; only podman worked)
- [`wp-iso-design-out.md`](wp-iso-design-out.md) — isolation / topology / security design brief
- [`wp-cred-spike-out.md`](wp-cred-spike-out.md) — credential-proxy feasibility (claude inject PASS, codex-ChatGPT FAIL, egress PASS)
- [`wp-unblock-out.md`](wp-unblock-out.md) — bubblewrap + gVisor unblock spike
- [`wp-precode-out.md`](wp-precode-out.md) — pre-code spikes (crun-vs-runsc data, wss, mount overlay, token refresh)

Object model
- [`wp-topology-out.md`](wp-topology-out.md) — how power users actually run many parallel agents
- [`wp-threat-out.md`](wp-threat-out.md) — evidenced threat model (agent-vs-agent isolation = theater)

Foundational + SOTA
- [`wp-foundational-out.md`](wp-foundational-out.md) — kernel-namespaces-direct feasibility (the "drop podman" proof)
- [`wp-generic-cred-out.md`](wp-generic-cred-out.md) — transparent egress + host-keyed MITM (the "generic" answer)
- [`wp-sota-methods-out.md`](wp-sota-methods-out.md) — SOTA key-protection methods survey
- [`wp-cli-auth-ai-out.md`](wp-cli-auth-ai-out.md) — claude/codex/kimi/gemini/hf auth classes (A/B/C)
- [`wp-cli-auth-infra-out.md`](wp-cli-auth-infra-out.md) — hcloud/s5·aws/wrangler/runpod/gh auth classes

## `briefs/`
The prompt/brief each worker was given (the inputs matching the `*-out.md` above).

## `prototypes/`
- `lockbox/lockbox.c`, `maprange.c` — the **proven** kernel-namespace isolation prototype; the spec's syscall sequence (SPEC §13) is traced from it.
- `security/*.py` — throwaway prototypes proving transparent egress capture, DNS filtering, and host-keyed MITM injection (disposable).

## Not captured here
Some intermediate subagent outputs (the archive-steelman, motivated-reasoning
audit, and several fable design iterations + the 3 spec review rounds) existed
only in the session transcript; their conclusions are distilled into
`FINAL-DESIGN.md` and `../SPEC.md`.

## Superseded
The earlier `../pivot/*` docs (a Go *session-manager* pivot) and the original
bash-product docs (`../PRODUCT-PLAN.md`, `../IMPLEMENTATION-PLAN.md`, root
`README.md`) are superseded by this direction. `../../decisions/` remain useful
history.
