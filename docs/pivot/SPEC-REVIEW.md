# Adversarial Review of SPEC-DRAFT.md — Codex xhigh, 2026-07-05

**Verdict: Major rework. Do not approve.**

"The draft has the right market thesis, but the v0 architecture collapses back
into 'tmux plus rootless Podman' while deferring the actual differentiators:
attention state, durable lifecycle, credential proxy, deny-by-default egress, and
clean review workflow. That violates the differentiation bar."

## Technical holes

1. **Podman labels cannot be the sole state store.** Labels won't hold lifecycle
   state, attention state, teardown transactions, volume/network/worktree
   membership, tombstones, failed creates, branch cleanup. (`podman ps` without
   `-a` misses stopped sessions — the spec's own listing command is wrong.) Use
   labels only for reconciliation; add a durable per-session manifest or SQLite.
2. **"tmux-in-sandbox = free reconnect robustness" is false.** The UX teardown's
   strongest evidence says tmux is the *source* of notification loss (OSC
   swallowing), scrollback/rendering bugs, and phone/laptop resize corruption. It
   may demo well; it does not satisfy the product gap.
3. **`podman exec -it … tmux attach` + SIGWINCH is under-specified.** Three PTYs
   in the chain (client → Go wrapper → podman exec → tmux); resize propagation,
   tmux multi-client `window-size` behavior, and phone attach semantics are
   unproven. Needs an M0 proof gate, not an assumption.
4. **Forced-proxy network topology is not established rootless.** `--internal`
   bridge networks + pasta behavior (copies host routes by default) mean "only
   route is the sidecar" is not demonstrated; `HTTP_PROXY` env is not topology
   enforcement; transparent egress likely needs routing/NAT privileges rootless
   doesn't have. Spike required.
5. **gVisor is plausible, not presumable.** systrap avoids /dev/kvm, but rootless
   podman + runsc needs install/config, subuids, cgroup v2/systemd, and network
   validation on the target kernel. Spike BEFORE the spec leans on it.
6. **Credential interception over-optimistic.** `ANTHROPIC_BASE_URL` works for
   static API keys, but subscription **OAuth** flows are not cleanly proxyable
   (gateway must preserve OAuth capability headers); Codex auth is
   config/provider-based — `OPENAI_BASE_URL` alone is brittle. Static-key mode
   maybe; OAuth/account auth no.
7. **Injected CA is not universal.** Codex has its own CA env; git/gh/cargo/npm
   differ; pinned/bundled TLS clients ignore it. No "agents never hold raw keys"
   claim until a per-tool support matrix exists.
8. **Per-session `~/.claude` breaks auth unless seeded.** Empty per-session
   config volume = login every session. Spec handled history but not the auth
   bootstrap (seed credentials / `apiKeyHelper` / brokered auth).

## UX contradictions (vs UX-TEARDOWN top-10)

- Req #1 (needs-attention push) — never ships in the spec's M0/M1. Unacceptable.
- Req #2 (zero-dependency) — host podman/pasta(/runsc) + tmux-in-image required;
  be honest: "single cove CLI, host Podman required."
- Req #5 (sandbox as real git remote/branch) — spec only offers exec'd git diff.
- Req #6 (atomic confirmed teardown) — `rm --force` exists but no transaction
  model.
- Req #9 (survive drops/crashes/reboots) — conmon/tmux/labels alone don't cover
  reboot/linger/agent-dead-vs-session-alive.

## Scope realism

M0/M1 are not honest weekends for one person. Cut v0 to: durable session
manifest; `new/ls/attach/logs/diff/rm`; one sandbox per session; one image;
`--net open|none`; confirmed atomic teardown; basic doctor; **one minimal
attention signal**. Defer: `--net allow`, gVisor, sidecars, credential proxy,
devcontainer, export, full image, `--multi` — until the golden path is solid.

## Missing pieces

Resource caps (research flagged: 5+ agents thrash a small VPS); port/dev-server
handling; reboot/linger setup; session-dead vs agent-dead status; branch/worktree
conflict handling; shallow/submodule/LFS clones; auth seeding for Claude/Codex;
cleanup reconciliation; lifecycle failure tests.

## Top 5 mandatory changes (ranked)

1. Durable manifest/store + podman-label reconciliation (labels-only is out).
2. Needs-attention state + notifications into M0/M1, not v1.
3. Attach/resize/phone behavior = proof gate; stop claiming tmux solves it.
4. Remove allowlist/proxy/credential claims from the golden path until proven
   per tool (spike matrix first).
5. Define atomic session lifecycle (create/start/stop/rm with
   branch/worktree/volume/network cleanup + confirmed destructive actions).

External checks used: Podman `--internal`/pasta docs, gVisor rootless/platform
docs, Claude Code auth/gateway docs, OpenAI Codex auth/config docs.
