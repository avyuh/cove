# UX Teardown of Adjacent Tools — 2026-07-05 (Sonnet research, web-sourced)

Input to the rearchitecture pass. Evidence from GitHub issues, docs, HN/Reddit/blogs
as of July 2026. Companion to `HANDOFF.md` and `RESEARCH.md`.

## 1. claude-squad (~8k stars, Go TUI over tmux + git worktrees)

**Install friction**: brew or curl installer; hard runtime deps on tmux AND gh that
the formula does not declare (issue #116 rejected declaring them) → silent first-run
failures. Windows essentially broken (#275, #291, #63).

**Golden path**: `cd repo && cs` → `n` new session (worktree+branch+tmux pane),
`↵/o` attach, `ctrl-q` detach (agent keeps running), `tab` diff view, `s` commit &
push, `c` pause/checkout (keeps work) vs `r` resume, `D` kill (destroys
worktree+branch, NO confirmation).

**Steal**: (1) pause-vs-kill two-key lifecycle ("step away" vs "discard");
(2) diff-first review embedded in the session list (`tab`); (3) agent-agnostic
subprocess model (`-p "<any agent command>"`).

**Avoid**: (1) synchronous git/tmux subprocess calls in the TUI render loop →
keystroke lag scaling with session count (#215/#249; #280 full diff held in memory
per session); (2) unconfirmed destructive delete — real data-loss reports
(#102, #44); (3) poll-vs-action races corrupting state (500ms poll running
`git add -N` concurrent with pause, #284; recurring tmux capture-pane errors
#189/#216/#218). Also: `-y` auto-yes unreliable (#151), single-repo assumption (#56).

## 2. Dagger container-use (per-agent containerized worktrees via MCP)

**Install friction**: real stack is Docker → auto-provisioned Dagger engine → `cu`.
MCP wiring per-editor; docs tell you to curl-append rules into CLAUDE.md so the
agent *remembers to use the tools*. No preflight doctor (#81).

**Golden path**: register `cu stdio` as MCP server; `cu list` (adjective-noun env
IDs like `modern-corgi`); `cu watch`; review via **stock git** — each env is a real
git remote/branch (`git diff container-use/<env>`); `cu terminal <env>` shells into
the live agent container; `cu merge/apply/delete`.

**Steal**: (1) sandbox exposed as a real git remote/branch — free diff/log/checkout
with tools users already know; (2) human-readable adjective-noun session IDs;
(3) terminal drop-in to a live agent container to inspect/unstick without killing.

**Avoid**: (1) broken/non-atomic cleanup (`cu delete` sometimes spawns a NEW env
(#110), leaves branches behind (#335)) — teardown must atomically remove
container+worktree+branch; (2) trusting the model to remember tool context —
community added a hook echoing "Remember to use container-use tools!" (#253);
enforce context server-side; (3) leaky lifecycle: orphaned stdio process holding a
repo lock (#300), CLI/engine version-mismatch surprises (#148), raw exit-128 git
edge cases (#89 no initial commit, #248 shallow clones, #41 signing, #142).

## 3. Docker Sandboxes (`sbx`) — the official product

**CLI** (docs.docker.com/reference/cli/sbx/): `sbx login` (mandatory Docker
account; picks default network posture) · `sbx run <agent>` / `sbx run --name <n>`
(named run doubles as reattach — no separate attach verb) · `sbx create` · `sbx
exec` · `sbx ls --json` · `sbx stop/rm` · `sbx secret set` · `sbx policy allow
network <domain>` · loopback-only SSH feature · `sbx ports`, `sbx diagnose` · bare
`sbx` opens a TUI dashboard.

**Requirements**: standalone ~50MB binary running microVMs (no Docker Desktop);
Linux needs Ubuntu 24.04+ WITH KVM — often unavailable under nested virt (our
exact target gap). Free core; paid org governance tier.

**Credential proxy**: secrets in host OS keychain; host-side egress proxy injects
auth headers so the agent never reads raw keys; deny-by-default network with three
postures + per-domain allow. Escape hatch = plaintext script inside the VM
(bypasses proxy). Real bugs shipped: tokens shown "managed" but not substituted
(#17, #278).

**Does NOT do (= our gap)**: no remote/VPS story — local CLI ↔ local `sandboxd`
only, SSH binds 127.0.0.1; fragile persistence (laptop sleep/wake wiped metadata
store, 7 running sandboxes invisible, #138); per-machine auth fatigue (#24);
`secret rm` broken → full reset wipes everything (#230).

**Steal**: named re-attachable sandboxes independent of cwd; header-injection
credential proxy; one-time network-posture choice + per-domain override.

## 4. tmux + DIY "Claude Code on a VPS" (the baseline we replace)

Pain ranked by evidence volume:
1. **Notification/attention gap — the #1 pain.** tmux eats Claude Code's OSC
   notification sequences unless DCS passthrough is configured (tmux ≥3.3
   `allow-passthrough`), which Claude Code doesn't do (claude-code #19976;
   `/terminal-setup` broken under tmux #6072). Verbatim user framing: "when Claude
   finishes and needs input, you have no way to know WHICH session needs attention
   without manually checking each one." 6+ independent tools exist solely to patch
   this (ccn, tap-to-tmux, cc-notifynub, Agent Deck, ntfy/Pushover/Telegram hook
   stacks).
2. **Scrollback/rendering wars**: Ink alt-screen + mouse capture vs tmux — wheel
   scrolls input history not output (#38810), alt-screen kills copy-mode (#67289,
   #63545), redraw corruption immune to Ctrl-L (#29937), scrollback silently lost
   (#42180, #4851). Design implication: own the scrollback buffer natively.
3. **Persistence that isn't**: tmux server killed on SSH logout by systemd session
   cgroups unless `loginctl enable-linger` (agent-deck #958); wrappers killing
   sessions on disconnect; agent OOM leaves "alive but dead" session with no signal.
4. **Reattach corruption**: size mismatch reattaching from phone vs laptop
   scrambles the TUI (#1495); multi-client attach forces smallest size on everyone.
5. **Naming/organization + contention**: no session↔task/branch binding; hand-rolled
   naming schemes; at 5+ agents shared ports/DBs/caches thrash (one practitioner cut
   16 agents → 2).

## 5. Omnara & Vibe Kanban (brief)

- **Omnara**: the one beloved feature at HN launch — push notification the instant
  the agent blocks, one-tap approve/answer from the phone. Repo archived Jan 2026;
  company pivoted. The need remains unserved in OSS.
- **Vibe Kanban** (27k stars, Bloop shut down Apr 2026 — business-model failure,
  not UX): validated (1) kanban board as top-level view — columns = running /
  needs-input / review / done scale better than a session list; (2) card =
  worktree + branch + dev server so parallel agents never collide; (3) dedicated
  per-card diff-review surface.

## Top 10 UX requirements (synthesized)

1. **First-class "needs attention" signal with push delivery** (built-in
   ntfy/webhook/Telegram sink + per-session state in the list) — the single most
   patched-around gap in the ecosystem.
2. **Zero-dependency single binary that IS the multiplexer** — no external
   tmux/gh/Docker-account required; onboarding failures of all three competitors
   deleted at a stroke.
3. **Rock-solid detach/reattach with per-client size handling** — phone reattach
   must never corrupt the TUI.
4. **Session = task + branch + sandbox**, human-readable names, reattach by name
   from anywhere.
5. **Each sandbox exposed as a real git remote/branch** — stock
   `git diff cove/<session>` for review, plus an embedded diff pane.
6. **Atomic, confirmed, complete teardown** — one destroy verb removes
   container+worktree+branch with y/n confirm; distinct pause vs kill.
7. **Async-everything UI** — no subprocess calls on the render loop; snappy at 20
   sessions.
8. **Credential proxy (agent never sees raw keys) + deny-by-default egress** chosen
   once, overridden per-domain — self-hosted, no vendor account.
9. **Survive SSH drops, crashes, reboots by design** — daemon outside the login
   cgroup (auto-handle enable-linger), distinguish session-alive from
   agent-process-dead, durable state store.
10. **Board/state overview** (running / needs-input / review / done), agent-agnostic
    per-session commands, sandbox/branch context enforced server-side rather than
    trusting the model to remember.

## Verified hypothesis

**"Knowing when an unattended agent needs input" is THE most-reported pain across
all five threads** — top DIY complaint (root-caused to tmux OSC/DCS passthrough),
Omnara's only beloved feature, partially answered by Vibe Kanban's needs-input
column and claude-squad's status column, unsolved by sbx for the remote case.
→ Notifications are a headline feature of the pivot, not a nice-to-have.
Runner-up: TUI scrollback/rendering conflicts — argues for owning the scrollback
natively instead of layering on tmux.
