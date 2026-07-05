# Cove reassessment — synthesis of Wave-1 evidence + DRAFT recommendation (to be attacked)

Objective set by owner: RATIONAL, no attachment, archiving is a first-class outcome. Optimize primarily for the owner's PERSONAL UTILITY (external users a secondary bonus, not a goal). Time investable IF justified. Owner runs Claude Code + Codex semi-unattended on a cheap ARM64 KVM-guest VPS (no /dev/kvm, 4 cores, 7.5GB). On that box RIGHT NOW: only claude, codex, tmux, git, gh are installed — NO podman, go, runsc, claude-squad.

## Wave-1 evidence (4 workers, 4 angles, strongly convergent)

**WP-B market (codex, adversarial):** Gap NARROWED→bordering REFUTED. Vendor obsolescence HIGH: Claude Code ships native bubblewrap/Landlock sandbox, remote cloud sessions surviving shutdown, web/iOS monitoring, needs-input notification hooks; Codex ships cloud tasks, worktrees, SSH host, remote, notifications. ~8 live independent tools cover most of the 4-way bundle (Imbue mngr, Coder mux, container-use, Docker sbx, Sculptor, amux, pocketdev, ACFS). Graveyard cause-of-death is mostly business-model/security-liability, NOT pure no-demand — so demand exists but is small, fragmented, and served. Bet: would NOT spend solo-dev months on it as a product; a narrow Linux/VPS-first hardened wedge is possible but is "infrastructure + security maintenance, not a weekend app."

**WP-H upstream (codex):** claude-squad seam = session/tmux.TmuxSession.Start; container backend MVP 300-600 LOC but maintainers closed "sandboxed agents" as NOT PLANNED (merge 25-40%). container-use TRACTABLE+WELCOME for rootless-podman hardening (merge 50-70%) but it's not a session manager. Vibe Kanban INTRACTABLE (sunset, revival = trap). Upstream only wins if goal narrows.

**WP-F archive steelman (opus):** Dogfood gate FALSE on the box (agents run bare, no container runtime installed, zero recorded incidents, 3-month dormancy since Apr 6). Toolmaker trap already realized (40 commits fighting environment, none shipping WITH the tool). Every differentiator on a vendor roadmap. Archiving costs ~nothing (ideas preserved in docs). Archive is clearly correct IF owner cannot name one concrete instance where his current setup actually failed/blocked him.

**WP-I motivated-reasoning audit (opus):** 3 most-fragile load-bearing claims: (1) dogfood gate — contradicted by machine; (2) "four independent streams converged" — manufactured; sub-agents shared priors, 2 were same model; (3) "dramatically smoother / gVisor flagship" — unproven; SPEC-REVIEW itself says v0 defers every differentiator and collapses to tmux+podman. Trust docs as hypothesis, not decision.

## DRAFT RECOMMENDATION (this is what you must attack)

1. **Do NOT build the Go "tmux for sandboxed agents" session manager.** Desirability fails before feasibility: demand premise is contradicted by the owner's own machine; the differentiators are being commoditized by Anthropic/OpenAI/Docker faster than a solo dev can ship; the category is a well-executed graveyard.
2. **Archive cove-classic as a product.** Tag it, keep the docs/decisions for their recipes. Optionally do the trivial GPU-strip if the owner wants to keep the bash script as a personal convenience (O6-lite), but invest nothing further in it.
3. **The only rational build, if any, is tiny:** a ~50-line needs-input notification hook (Claude Code Notification/Stop hook -> ntfy/Telegram) + `loginctl enable-linger` + tmux. This captures the one verified real pain for the owner's personal use in an afternoon, with zero product ambition. An "agent pager" as a shared tool is optional and still small.
4. **Spikes (gVisor-rootless, forced-egress, credential-proxy) are NOT run** — they test feasibility of a build that desirability has already ruled out.
5. **One honest gate before finalizing:** ask the owner to name ONE concrete time his current setup (bare agents + tmux + native sandboxing) actually failed or blocked him. If he can't, archive is confirmed. If he can, that specific failure — not the pivot docs — defines the (small) thing worth building.

## Your job as reviewer
Attack this recommendation. Is it the motivated conclusion of agents that were explicitly told to prosecute the pivot? Where is the archive case weakest? What is the STRONGEST honest case to keep building something more than a hook? Am I under-weighting the "narrow self-hosted wedge for people who distrust vendor cloud" that even the market worker admitted survives? Is there a real security risk (unsandboxed agent + secrets + network) that the "no recorded incident" argument dangerously ignores? Give a verdict: ENDORSE / ENDORSE-WITH-CHANGES / REJECT, with the 3 changes that would most improve the recommendation.
