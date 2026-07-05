You are an independent adversarial researcher. Your job is to REFUTE, not confirm, a strategic claim. Bias toward skepticism; a previous team already talked itself into building this and may be wrong.

CONTEXT: A developer is deciding the future of a personal tool ("cove"). A prior research pass concluded there is a "genuine open market gap" for a **self-hosted, Linux/VPS-native, genuinely-sandboxed, tmux-like multiplexer for multiple AI coding agents** — i.e. persistent named agent sessions you SSH to on a cheap VPS, attach/detach, get notified when an agent needs input, review diffs, with per-agent container isolation. They cited: claude-squad (~8k stars, no sandboxing), Vibe Kanban (~27k stars, leaderless after Bloop shut down Apr 2026), Daytona (went closed Jun 2026), Omnara/Crystal (archived/deprecated early 2026), Docker sbx (microVM+credential-proxy but local/vendor-bound).

YOUR TASK — use web search aggressively (today is 2026-07-05). Try hard to REFUTE the gap claim by answering:

1. NEW ENTRANTS / MOVES since ~2026-06: Any new or updated tools that now serve this combination? Re-check claude-squad, container-use (Dagger), Docker sbx (did it get a Linux/remote/self-host story?), microsandbox, sculptor/Imbue, Sculptor, mux, uzi, terragon, conductor, vibe-kanban forks, sketch.dev, Ona (ex-Gitpod/Daytona), and anything else. Note stars/velocity/funding/activity.

2. VENDOR OBSOLESCENCE RISK: Are Anthropic (Claude Code) and OpenAI (Codex) shipping features that would make a third-party session manager redundant within ~12 months? Specifically research: Claude Code remote/teleport/web sessions, background tasks, notifications/hooks; Codex cloud sessions, Codex CLI notify. Rate obsolescence risk high/med/low with evidence.

3. GRAVEYARD FORENSICS: For each dead/pivoted adjacent tool (Omnara, Crystal, Vibe Kanban/Bloop, Daytona, others you find), classify the cause of death: (a) no real demand, (b) business-model/funding failure despite demand, or (c) execution failure. Cite evidence. The core question: is this a "gap = opportunity" or a "gap = demand desert where products go to die"?

4. DEMAND FORENSICS: Search HN, Reddit (r/ClaudeAI, r/LocalLLaMA, r/selfhosted), GitHub issues, X. Are real people explicitly asking for the FOUR-WAY combination (self-hosted + VPS + sandboxed + multiplexed)? Or are they only asking for narrower things (just notifications? just parallel worktrees? just a sandbox)? Where did the refugees from the dead tools actually go — did they adopt an alternative or just go back to raw tmux/CLI?

OUTPUT (write a tight, cited memo, ~1-2 pages):
- Verdict on the gap: CONFIRMED / NARROWED / REFUTED, with reasoning.
- Table of live competitors with the four capabilities as columns (self-host / VPS / sandbox / multiplex) marked yes/no/partial.
- Vendor obsolescence rating with evidence.
- Graveyard cause-of-death table.
- Demand evidence: strongest signals FOR and AGAINST real durable demand, with links.
- One paragraph: if you had to bet, is building this a good use of a solo dev's weeks/months? Why or why not.
Be concrete and cite URLs. Do not hedge into mush — give a clear bottom line.