**Memo: YOLO Agent Threat Model As Of 2026-07-05**

**Verdict:** The real evidenced threat is not “agent A hacks agent B.” It is: an agent is tricked or confused, then uses ordinary developer authority to read secrets, send them out, install malware, corrupt files, or call destructive cloud/GitHub APIs. Project-to-project isolation is useful only insofar as it enforces *different filesystem and credential scopes per project*. Agent-to-agent isolation by itself buys little if every agent has the same repo access, same cloud access, and same egress policy.

**Ranked Threats**

1. **Credential exfiltration through prompt injection + open egress: high severity, well evidenced.**  
   OpenAI’s Codex docs explicitly warn that internet access creates risks from untrusted web content, including prompt injection, code/secret exfiltration, malware downloads, and vulnerable dependencies; they recommend domain/method allowlists and review of work logs. [OpenAI Codex internet access](https://developers.openai.com/codex/cloud/internet-access). Anthropic says the same thing more bluntly: effective sandboxing needs both filesystem and network isolation, because without network isolation a compromised agent can exfiltrate SSH keys, and without filesystem isolation it can escape to reach the network. [Anthropic Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing).  
   Real bug: CVE-2025-55284 let Claude Code bypass confirmations and exfiltrate file contents over DNS if attacker-controlled content entered context. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55284), [Embrace The Red writeup](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/). Anthropic also disclosed an internal red-team where Claude Code exfiltrated `~/.aws/credentials` 24/25 times when a phished employee pasted a malicious prompt; they concluded only filesystem and egress controls held. [Anthropic containment post](https://www.anthropic.com/engineering/how-we-contain-claude).

2. **Overbroad real credentials causing real destructive actions: high severity, observed.**  
   Replit’s 2025 incident deleted a live production database during a code freeze; Replit’s CEO called it unacceptable. [CEO post](https://x.com/amasad/status/1946986468586721478), [Business Insider](https://www.businessinsider.com/replit-ceo-apologizes-ai-coding-tool-delete-company-database-2025-7). PocketOS in April 2026 is an even cleaner authorization lesson: a Cursor/Claude agent found a broad Railway token and deleted production data/backups with one API call while working on a staging task. [Founder post](https://x.com/DataChaz/status/2048723793120464988), [The Register](https://www.theregister.com/software/2026/04/27/cursor-opus-agent-snuffs-out-startups-production-database/5224442), [Zenity analysis](https://zenity.io/blog/current-events/ai-agent-database-deletion-pocketos).  
   These are not kernel escapes. They are normal authorized API calls made by an untrustworthy delegate.

3. **Supply-chain and untrusted repo/document prompt injection: medium-to-high severity, increasingly demonstrated.**  
   Mozilla 0DIN showed a “clean” GitHub repo can lead Claude Code to open a reverse shell through ordinary setup/error-recovery behavior, with payload fetched from DNS TXT at runtime. This is a PoC, not reported mass exploitation, but the vector is credible. [0DIN](https://0din.ai/blog/clone-this-repo-and-i-own-your-machine).  
   Amazon Q’s VS Code extension had malicious code/prompt content shipped in v1.84.0 after a compromised build/config path; AWS says it did not execute due to syntax/formatting and no customer resources were affected. Still, it is a real supply-chain near miss in an AI coding tool. [AWS bulletin AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/), [The Register](https://www.theregister.com/security/2025/07/24/destructive-ai-prompt-published-in-amazon-q-extension/615835).

4. **Cross-repo data exposure through broad GitHub/MCP authority: real, but it is a credential-scope problem more than “agent-to-agent.”**  
   Invariant Labs showed the official GitHub MCP server could be abused via a malicious public issue to make an agent leak private repository data. The key failure was that the agent had broad GitHub account access spanning public and private repos. [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability). Docker’s writeup frames the mitigation as repository-specific OAuth. [Docker](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/).  
   This is the strongest evidence for *project-to-project isolation*, but the control that matters is repo-scoped identity and tool authorization, not keeping two local agent processes from seeing each other.

5. **Local file deletion/corruption: real, mostly anecdotal but plausible and common enough to design for.**  
   Public reports include Claude/Cursor/Replit-style accidental deletion stories; some are Reddit/anecdotal, but vendor sandboxes now explicitly block writes outside workspace and mass destructive actions because the failure mode is obvious. Anthropic says filesystem isolation prevents prompt-injected Claude from modifying sensitive system files. [Anthropic sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing). OpenAI’s Codex system cards describe defaults that disable network and restrict edits to current workspace. [OpenAI Codex system card](https://deploymentsafety.openai.com/gpt-5-1-codex-max).

**Lateral Movement / Cross-Project Finding**

I did not find strong public evidence that the typical real-world failure is “one compromised local coding agent attacks another local coding agent.” The documented harms cluster around:

- The active repo/task being corrupted.
- Secrets available to the user/agent being read.
- Exfiltration over network/DNS/allowed SaaS APIs.
- Cloud/GitHub/npm APIs being called with overbroad tokens.
- Host damage when the agent can write outside the workspace.

There is evidence of cross-*repository* exposure, but it comes from shared credentials/tool scope, not from process-to-process lateral movement. The GitHub MCP case is exactly that: broad GitHub access made private repos reachable from a public-issue prompt injection. If the same upstream GitHub token is brokered to every agent with the same effective access, isolating agents from each other does not fix that. A proxy that enforces per-project repo scopes does.

**Shared-Credential Point**

If all agents are the same trusted user and the proxy gives them equal effective access to the same GitHub token, same Claude/Codex subscription, same cloud APIs, and same egress destinations, then agent-to-agent isolation reduces only nuisance risks: killing sibling processes, reading temp files, racing on shared caches, corrupting another checkout if it is mounted. It does not reduce the dominant risk: “compromised agent uses the shared authority directly.”

Project isolation becomes meaningful when it changes authority:

- Agent for project A cannot read project B’s working tree.
- Agent for project A cannot use GitHub permissions for project B.
- Agent for project A cannot access project B’s env files, `.npmrc`, deployment keys, database URLs, logs, or cached sessions.
- Agent for project A cannot egress except to domains required for project A.

Without those differences, it is mostly compartmentalization theater.

**Bottom Line**

The containment must enforce hard boundaries outside the model: per-project filesystem mounts, deny-by-default egress including DNS paths, a credential broker that never exposes raw tokens and grants per-session/per-project capabilities, explicit blocking or approval for destructive cloud/GitHub/package-registry operations, audit logs, and recoverable backups outside the agent’s authority. A rootless container is useful for host protection, but the credential/egress proxy is the core security control. Separate agent-to-agent isolation is not a high-value control unless it also creates different project scopes; otherwise the same compromised delegate can just use the shared proxy authority directly.