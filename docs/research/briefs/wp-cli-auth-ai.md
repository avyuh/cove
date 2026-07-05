You are reverse-engineering the authentication mechanisms of AI/model command-line tools, to classify how each one's credentials can be protected. Use web search + official docs aggressively (today 2026-07-05). Some are installed on this box (claude, codex, kimi) — inspect their config/auth files and --help where useful (REDACT any secret values to 4 chars; never print full tokens).

For EACH CLI below, determine precisely:
- AUTH MECHANISM: static API key / bearer token? OAuth user-session with refresh tokens? request signing? something else?
- CREDENTIAL STORAGE: which file/env/keyring, and the shape (redacted).
- PROXY & CA BEHAVIOR: does it honor HTTPS_PROXY? a base-URL override env (e.g. ANTHROPIC_BASE_URL / OPENAI_BASE_URL)? a custom CA env (e.g. NODE_EXTRA_CA_CERTS / CODEX_CA_CERTIFICATE / REQUESTS_CA_BUNDLE)? Does it cert-pin?
- ENDPOINTS/HOSTS it contacts.
- CLASSIFICATION into exactly one: (A) INJECTABLE = simple bearer/api-key over TLS, no pinning -> a host-keyed MITM proxy can inject the real key so the CLI holds only a dummy; (B) OAUTH-SESSION-LOCAL = uses an OAuth/session token it must read/refresh locally -> key must stay in the box, protect only by egress containment; (C) SIGNED/OTHER = request signing / mTLS -> key must stay local.

CLIs: 
1. claude (Anthropic Claude Code)
2. codex (OpenAI Codex CLI)
3. kimi (Moonshot Kimi CLI)
4. gemini cli (Google Gemini CLI — note it supports BOTH Google-account OAuth AND API-key modes; cover both)
5. huggingface cli (huggingface-cli / hf)

OUTPUT: a table [CLI | auth mechanism | storage | honors proxy? | honors base-URL? | honors custom CA? | pins? | class A/B/C], plus a one-line note per CLI on what a credential-protecting local proxy CAN and CANNOT do for it. Cite doc URLs.