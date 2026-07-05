**Auth Modes**
Claude Code: Claude AI OAuth from `~/.claude/.credentials.json`, not `ANTHROPIC_API_KEY`. Access token shape redacted as `sk-a...GAAA`.

Codex: ChatGPT login OAuth from `~/.codex/auth.json`, `auth_mode=chatgpt`, `OPENAI_API_KEY=null`. Token shapes: access `eyJh...e6ac`, refresh `rt.1...Ma7M`.

**Verdicts**
Part 1, Claude Code: **PASS**. With a temp `HOME` containing only dummy OAuth tokens and `ANTHROPIC_BASE_URL=http://127.0.0.1:40249`, `claude -p "reply with the single word: ok"` returned `ok`. Proxy evidence:

```text
REQ POST /v1/messages?beta=true auth=Bear...oken x-api-key=<none>
RESP status=200
```

The proxy replaced the dummy bearer with the real Claude OAuth bearer in memory and forwarded to `https://api.anthropic.com`.

Part 2, Codex: **FAIL for ChatGPT-auth credential injection**. Codex with ChatGPT OAuth does not honor `OPENAI_BASE_URL` for the built-in provider. With dummy OAuth and `OPENAI_BASE_URL` pointed at the proxy, it still went directly to:

```text
https://chatgpt.com/backend-api/codex/models?client_version=0.142.5
wss://chatgpt.com/backend-api/codex/responses
```

A CONNECT logger with the real account showed Codex traffic to:

```text
github.com:443
chatgpt.com:443
ab.chatgpt.com:443
```

Using a custom `model_provider` with `base_url` is accepted, but it switches to API-key semantics and requires `OPENAI_API_KEY`; it did not use ChatGPT OAuth for that path. So a simple reverse proxy cannot inject ChatGPT-auth Codex credentials unless you do TLS interception or modify/wrap Codex’s ChatGPT backend transport. A scoped API key path through a custom provider is the cleaner architecture if Codex must use header injection.

Part 3, egress socket bridge: **PASS**. Rootless podman `--network=none` container, mounted Unix socket, `socat` bridge to `127.0.0.1:3128`, deny-by-default CONNECT proxy:

```text
github.com: allowed, curl rc 0, HTTP/2 200
example.com: denied, curl rc 56, CONNECT tunnel failed 403
direct raw IP with --noproxy: rc 7, could not connect
```

Proxy evidence:

```text
EGRESS CONNECT github.com:443 verdict=ALLOW
EGRESS CONNECT example.com:443 verdict=DENY
```

**Bottom Line**
The architecture survives for Claude Code and for the container egress control. It does **not** survive unchanged for the owner’s current Codex auth, because ChatGPT-login Codex uses fixed `chatgpt.com` backend/WebSocket endpoints and ignores `OPENAI_BASE_URL` for that built-in auth path. For Codex, use API-key auth with a custom provider/base URL, or plan a different interception point than plain reverse-proxy header injection.

Cleanup completed: temp homes removed, Unix socket removed, temp podman image removed, proxy processes stopped. No full credentials were printed, and no real credentials were written to temp files.