As of 2026-07-05, local inspection plus official docs gives this classification:

| CLI | auth mechanism | storage shape | honors proxy? | honors base-URL? | honors custom CA? | pins? | class |
|---|---|---|---|---|---|---|---|
| `claude` OAuth | Claude account OAuth user session with access + refresh token | `~/.claude/.credentials.json`: `claudeAiOauth.accessToken=sk-a...`, `refreshToken=sk-a...`, `expiresAt`, `scopes` | Yes: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`; no SOCKS | Yes: `ANTHROPIC_BASE_URL` | Yes: OS store, `NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_CERT_STORE`; mTLS vars also supported | No evidence of pinning; docs support custom CA/TLS inspection | B |
| `claude` API key | Static Anthropic API key / auth token bearer | Env `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; `--bare` only reads API key/helper | Yes | Yes: `ANTHROPIC_BASE_URL` | Yes | No | A |
| `codex` ChatGPT login | ChatGPT OAuth/session tokens with refresh | `~/.codex/auth.json`: `auth_mode=chat...`, `tokens.id_token=eyJh...`, `access_token=eyJh...`, `refresh_token=rt.1...` or OS keyring | Likely yes for normal clients; doctor reports proxy env state; sandbox proxy separately supports upstream proxy | Yes: `chatgpt_base_url`, `openai_base_url` in `~/.codex/config.toml` | Yes: `CODEX_CA_CERTIFICATE`, fallback `SSL_CERT_FILE` | No evidence of pinning; custom CA applies to HTTPS and WSS | B |
| `codex` API key | Static OpenAI API key bearer | `codex login --with-api-key` caches in auth store, or `CODEX_API_KEY` for `codex exec`; custom providers use `env_key` | Likely yes | Yes: `openai_base_url` or custom `model_providers.*.base_url` | Yes | No | A |
| `kimi` OAuth | Kimi Code device OAuth with access + refresh token | `~/.kimi/credentials/<provider>.json` after login; docs say mode `600`; local box currently has no credential file | Not reliably: installed `aiohttp` client constructs custom certifi SSL connector and does not set `trust_env`; no proxy env documented | Yes: `KIMI_CODE_BASE_URL`, `KIMI_BASE_URL`; OAuth host `KIMI_CODE_OAUTH_HOST` / `KIMI_OAUTH_HOST` | No documented env; installed OAuth client uses certifi bundle directly | No evidence of pinning | B |
| `kimi` API key | Static bearer/API key for OpenAI-compatible Moonshot/Kimi API | `~/.kimi/config.toml`: `[providers.*] base_url`, `api_key`; or env `KIMI_API_KEY`; local config has no key | Not reliably/documented | Yes: config `base_url`, env `KIMI_BASE_URL` | No documented env | No evidence of pinning | A |
| Gemini CLI Google OAuth | Google account OAuth for Gemini Code Assist; refresh token via `google-auth-library` | `~/.gemini/settings.json`, `~/.gemini/google_accounts.json`; OAuth in OS keychain/hybrid encrypted file, legacy `~/.gemini/oauth_creds.json` | Yes: `HTTP_PROXY` / `HTTPS_PROXY` via config/proxy agents | Yes for Code Assist dev/test: `CODE_ASSIST_ENDPOINT`; gateway/base env also exists | Yes via Node runtime, typically `NODE_EXTRA_CA_CERTS` | No evidence of pinning | B |
| Gemini CLI API key | Static Gemini Developer API or Vertex AI API key; default header `x-goog-api-key`, optional bearer | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `.env`; or keychain service `gemini-cli-api-key` with `accessToken=<key>` | Yes: `HTTP_PROXY` / `HTTPS_PROXY` | Yes: `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_VERTEX_BASE_URL` | Yes via Node runtime, typically `NODE_EXTRA_CA_CERTS` | No evidence of pinning | A |
| `huggingface-cli` / `hf` | Hugging Face User Access Token bearer; browser login can retrieve/save token | `HF_TOKEN`, `HF_TOKEN_PATH`, default `~/.cache/huggingface/token`; optional git credential helper | Yes via Python HTTP stack standard env in practice | Yes: `HF_ENDPOINT` for Hub, `HF_INFERENCE_ENDPOINT` for inference API | Usually Python/httpx CA env such as `SSL_CERT_FILE` / `SSL_CERT_DIR`; older requests flows may use requests CA envs | No evidence of pinning | A |

Proxy notes:

- `claude`: a local MITM key-injecting proxy can protect `ANTHROPIC_API_KEY` mode; it cannot remove the need for local OAuth refresh/session material in Claude account mode.
- `codex`: proxy injection works for API-key/custom-provider mode; ChatGPT login needs local refreshable session state or a local `CODEX_ACCESS_TOKEN`.
- `kimi`: proxy injection is viable for static `KIMI_API_KEY` mode if you can force traffic through your proxy; OAuth mode still needs local refresh tokens and Kimi’s own HTTP client is not proxy-friendly by default.
- Gemini CLI: proxy injection works for `GEMINI_API_KEY`/`GOOGLE_API_KEY` mode; Google-account OAuth keeps refreshable credentials local.
- Hugging Face: proxy injection can substitute `HF_TOKEN` for Hub API calls; it cannot help if a workflow depends on browser-login token refresh semantics rather than a static user access token.

Sources: Anthropic Claude Code network/auth docs, OpenAI Codex manual, Kimi CLI docs/source, Gemini CLI docs/source, Hugging Face Hub docs. Key URLs:  
https://docs.anthropic.com/en/docs/claude-code/corporate-proxy  
https://docs.anthropic.com/en/docs/claude-code/iam  
https://developers.openai.com/codex/auth  
https://developers.openai.com/codex/environment-variables  
https://moonshotai.github.io/kimi-cli/en/configuration/config-files.html  
https://moonshotai.github.io/kimi-cli/en/configuration/env-vars.html  
https://moonshotai.github.io/kimi-cli/en/configuration/data-locations.html  
https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/resources/tos-privacy.md  
https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/configuration.md  
https://huggingface.co/docs/huggingface_hub/quick-start  
https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables