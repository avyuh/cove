Empirical investigation completed on 2026-07-05. I left the prototype scripts in [tmp-security-prototype](/home/dev/cove/tmp-security-prototype); I cleaned up the netns, host iptables rules, temp certs, and logs.

**Part 1 Verdict**

Transparent egress allowlisting is the genuinely generic mechanism.

Prototype: manual netns + veth + host NAT + namespace `iptables -t nat OUTPUT` redirects:

- all TCP from non-proxy users to a transparent TCP proxy
- all UDP/53 to a DNS interceptor
- proxy user `nobody` exempted to avoid redirect loops

Evidence:

```text
curl --noproxy '*' https://example.com -> HTTP/2 200
TCP ALLOW original=172.66.147.243:443 host='example.com'

curl --noproxy '*' https://www.google.com -> curl: (35) reset
TCP BLOCK original=142.250.191.196:443 host='www.google.com'

openssl s_client -connect 142.250.191.196:443 -> write:errno=104
TCP BLOCK original=142.250.191.196:443 host=None

manual UDP query to 1.1.1.1:
example.com rcode 0 answers 1
www.google.com rcode 3 answers 0
DNS ALLOW qname='example.com'
DNS BLOCK qname='www.google.com'
```

This captures programs that ignore `HTTP_PROXY`, including `curl --noproxy '*'`, direct sockets, and explicit DNS to `1.1.1.1`.

Robustness caveat: it is unbypassable only if the agent lacks `CAP_NET_ADMIN`, cannot alter the netns firewall/routing, and cannot join another network namespace. In a podman setup, enforce from outside the workload or run the workload without network-admin capabilities. Complexity is moderate: transparent TCP proxy + DNS policy + SNI parsing + IPv6 handling + UDP/QUIC decisions. I would block UDP/443 unless explicitly supported.

**Part 2 Verdict**

Transparent MITM credential injection works technically for simple bearer/API-key HTTP clients that trust a local CA, but it is not a universal credential-protection mechanism.

Claude Code test:

- No `ANTHROPIC_BASE_URL`.
- CLI targeted normal `api.anthropic.com`.
- Trusted test CA with `NODE_EXTRA_CA_CERTS`.
- Box had only `ANTHROPIC_API_KEY=dummy-cove-key`.
- Transparent MITM terminated TLS and returned synthetic 401.

Evidence:

```text
MITM_TLS_CLIENT_HELLO sni='api.anthropic.com'
MITM_HTTP request='POST /v1/messages?beta=true HTTP/1.1'
Host: api.anthropic.com
auth_present=False x_api_key_present=True

Claude debug:
API error: 401 ... "MITM test response after TLS accept"
```

So Claude Code accepted the MITM CA and did not cert-pin in this tested path. Anthropic’s docs also explicitly document custom CA support via OS store and `NODE_EXTRA_CA_CERTS`: https://code.claude.com/docs/en/network-config

Codex test:

- Codex v0.142.5 uses ChatGPT auth from `~/.codex/auth.json`; local auth file shape contained `id_token`, `access_token`, `refresh_token`, `account_id` without printing values.
- Official docs say Codex caches ChatGPT/API-key login locally in `~/.codex/auth.json` or credential store, refreshes ChatGPT tokens during use, and treats `auth.json` like a password: https://developers.openai.com/codex/auth
- Docs also state `CODEX_CA_CERTIFICATE` applies to login, HTTPS, and secure WebSocket connections.
- With a forged `chatgpt.com` cert signed by the test CA, Codex accepted MITM for `chatgpt.com`.

Evidence:

```text
Codex error:
unexpected status 401 Unauthorized: MITM test response after TLS accept
url: https://chatgpt.com/backend-api/codex/models?client_version=0.142.5

MITM log:
sni='chatgpt.com'
GET /backend-api/codex/models ... auth_present=True
GET /backend-api/codex/responses ... auth_present=True
POST /backend-api/codex/responses ... auth_present=True
```

So Codex CLI also accepted MITM for `chatgpt.com` when configured with its CA. But that does not solve “keep the credential out of the box” for ChatGPT OAuth. Codex needs cached OAuth/access/refresh material or an access token to decide it is logged in and to refresh. OpenAI’s access-token docs explicitly say these tokens represent the ChatGPT workspace user and must be treated as secrets: https://developers.openai.com/codex/enterprise/access-tokens

**Synthesis**

There is one truly generic control here: transparent egress allowlisting by destination host. It protects every credential type from exfiltration because the compromised CLI cannot choose an off-policy destination, even with raw sockets or proxy bypasses.

Credential injection is only conditionally generic:

- Works: simple HTTP bearer/API-key APIs, no cert pinning, no mTLS, no signed request binding, no protocol surprises.
- Breaks or becomes targeted: certificate pinning, mTLS client certs, OAuth/session refresh flows, WebSockets with stateful auth semantics, non-HTTP protocols, request signing, CLIs that refuse to start without local auth material.
- Claude-style API-key traffic can be protected with host-keyed MITM injection.
- Codex ChatGPT-OAuth cannot be made fully generic this way; its session credential is itself the thing the CLI uses to authenticate, refresh, and select workspace identity.

Recommendation: make transparent egress allowlist the generic foundation. Keep credential injection as a targeted optimization for known simple-bearer providers, implemented by host policy rather than CLI name where possible, but expect provider-specific auth adapters for OAuth/session CLIs like Codex. The honest split is: generic containment for exfiltration, targeted injection for keeping high-value keys out of the box.