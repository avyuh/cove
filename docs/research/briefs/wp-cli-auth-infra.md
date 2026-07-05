You are reverse-engineering the authentication mechanisms of infrastructure/cloud command-line tools, to classify how each one's credentials can be protected by a local credential proxy. Use web search + official docs aggressively (today 2026-07-05).

For EACH CLI below determine: AUTH MECHANISM (static API key/bearer? OAuth? AWS SigV4 / request signing? mTLS?), CREDENTIAL STORAGE (file/env), PROXY & CA behavior (honors HTTPS_PROXY? custom CA bundle? cert-pinning?), ENDPOINTS, and CLASSIFICATION into exactly one:
(A) INJECTABLE = simple bearer/api-key over TLS -> a host-keyed MITM proxy can inject the real key, CLI holds only a dummy;
(B) OAUTH-SESSION-LOCAL = OAuth/session token must live locally;
(C) SIGNED/OTHER = request signing (e.g. AWS SigV4) or mTLS -> the client MUST hold the secret to sign each request, so a header-injecting proxy CANNOT keep the key out; only egress-containment + short-lived/scoped credentials help.

CLIs:
1. hetzner cli (hcloud)
2. s5 cli / S3 clients (s5cmd or the S3-compatible tool "s5" — cover AWS S3 SigV4 auth; this is the archetypal SIGNED case)
3. cloudflare cli (wrangler; note it supports OAuth login AND API-token; cover both) and flarectl
4. runpod cli (runpodctl)
5. aws cli (reference for SigV4 + STS short-lived creds)
6. gh (GitHub CLI, reference)

Pay special attention to the SIGNED class: explain precisely why a proxy cannot inject a SigV4 credential (the signature is computed over the request using the secret key, client-side), and what the SOTA alternative is (STS/short-lived scoped creds, IAM Roles Anywhere). For each CLI note whether short-lived/scoped credentials are available as a blast-radius reducer.

OUTPUT: a table [CLI | auth mechanism | storage | honors proxy? | honors custom CA? | pins? | class A/B/C | short-lived option?], plus a one-line note per CLI on what a local credential proxy CAN and CANNOT do. Cite doc URLs.