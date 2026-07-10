# cove

A credential firewall for AI coding agents run with permissions off.

## The problem

An agent running unsupervised with permissions skipped has your shell: it can
read `~/.ssh`, `~/.aws/credentials`, `~/.claude/.credentials.json`, and every
other project's `.env`, then POST them to any host on the internet. One
prompt-injected web page in its context is enough. The agents' built-in
sandboxes block so much legitimate work — package installs, git pushes, API
calls — that most people disable them, which is how the keys got exposed in the
first place.

## How it works

`cove -- <agent>` runs the agent in an ephemeral Linux namespace box
(user/mount/pid/net — unprivileged, no root, no Docker, no daemon to manage).
Three mechanisms:

- **Secrets are absent, not blocked.** The box gets an empty tmpfs HOME at
  `/root`. Host HOME, dotfiles, `~/.ssh`, `~/.aws` are simply not mounted — an
  agent cannot read what does not exist. Only the project directory enters the
  box, bind-mounted read-write at `/work`.
- **One network door.** The box's network namespace has only loopback; the sole
  route out is a unix socket to a proxy on the host. The proxy tunnels traffic
  to hosts on your `allow` list and refuses everything else. A tool that
  ignores proxy settings gets `ENETUNREACH` — it fails closed.
- **Keys injected host-side.** For hosts with an `[[inject]]` stanza, the proxy
  terminates TLS (using cove's own CA, trusted only inside the box) and adds
  your real API key to each request. The agent holds a dummy
  (`cove-dummy-do-not-use`); the real key never enters the box, so it cannot be
  stolen there.

Every request gets a JSONL audit record with its verdict: `allow`, `inject`, or
`deny`.

## Install

Linux only; built and tested on Ubuntu 24.04. Needs Go to build.

```sh
go build -o cove ./cmd/cove
sudo install -m0755 cove /usr/local/bin/cove
sudo cove setup
```

`cove setup` is one-time and idempotent. The only step that needs root is
installing an AppArmor profile for `/usr/local/bin/cove` — Ubuntu 24.04 blocks
unprivileged user namespaces by default, and the profile grants them to cove
the same way Podman and bwrap do (on distros where userns already works, the
step is skipped). As your user, setup generates cove's CA, creates
`~/.config/cove/config.toml` from the seed if absent, and prints which inject
secrets are still unpopulated.

## Run

```sh
cove -- claude -p "summarize this repo"
cove -C ~/src/app -- codex exec "run the tests"
cove --dry-run -- claude     # print the launch plan, run nothing
```

`cove -- <agent>` is a drop-in for `<agent>`: same TTY behavior, argv passed
verbatim after `--`, the agent's own exit code propagated. The project (cwd, or
`-C DIR`) appears read-write at `/work`, the agent's starting directory; edits
are real host files owned by your uid. On exit the box is destroyed — nothing
persists except `/work` and the audit log.

Agents installed via nvm, volta, or asdf are auto-resolved and their toolchain
directory mounted read-only at its own absolute path; the rest of HOME stays
absent. Agents installed under `/usr/local/bin` need nothing. Other cases:
`runtime_mount` in the config. `-v` prints launcher diagnostics; `--no-audit`
skips audit records for one run.

## Credentials, per tool

| Tool | You do | Real key in the box? |
|---|---|---|
| Claude Code | Nothing — a logged-in `claude` works immediately | No. The proxy reads the OAuth token from host `~/.claude/.credentials.json` per request and injects it. If it expires, run `claude` on the host once to re-login. |
| Codex (ChatGPT login) | Add `cred_mount = ["~/.codex:rw"]` to the config | Yes — the login writes under `~/.codex`, so it must be mounted. Egress is still bounded to `chatgpt.com` / `auth.openai.com`. |
| OpenAI API | Key into `~/.config/cove/secrets/openai-api-key` | No — injected |
| Kimi | `~/.config/cove/secrets/kimi-api-key` | No — injected |
| Gemini (API key) | `~/.config/cove/secrets/gemini-api-key` | No — injected |
| Hugging Face | `~/.config/cove/secrets/hf-token` | No — injected |
| Hetzner | `~/.config/cove/secrets/hcloud-token` | No — injected |
| Cloudflare | `~/.config/cove/secrets/cloudflare-token` | No — injected |
| RunPod | `~/.config/cove/secrets/runpod-key` | No — injected |
| GitHub PAT (opt-in) | Configure the two GitHub PAT inject stanzas and remove `github.com` and `api.github.com` from `allow` | No — Bearer API and scoped Git smart-HTTP Basic credentials are replaced host-side. |

A missing secret for a legacy header-injection stanza is inert: cove strips
its dummy header and forwards anonymously (so, for example, public Hugging
Face downloads can still work) and warns once. SigV4 and upstream-mTLS stanzas
are different: every required secret is host-side and missing material fails
closed with HTTP 502; cove never falls back to a tunnel or forwards a dummy.

For GitHub, choose one mode. The default is `gh` OAuth: GitHub hosts remain
`allow` rules and `gh` needs `cred_mount = ["~/.config/gh"]`, so that session is
in the box. PAT mode is different: enable the two commented GitHub `[[inject]]`
stanzas in the seed, remove both `github.com` and `api.github.com` from `allow`,
and store a fine-grained PAT in the referenced host file. This gives `gh` API
Bearer requests and scoped Git smart-HTTP Basic requests a dummy in the box.
See the [supported/rejected S3 matrix](docs/SPEC.md#531-s3-sigv4-supportedrejected-matrix)
and [short-lived credential guidance](docs/SHORT-LIVED-CREDENTIALS.md) when
choosing credential lifetime and scope.

> **Capability — GitHub PAT mode:** Bearer requests to `api.github.com` and scoped Git smart-HTTP Basic requests to `github.com` are replaced host-side; the box holds only a dummy. **Residual — credentialed GitHub oracle:** a subverted agent can still perform every GitHub API/repository operation allowed by the PAT and cove repository/method policy. Use a fine-grained/short-lived token; cove prevents token theft, not authorized misuse.

## Reading the audit trail

```sh
cove log                          # every request: allow / inject / deny
cove log --follow --deny-only     # watch denials live
cove log --session 1a2b3c4d --host api.anthropic.com
```

Flags compose. The log is JSONL at `~/.local/state/cove/audit.log`
(`$XDG_STATE_HOME` respected); `--follow` survives rotation and truncation;
half-written trailing lines are skipped.

## Config

`~/.config/cove/config.toml`. Adding a tool is config, not code.

- `allow = [...]` — hosts the box may reach as opaque tunnels; whatever
  credential the agent holds is used as-is, exfil-contained by this list. Exact
  hosts or leftmost wildcards (`*.hf.co`). The seed includes GitHub, npm, PyPI,
  the Go module proxy, crates.io, and the Hugging Face CDNs, so installs and
  clones work out of the box.
- `[[inject]]` — one stanza per host whose key the proxy adds:
  `header_name`/`header_template` (`Bearer {secret}`), a `secret` reference
  (`file:`, `env:`, or `json:path#dotted.field` — the Claude stanza reads
  `json:~/.claude/.credentials.json#claudeAiOauth.accessToken`), `dummy_env`
  for the placeholder the agent sees, and `base_url_env` to point the client at
  the proxy.
- `cred_mount = ["~/.codex:rw", ...]` — host dirs mounted into the box HOME for
  logins that cannot be injected. Read-only unless `:rw`; `:rw` lets the tool
  refresh its own token but is unsafe under concurrent sessions on the same
  dir.
- `runtime_mount` — extra toolchain dirs, read-only, same path as on the host.
- `env_passthrough` — env vars copied into the box for opaque `allow` hosts.
  Do not pass real `AWS_*` credentials when using a `[[sigv4]]` rule: cove
  supplies dummy AWS credentials and re-signs its supported S3 subset
  host-side. Unsupported AWS services or SigV4 modes remain `allow` +
  short-lived credentials in the box.

A host must have exactly one policy kind: `allow`, `[[inject]]`, `[[sigv4]]`,
or `[[mtls]]`; cove validates conflicts at startup.

> **Capability — S3 SigV4 re-signing (v1):** aws/boto3/s5cmd may hold dummy AWS credentials; cove re-signs supported, finite S3 requests with a host-side key after enforcing configured account label, region, service, method, operation, and resource. **Residual — policy-constrained signing oracle:** a subverted agent can perform every operation the cove policy and AWS IAM both allow. The real key stays out of the box, but cove is not misuse-proof. Presigned URLs, SigV4a, multipart, and AWS streaming/chunk signatures fail closed.

> **Capability — upstream mTLS termination:** the box uses ordinary one-way TLS to cove; cove presents a host-side client certificate only to configured upstream hosts and method/path prefixes. The private key never enters the box. **Residual — credentialed mTLS oracle:** a subverted agent can invoke every operation the destination and cove method/path policy permit through that client identity. This is credential theft resistance, not proof of legitimate intent.

> **Capability — short-lived sources:** cove can consume rotated file/json-backed tokens, SigV4 session credentials, and client certificates issued by an external or human-rooted system. **Residual — blast-radius reduction, not local secret elimination:** expiry limits damage; security still depends on the issuer bootstrap, host authority, snapshots, clock, scope, and renewal path. On a clonable VPS, a local OIDC issuer merely moves the bootstrap secret.

## What cove stops, and what it does not

cove stops credential **theft** (Class-A keys are never in the box; host
dotfiles are absent) and **exfiltration** (the only egress is to hosts you
listed). It runs *contained agent sessions* — it is not a secure sandbox, and
these residuals are real:

- **Misuse at an allowed host.** An agent with the injected Anthropic key can
  still spend your API quota; one with your `gh` login can still push to your
  own repos. Injection cannot distinguish a legitimate request from a malicious
  one at the same host. `cove log` is the only mitigation.
- **Mounted credentials are readable.** A `cred_mount`ed session file (Codex,
  `gh`) is in the box by necessity: exfil-contained by the allow list, but not
  hidden from the agent.
- **Kernel escape.** The box is namespaces, not a hypervisor or gVisor. A
  kernel exploit that breaks the user/mount/net namespace defeats cove.
- **The project itself.** `/work` is fully in the agent's power — deleting or
  corrupting your working tree is within its granted authority. Use git.
