# cove — credential posture (revised direction)

**Status: accepted 2026-07-10. Supersedes the 7-rung "credential vault" design**
(`docs/research/…` thinker→QC→synthesis trail) for the locally-consumed-credential
problem. This is the plan of record.

This document is the outcome of a design→red-team→capstone pass on the open problem
"how do we protect credentials that are *consumed locally* (OAuth-session self-refresh;
SigV4/mTLS client-side signing) — the ones cove's transmitted-token MITM swap cannot
help." A six-candidate mechanism ladder was designed, adversarially QC'd, then reviewed
independently by GPT-5.6 (sol-high). **The capstone rejected most of the ladder as either
already-solved by shipped cove or as theater, and its load-bearing claims were verified
against this box.** We adopt its cut.

Implementation details: [policy schemas, matrix, and local harness](SPEC.md#5-credential-model--config).

## The reframe (why the vault shrank)

Three corrections collapsed the design:

1. **`gh` and `git` are not a new problem class.** `GH_TOKEN` is sent as
   `Authorization: Bearer …`; a GitHub HTTPS git push sends the token as the Basic-auth
   password. Both are **transmitted-verbatim header credentials** — exactly what cove's
   existing host-side MITM injection proxy already handles. The proposed OAuth broker +
   capture-at-login + token rotation + service UID (design "Candidate 2") solved a case
   the shipped mechanism already solves. Deleted.

2. **"Run the tool under a dedicated service UID" is sandboxing renamed — and it does not
   hold on this box anyway.** A *narrow signer/broker daemon* under its own UID (never
   returns the secret, tiny protocol) is legitimate privilege separation. Running the
   whole `codex`/`gh`/`aws` CLI under another UID to constrain it is process isolation
   with the noun changed; AppArmor/SELinux on the cred file is, by definition, process
   confinement. Worse, a "codex service" reached over a socket that accepts arbitrary
   prompts while codex runs with permissions off is a **credentialed confused deputy**: a
   prompt-injected codex simply reads its own `auth.json` and returns it over an allowed
   channel. Separate-UID stops a dumb sibling `open()` — not the subverted-blessed-tool
   adversary in our own threat model.

3. **The at-rest OAuth case has no honest local win on a hardware-less, clonable VPS.**
   Against a prompt-subverted codex there is nothing to hide behind: the tool must read
   its own live token, and a subverted tool discloses it. FUSE, keyring, and PID-gated
   sockets all reduce to "blocks a dumb scraper" at best, and the FUSE fallback is
   internally contradictory here (it is the "no-root" fallback yet requires a separate-UID
   daemon and `user_allow_other`, both of which need the root it assumes absent).

Net: subtract what cove already does and what is theater, and the residue is small.

## What we build

All of this **extends the existing host-side proxy / host boundary** — no new broker, no
FUSE, no service-UID launcher.

1. **GitHub Bearer + Git Basic injection.** Put a dummy `GH_TOKEN` in the box; swap it for
   the real token at the proxy (already the pattern for Anthropic et al.). Add a Basic-auth
   transform so `git` over HTTPS gets the same treatment. Real token never enters the box.
2. **Policy-constrained SigV4 re-signing** on the proxy. Keep dummy AWS creds in the box;
   re-sign after MITM decryption with the real key held host-side. **Fail closed** on
   presigned URLs and streaming/chunked signatures (each chunk chained). Bind policy to
   account / service / region / operation / resource / method — *not* merely destination.
   Ship an explicit supported-mode matrix.
3. **Upstream mTLS termination** at the same host boundary. Client cert stays outside the
   box; restrict destination + protocol. Treat it honestly as a credentialed oracle, not
   misuse prevention.
4. **Short-lived issuance only where the bootstrap is independently credible** — real cloud
   workload identity, an interactive human ceremony, or an external control plane with a
   non-local root of trust. For every deployment, **record where the bootstrap secret
   lives.** On a bare clonable VPS, OIDC/WIF does not create a root of trust — it moves it.

## What we do NOT build (named theater)

- Broker-backed FUSE for codex.
- A same-UID keyring sold as a security boundary.
- PID / executable-hash authorization over a same-UID socket.
- A generic `sudo -u codexsvc` launcher, or any socket that runs arbitrary
  codex/gh/git commands under a credential UID (extraction oracle, not misuse oracle).
- A custom `gh` OAuth broker (proxy substitution already covers it).
- SoftHSM or any software "non-exportable" key.
- A local OIDC issuer / client-secret flow sold as secret elimination.
- AppArmor/SELinux file policy sold as protection from a *malicious* credential-owning codex.

## The Codex / ChatGPT OAuth case — stated plainly

There is **no at-rest protection** for `~/.codex/auth.json` on this box against the full
stated adversary (a prompt-subverted codex). Honest options, best first:

- Prefer **API-key mode via existing header injection** if account/product economics allow
  (moves codex back into the solved transmitted-token class).
- Otherwise: verified `ephemeral` credential store (confirm empirically it keeps no plaintext
  file — see below), one-shot boxes, a **low-value throwaway account**, tight provider-side
  scope, and accept that a subverted codex can use or disclose its own session.

## Prerequisites (host authority) — NOT yet met on this box

The proxy work is worth little while the host hands the agent UID the keys to the kingdom.
These are recorded as prerequisites; **owner elected not to change system config in this
session.** Verified state on `aj-minion-01`, 2026-07-10:

- `dev` (uid 1000) has `(ALL) NOPASSWD: ALL` → any malware as uid 1000 does
  `sudo -u <anyone> cat <anyfile>`. Every UID-separation story is moot until this is removed.
- codex is installed under `~/.nvm/...`; `codex.js` is `-rwxrwxr-x dev dev` and the
  containing dirs are `775 dev:dev` → attacker replaces the binary and waits for it to run.
- `~/.codex` is `775 dev:dev` → directory-write permits rename/unlink of `auth.json` even
  though the file itself is `0600`.
- 4 GiB **swapfile active**; `fs.suid_dumpable=2`; core dumps piped to apport → an
  "ephemeral, nothing-durable-persists" claim is false until swap/core/snapshot are handled.
- `codex` and `cove` are AppArmor-**unconfined**.

Required before any service-UID/MAC work is credible: strip the agent UID's passwordless
sudo; make the codex install (binary, libs, config, plugins, PATH entries) root-owned;
private service-home dirs, not merely mode-0600 files; address swap + core-dump + snapshot
exposure; treat workspace content as hostile input.

## Empirical checks still owed

None of these print secret values.

```sh
# codex ephemeral/keyring store behavior (source-inspected at commit 1f0566d, not run):
#   confirm `ephemeral` leaves NO plaintext file and `auto` does not silently fall back.
# host authority (re-run after any hardening):
sudo -n -l; namei -l "$(readlink -f "$(command -v codex)")"
swapon --show; sysctl kernel.core_pattern fs.suid_dumpable
# AWS re-signer scope, before shipping: presigned-URL + streaming-chunk coverage, fail-closed.
```

## Honest positioning (unchanged from cove's charter, sharpened)

cove stops credential **theft** for transmitted-token tools (the key is never in the box)
and bounds **exfiltration** to an allowlist — but destination allowlisting is a *friction
layer, not an exfil boundary* (a stolen bearer replays elsewhere; misuse flows through an
allowed provider). It does **not** stop a subverted-but-authorized tool from using or
disclosing a credential it legitimately holds. Say so; never label a live token
"unstealable."
