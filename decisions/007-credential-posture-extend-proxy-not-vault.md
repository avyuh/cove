---
title: Credential posture — extend the proxy, do not build a credential vault
date: 2026-07-10
status: accepted
---

For locally-consumed credentials (OAuth-session self-refresh; SigV4/mTLS client-side
signing), extend the existing host-side injection proxy rather than build the six-candidate
"credential vault" (broker + capture-at-login, broker-backed FUSE, dedicated service UID,
MAC-labelled cred files). See [`../docs/CREDENTIAL-POSTURE.md`](../docs/CREDENTIAL-POSTURE.md)
for the full posture.

## Context

A design→QC→capstone pass produced a six-mechanism ladder. GPT-5.6 (sol-high) reviewed it
independently and rejected most of it; the load-bearing claims were verified against the box
(`aj-minion-01`, 2026-07-10). Three corrections collapsed the design:

1. `gh` (`GH_TOKEN` = `Authorization: Bearer`) and `git`-over-HTTPS (token = Basic-auth
   password) are transmitted-verbatim header credentials cove's existing MITM proxy already
   handles — the proposed OAuth broker solved an already-solved case.
2. Running a whole CLI under a dedicated service UID is sandboxing renamed, and a socket
   accepting arbitrary prompts under a credential UID is a confused deputy; on this box it is
   moot anyway because uid 1000 has `(ALL) NOPASSWD: ALL`.
3. The at-rest OAuth case (codex `auth.json`) has no honest local win against a
   prompt-subverted codex on a hardware-less, clonable VPS.

## Decision

**Build:** GitHub Bearer + Git Basic injection on the proxy; policy-constrained SigV4
re-signing (fail closed on presigned/streaming); upstream mTLS termination; short-lived
issuance only where the bootstrap root of trust is independently credible.

**Do not build:** broker-backed FUSE, same-UID keyring as a boundary, PID/exe-hash authz
over a same-UID socket, `sudo -u codexsvc` launcher, custom `gh` OAuth broker, SoftHSM,
local OIDC issuer sold as elimination, AppArmor/SELinux file policy sold as protection from a
malicious codex.

**Codex/ChatGPT OAuth:** state the loss plainly — prefer API-key mode via header injection;
else verified `ephemeral` store + one-shot boxes + low-value account + provider-side scope.

**Prerequisite (not done this session, owner's choice):** host-authority hygiene — remove the
agent UID's passwordless sudo, root-own the codex install, address swap/core-dump exposure —
before any service-UID/MAC work is credible.
