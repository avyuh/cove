# Short-lived credentials

cove consumes credentials issued elsewhere; it does not mint, refresh, broker, or
validate their expiry. Use this worksheet when arranging a short-lived SigV4
session, injected token, or mTLS certificate. Fill it in for each consuming cove
stanza and keep the record with the deployment runbook.

**Capability — short-lived sources:** cove can consume rotated file/json-backed
tokens, SigV4 session credentials, and client certificates issued by an external
or human-rooted system. **Residual — blast-radius reduction, not local secret
elimination:** expiry limits damage; security still depends on the issuer
bootstrap, host authority, snapshots, clock, scope, and renewal path. On a
clonable VPS, a local OIDC issuer merely moves the bootstrap secret.

Session tokens and certificates work through the supported SigV4 and mTLS paths,
but any credential delivered into the box is readable there. Keep values host-side
where possible; cove's source reporting intentionally prints only references and
labels.

## Worksheet: cloud workload identity / instance identity

- Issuer/control plane: ____________________
- Subject: ____________________
- Audience: ____________________
- Provider-side scopes: ____________________
- Maximum TTL: ____________________
- Renewal actor: ____________________
- Revocation path: ____________________
- Bootstrap material and where it lives: ____________________
- Host snapshot/clone exposure: ____________________
- Clock dependency: ____________________
- Consuming cove stanza and `file:`/`json:` reference: ____________________

Use this only when the workload or instance identity is independently credible.
On a bare clonable VPS, local OIDC/WIF does not create a root of trust; it moves
the bootstrap secret.

## Worksheet: interactive human issuance

- Issuer/control plane: ____________________
- Subject: ____________________
- Audience: ____________________
- Provider-side scopes: ____________________
- Maximum TTL: ____________________
- Renewal actor: ____________________
- Revocation path: ____________________
- Bootstrap material and where it lives: ____________________
- Host snapshot/clone exposure: ____________________
- Clock dependency: ____________________
- Consuming cove stanza and `file:`/`json:` reference: ____________________

Record the actual ceremony and its recovery/revocation authority, not just the
device model. A human-issued value copied to the host remains exposed to that
host's authority and snapshots until it expires or is revoked.

## Worksheet: external control plane

- Issuer/control plane: ____________________
- Subject: ____________________
- Audience: ____________________
- Provider-side scopes: ____________________
- Maximum TTL: ____________________
- Renewal actor: ____________________
- Revocation path: ____________________
- Bootstrap material and where it lives: ____________________
- Host snapshot/clone exposure: ____________________
- Clock dependency: ____________________
- Consuming cove stanza and `file:`/`json:` reference: ____________________

The control plane must have a non-local root of trust. Do not replace it with an
issuer, STS loop, refresh broker, metadata emulator, or local OIDC service in
proxyd.

## Rotation recipes

Write a complete replacement beside the destination with mode 0600, then rename
it into place. Point `[[inject]]`, `[[sigv4]]`, or `[[mtls]]` at the final
`file:/absolute/path` or `json:/absolute/path#field` reference. Existing
file-backed resolution notices mtime/size changes, so the next use picks up the
replacement; see [`internal/secret/secret.go`](../internal/secret/secret.go#L120-L155).

```sh
umask 077
dir=/var/lib/cove/short-lived
mkdir -p "$dir"
tmp=$(mktemp "$dir/token.new.XXXXXX")
printf '%s\n' "$ISSUED_TOKEN" >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$dir/token"
# config ref: file:/var/lib/cove/short-lived/token
```

For structured credentials, atomically replace the entire JSON document rather
than editing it in place:

```sh
umask 077
tmp=$(mktemp /var/lib/cove/short-lived/aws-session.new.XXXXXX)
issuer-command-that-writes-complete-json >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" /var/lib/cove/short-lived/aws-session.json
# config ref: json:/var/lib/cove/short-lived/aws-session.json#sessionToken
```

Do not log shell values, put values in `bootstrap_ref`, or rely on cove to parse
expiry. `max_ttl` is a deployment assertion only; provider denial is authoritative.

## Codex OAuth limitation

There is no at-rest protection for `~/.codex/auth.json` on this box against a
prompt-subverted Codex. Prefer API-key mode through existing header injection if
account/product economics allow, which returns Codex to the transmitted-token
class. Otherwise, use a verified `ephemeral` credential store (confirm it leaves
no plaintext file), one-shot boxes, a low-value throwaway account, tight
provider-side scope, and accept that a subverted Codex can use or disclose its
own session. These are risk-management measures, not a local secret vault.
