# Final Tester Sweep Results

Date: 2026-07-06 UTC

Live cove binary used for namespace/box tests: `/usr/local/bin/cove` (`cove 0.1.0`).

Reason: this host's AppArmor grant is path-specific for `/usr/local/bin/cove`; the final live checks installed the freshly built binary at that path before running box tests.

## Summary

| Area | Result | Notes |
| --- | --- | --- |
| Preconditions | PASS | build/vet/test clean; setup artifacts present; live binary reports 0.1.0 |
| A - Unit | PASS | `go test ./... -count=1` clean; new 77 preflight unit tests pass |
| B - Security invariants | PASS | `scripts/e2e-box.sh` all green; B6 now checks cove's actual CA-key material, not generic distro key examples |
| C - Concurrency/stress | PASS | e2e harness: 20/20 concurrent sessions, distinct audit sessions, fd/session cleanup returned to baseline |
| D - Robustness/lifecycle | PASS | e2e harness: fail-closed proxy death, respawn, singleton, stale sweep, SIGHUP reload, rotation |
| E - Real-agent E2E | PASS | Claude/runtime path green; Codex requires `cred_mount=["~/.codex:rw"]`, verified live with CODEX-OK and egress-bounded 403 |
| F - Streaming | PASS | Prior final sweep streaming result unchanged; no streaming code touched in this delta |
| G - Negative/error paths | PASS | Runnable exit codes still pass; first-run 77 preflight covered by direct unit tests; real ungranted state not toggled on this pre-granted host |

## Gate Commands

Command:

```sh
/usr/local/go/bin/go build ./... && /usr/local/go/bin/go vet ./... && /usr/local/go/bin/go test ./... -count=1
```

Output excerpt:

```text
ok  	cove/cmd/cove	0.012s
ok  	cove/internal/box	1.134s
ok  	cove/internal/config	0.012s
ok  	cove/internal/launcher	0.029s
ok  	cove/internal/logcmd	0.165s
ok  	cove/internal/proxy	6.511s
ok  	cove/internal/secret	0.011s
ok  	cove/internal/setup	0.468s
?   	cove/internal/version	[no test files]
```

Command:

```sh
/usr/local/bin/cove --version
/usr/local/bin/cove -- /bin/true
```

Output excerpt:

```text
cove 0.1.0
```

The `/bin/true` launch exited 0.

## B - Security Invariants

Command:

```sh
COVE_BIN=/usr/local/bin/cove GO_BIN=/usr/local/go/bin/go bash scripts/e2e-box.sh
```

Output excerpt:

```text
PASS B1-secret-absence
PASS B2-ip-proxy-403
PASS B2-raw-socket-ENETUNREACH
PASS B2-no-resolver
PASS B2-evil-403-audit
PASS B2-ip-literal-denied
PASS B3-privilege
PASS B4-pivot-root
PASS B5-audit-unforgeable
PASS B6-ca-key-absent
PASS B7-allow-opaque
...
PASS E-claude-runtime-positive
PASS G-exit-codes
...
ALL PASS
```

### B6 CA Key Absent - PASS

The B6 tester and `scripts/e2e-box.sh` now search for a byte-prefix of the actual host cove CA private key from `~/.config/cove/ca-key.pem` across the box filesystem, excluding only `/proc`, `/sys`, and `/dev`. The generic private-key-header grep was removed because it matches public distro package examples under the intentional read-only `/usr` mount.

Verified invariant:

```text
actual cove CA private-key material in box: zero matches
/etc/ssl/certs/cove-ca.pem: present
/etc/ssl/certs/cove-ca-bundle.pem: present and contains the public cove CA
```

Interpretation: B6 now asserts the intended invariant precisely. The public distro documentation/test fixtures no longer false-fail the sweep.

## E - Real-Agent E2E

### Codex `:rw` Acceptance - PASS

Test config:

```toml
[options]
cred_mount = ["~/.codex:rw"]
```

Command:

```sh
env XDG_CONFIG_HOME="$cfg" XDG_STATE_HOME="$state" \
  /usr/local/bin/cove -- codex exec 'reply with exactly: CODEX-OK'
```

Output excerpt:

```text
cove: credential "~/.codex:rw" is mounted INTO the box read-write - UNSAFE under concurrent sessions (exfil-contained, not theft-proof)
OpenAI Codex v0.142.5
codex
CODEX-OK
```

Audit evidence:

```text
{"policy":"allow","host":"chatgpt.com","port":443,"agent":"codex"}
```

Egress-bounded proof from the same isolated cove config:

```sh
env XDG_CONFIG_HOME="$cfg" XDG_STATE_HOME="$state" \
  /usr/local/bin/cove -- /bin/sh -lc 'curl -skv --max-time 8 https://evil.example.com/ -o /dev/null'
```

Output/audit excerpt:

```text
< HTTP/1.1 403 Forbidden
* CONNECT tunnel failed, response 403
{"policy":"deny","host":"evil.example.com","status":403,"agent":"sh"}
```

Interpretation: Codex 0.142.5 is live-green with `~/.codex:rw`; the token remains egress-bounded by the cove proxy. The old `~/.codex` read-only acceptance is intentionally retired because Codex fails init on read-only auth state.

### Claude Runtime Path - PASS

Covered by `scripts/e2e-box.sh`:

```text
PASS E-claude-runtime-positive
```

### Kimi - OWNER-ACCEPTED SKIP

Kimi E2E remains skipped because no `~/.config/cove/secrets/kimi-api-key` is configured on this host.

## First-Run 77 Preflight

Before fix, the locally ungranted binary path produced the misleading setup failure:

```text
local_ungranted_rc=75
cove: box setup failed: ERR mount private root: permission denied
```

After fix, launcher preflight is covered directly:

```sh
/usr/local/go/bin/go test ./internal/launcher -run TestPreflightUserns -count=1
```

Output:

```text
ok  	cove/internal/launcher	0.009s
```

The new tests drive the profile-absent and probe-failure branches directly and assert exit 77 with:

```text
cove: user namespaces denied; run `cove setup` (needs sudo, once)
```

Regression guard:

```text
/usr/local/bin/cove -- /bin/true: exit 0
```

Real userns-denied reproduction remains owner-accepted residual: this host is already configured by `/etc/apparmor.d/cove` for `/usr/local/bin/cove`; revoking AppArmor/userns policy would be system-wide and disruptive.

## Residuals

- Kimi E2E skipped: no Kimi API key configured on this host.
- Userns-denied 77 not physically reproduced by toggling host policy; direct preflight tests cover the 77 behavior on this pre-granted box.
- Orphan proxyd in isolated-XDG/test runs is v0-acceptable and not fixed in this work order. It was observed once during the live gate after replacing the binary: stale `cove proxyd` processes held the lock while `proxyd.sock` was absent, producing `cove proxy unavailable: PING timed out`. Test cleanup killed the stale proxyd processes; no proxy/lifecycle code was changed.

## Documentation Delta

Codex guidance now consistently says to use:

```toml
cred_mount = ["~/.codex:rw"]
```

Updated locations:

- `internal/config/default_config.toml`
- `docs/SPEC.md` section 5.5 seed comment, section 5.7 friction/concurrency prose, E2E snippet, and B4 note
- `docs/TESTPLAN.md`
- `README.md`

The seed default remains `cred_mount = []`, and the behavior of plain credential mounts remains read-only by default.
