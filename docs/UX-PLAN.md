# cove — UX plan (agreed design)

Status: accepted 2026-07-10. Output of a 2-round UX design panel (sol-high + fable,
full agreement). This is the plan of record for cove's interface. It changes *surface*,
not the security model — the credential firewall (`docs/CREDENTIAL-POSTURE.md`,
`docs/SPEC.md`) is unchanged underneath.

## North star

cove is the **calm doorman**, not the alarm system. You type `cove claude` instead of
`claude` and nothing else changes — except that afterward, in one beautiful line per
request, you can see exactly what your agent did with the outside world. Every other
action — setup, adding a key, allowing a host, diagnosing a failure — is one short
command that says what it did and what to do next. The teachable model, in one sentence:

> Your agent runs in an empty box; cove is the doorman who only opens the door to hosts
> you allow and stamps your real keys on at the door.

Everything below that sentence is progressive disclosure. The tools whose taste we
imitate: `gh` (posture as a checklist), `tailscale`/`mkcert` (a scary operation reduced
to one friendly command). The anti-goal: another cryptic security-tool CLI.

## Settled decisions

- **Readiness command = `cove status`** (one screen; `doctor` is a hidden alias). Active
  checks (userns probe, config validation with line numbers, CA/key pairing, proxy
  reachability, agent resolution, a minimal contained HTTPS probe), reports credential
  *availability* only — never values — and turns every red line into one runnable fix.
  `--verbose` shows fingerprints/paths.
- **Verdict vocabulary.** Human surfaces say **protected / allowed / blocked**
  (protected = a real key was stamped on host-side without entering the box — the
  product's most valuable state). Config keys, JSONL, and `--json` keep
  **inject / allow / deny** byte-stable. The mapping is printed once in `cove help` so
  the two vocabularies never silently drift.
- **Config authoring = one `cove add <service>` compiler + `cove allow <host>`** as the
  top-level denial-loop verb. Secrets are **never** accepted in argv — hidden TTY prompt
  or `--secret-stdin`. Files written atomically at `0600`. Every add previews the compiled
  grant before saving; non-interactive requires `--yes`.
- **Speak through the agent.** Deny bodies and dummy values are strings an LLM reads and
  reasons about. They must name the fix command, so the *agent* relays it to the human.
  No competitor designs for a human-and-agent audience.

## `cove add` command surface (v1)

```
cove add github [--repo OWNER/REPO,… | --repo 'OWNER/*'] [--oauth] [--secret-stdin] [--yes]
    # default PAT mode: hidden prompt; atomically removes github.com + api.github.com
    # from allow, enables both inject stanzas, stores PAT 0600; prints what changed + undo.
    # --oauth: reverse — expose ~/.config/gh, re-add allow hosts.
cove add openai | gemini | kimi | huggingface [--secret-stdin] [--yes]
    # hidden prompt; trims whitespace; enables the inject stanza; ends with a `try:` line.
cove add token <name> --host HOST [--env VAR] [--header 'Authorization: Bearer {secret}']
    # generic header injection for any service.
cove add s3 s3://BUCKET/PREFIX/ [--read-write] [--delete] [--profile NAME] [--region R]
    # reads host AWS profile, STS-infers account, region from URI/profile; methods from
    # capability (--read-write ≠ delete); ARN from URI; body cap chosen; PREVIEWS grant.
cove add mtls HOST --cert PATH --key PATH --allow 'GET /v1/reports/*' …
    # each --allow is ONE method+prefix PAIR -> rules = [{method, path_prefix}].
cove add codex-login          # expose ~/.codex read-write, consent at add time

cove allow <host> [--once] [--yes]   # top-level; TTY shows consequence + confirms;
                                     # --once = next session only, not persisted
cove remove <name>                   # reverts the named connection to blocked
cove list                            # every connection: verdict class, hosts, secret state
cove config check                    # validate without launching; pretty 3-beat errors
cove config edit                     # escape hatch; TOML stays hand-editable
```

## Roadmap

### P0 — trust + the daily breeze (the core deliverable)

1. **Correctness (release-blocking honesty fixes).**
   - `--no-audit` / `[options].audit` are parsed but never applied. Wire a per-session
     audit bit through session registration + proxy and test that **zero** records are
     emitted — or delete both controls until they work.
   - mTLS `allowed_methods` × `allowed_path_prefixes` is an over-granting Cartesian
     product. Replace with method/path **pairs**: `rules = [{method="GET",
     path_prefix="/v1/x/"}]`. Validation errors cite config lines. (Gates `cove add mtls`.)
   - Replace or delete the stale podman `install.sh` (it demands podman, runs
     `cove build` — a different, retired product).
   - Fix README: don't lead with `sudo cove setup`; remove the false "setup prints which
     inject secrets are unpopulated" claim.
2. **Kill the mandatory `--`.** First non-flag positional starts the agent argv; cove flag
   parsing stops there. `cove -- <agent>` kept forever as the escape hatch for agents whose
   names collide with subcommands.
3. **Close the denial loop** (one feature): an in-box denial response body that names
   `cove allow <host>` (so the agent relays it); a post-run deny receipt on stderr (hosts ×
   counts, session id, the `allow` command, `cove log --last`); and `cove allow <host>`
   itself (`--once`, TTY confirmation showing the consequence, never implicit mutation).
4. **Pretty `cove log`.** TTY table by default — protected/allowed/blocked (colored,
   blocked reason inline), right-aligned sizes/durations, latest session by default; flags
   `--last`, `--blocked` (alias for `--deny-only`), `--since`. `--json` and non-TTY output
   stay byte-stable JSONL for scripts.

### P1 — the confidence surfaces

5. **`cove status`** (above); the `cove setup` epilogue becomes its concise mode — a calm
   checklist, "ready to inject / needs a key", one `try:` line; fingerprints and
   bootstrap noise move behind `--verbose`.
6. **`cove add` compiler, wave 1:** `github`, key services (`openai`/`gemini`/`kimi`/
   `huggingface`), `token`, plus `remove` / `list` / `config check`.
7. **Three-beat errors everywhere:** what stopped / where (TOML line+column via decode
   spans) / the one fix command. Keep the sysexits exit codes; document them.
8. **Humanized `--dry-run`** (Would start… / Project / Home / Credentials / Network /
   Audit); hide `proxyd` from help; rewrite help around the one-sentence model.

### P2 — polish + reach

9. `cove add s3` and `cove add mtls` (need the P0 `rules` schema); `cove add codex-login`
   plus the `[[expose]]` rename of `cred_mount` (explicit `path`/`mode`/`reason`).
10. `cove sessions` listing; git-style unique session-id prefixes; `cove explain last`.
11. Release binaries + checksums + packages; `~/.local/bin` install default (the AppArmor
    profile pins the resolved exe path anyway); a minimal generated config replaces the
    eight-inert-stanza seed dump.
12. Dummy-value hint (`cove-dummy-…-ask-the-human-to-run-cove-add`) — the second
    speak-through-the-agent channel.

## Must-not-lose (guard with tests)

Zero-config `cove claude` for a logged-in Claude; the verbatim-argv / real-TTY /
exit-code drop-in contract; fail-closed honesty and the residual-truth voice; the
self-describing dummies; JSONL + `--follow` rotation/truncation handling under the hood;
quiet nvm/volta/asdf auto-resolve; idempotent self-elevating setup. The README's prose
quality is the bar the CLI *output* is raised to — not the reverse.

## Shipped interface and release contract

The shipped front door is `cove <agent> [args...]`; `cove -- <agent>` remains
the collision escape hatch. The public commands are `setup`, `status`, `add`,
`allow`, `remove`, `list`, `log`, `config check`, `config edit`, `sessions`,
and `explain last`. Terminal log output is a human verdict view; `--json` and
non-terminal output preserve raw JSONL bytes.

Config commands edit only a versioned COVE MANAGED block. `[[expose]]` makes a
necessary local credential mount explicit, while `[[inject]]`, `[[sigv4]]`, and
`[[mtls]]` keep their material host-side. mTLS rules are paired
`{method,path_prefix}` entries, never a Cartesian product. Audit defaults on;
an audit-disabled session has no audit records. The sysexits contract remains:
64 usage, 66 input, 69 unavailable, 73 create, 74 I/O, 75 temporary, 77
permission, and 78 config (agent exit status remains verbatim).

Releases provide Linux amd64/arm64 archives, SHA-256 `checksums.txt`, SBOMs,
and deb/rpm packages. Packages install the binary and documentation only:
setup stays a deliberate per-user command.
