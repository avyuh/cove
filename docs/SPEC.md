# cove — Engineering Specification (v0)

Status: implementer-ready. Source of truth for decisions is
`scratchpad/FINAL-DESIGN.md`; this document specifies, not relitigates, those
decisions. Target: a single competent Go engineer can build cove from this
document alone. Target platform: ARM64 (and amd64) Ubuntu 24.04, KVM guest, no
`/dev/kvm`.

Conventions in this document:
- MUST / MUST NOT / SHOULD / MAY are used in the RFC 2119 sense.
- Paths written `~/…` expand against the invoking user's `$HOME` on the host.
- "the box" = the per-session sandbox (namespaces). "the proxy" = the shared
  host-side daemon. "the agent" = the child CLI (`claude`, `codex`, …).
- Line-count budgets are guidance, not gates.

---

## 1. OVERVIEW & MISSION

### 1.1 One-sentence definition

cove is a **credential firewall for locally-run YOLO AI coding agents**: an
unprivileged Go binary that runs each agent in an ephemeral kernel-namespace box
containing no secrets and no network route except a single host-side proxy that
allowlists every destination and injects the keys the agent must never hold.

### 1.2 What cove is

cove is the self-hosted, KVM-less, CLI-agnostic realization of the SOTA
containment pattern (sandbox + deny-by-default egress + host-side injection
broker) — the same architecture as Docker Sandboxes' credential proxy — rebuilt
as one Go binary on a cheap ARM VPS with no hypervisor. It exists to make
`cove -- claude` a zero-friction reflex replacement for bare `claude`, so that
an owner running ~30 concurrent full-YOLO agent sessions across 10+ projects
never hands a prompt-injected agent the ability to *steal* or *exfiltrate*
long-lived credentials.

### 1.3 Honest positioning (verbatim discipline)

cove **stops key THEFT and key EXFILTRATION**. It does **NOT** stop **MISUSE**
of an allowed credential at an allowed host, and it is **NOT** a defense against
kernel escape. The phrase "secure sandbox" MUST NOT appear in cove's UI, docs,
or marketing. Approved language: "contained agent sessions", "credential
firewall". The threat cove addresses is a *confused or prompt-injected delegate*
with ordinary developer authority — not a kernel attacker.

### 1.4 Threat model

**In scope (cove defends these):**

1. **Credential theft at rest.** A compromised agent reading `~/.ssh`,
   `~/.aws/credentials`, `~/.claude/.credentials.json`, browser cookies, other
   projects' `.env` files, or any host dotfile. Defended by *absence*: those
   paths do not exist in the box (deny-by-default mount construction).
2. **Credential/data exfiltration to an arbitrary destination.** A compromised
   agent opening a raw socket, using a bypass DNS resolver, or POSTing stolen
   data to an attacker host. Defended by the loopback-only network namespace:
   there is no route out except the one Unix socket to the proxy, and the proxy
   denies every destination not on the allowlist. Proxy-ignoring tools **fail
   closed** (`ENETUNREACH`), which is safe.
3. **High-value key handling.** Class-A bearer keys (Anthropic API key, Hetzner
   token, GitHub PAT, …) are never placed in the box at all; the proxy injects
   them host-side per request.

**Explicitly out of scope (cove does NOT defend these):**

1. **Misuse at an allowed host ("oracle" residual).** If `api.anthropic.com` is
   allowed and injected, a compromised agent can still make authorized Anthropic
   API calls (spend tokens, read data the key can read). cove's only mitigation
   is the audit log (§4.9). This is inherent to any injection broker.
2. **Kernel escape.** The box uses namespaces, not a hypervisor and not gVisor.
   A kernel-level exploit that breaks the user/mount/net namespace defeats cove.
   cove explicitly chose not to pay the gVisor CPU/RSS tax (measured 1.64x CPU,
   ~6x RSS in the precode spike) because kernel escape is not the threat this
   owner is defending against.
3. **Misuse of a Class-B/C credential that MUST live in the box.** OAuth session
   tokens (codex ChatGPT, gemini Google, gh OAuth) and SigV4 signing keys (aws,
   s5cmd) cannot be injected; they live in the box and are only *exfil-contained*
   by egress policy. A compromised agent can misuse them at their allowed host.
4. **Destructive actions within policy.** Deleting a production database via an
   allowed, in-scope cloud token is a misuse cove does not block. cove's answer
   is to keep the *token* scoped/short-lived (user's responsibility) and to log
   the request (audit log). cove ships no approval gates, no per-path policy, no
   rate limits in v0.
5. **Host hardening.** cove protects the host's *secrets*, not the host. Damage
   to the mounted `/work` tree (the agent's own project) is fully in the agent's
   authority and is not defended.

### 1.5 Non-goals (binding anti-scope)

No session manager / "tmux for agents" / TUI / kanban / notifications. No
per-project / per-agent / per-tier isolation. No pluggable backends. No podman /
gVisor / bubblewrap dependency. No microVM roadmap. No transparent
redirect / TPROXY / nftables / DNS-interceptor / SNI parser. No SigV4 signing
broker. No WIF/STS minting in v0 (keep the config seam, ship nothing). No
per-host method/path policy or rate limits in v0 (audit log instead). No
multi-user. No GPU. No macOS/Windows. **Standing rule:** every shipped feature
must name the bare-YOLO failure it prevents.

### 1.6 Success metric

Exactly one axis is measured: **friction**. 30 days after install, the owner's
count of bare `claude` / `codex` invocations should be zero (reflex
replacement). If not, archive cove without sentiment.

---

## 2. ARCHITECTURE

### 2.1 Component diagram (text)

```
 HOST (unprivileged user; one login uid)
 ┌─────────────────────────────────────────────────────────────────────┐
 │                                                                       │
 │  cove (argv dispatch: launcher | proxyd | init)                       │
 │                                                                       │
 │  ┌──────────────────────────┐        ┌──────────────────────────┐     │
 │  │ cove proxyd  (daemon)     │        │ cove  (launcher, per run)│     │
 │  │  - 1 shared process       │        │  - forks child           │     │
 │  │  - holds CA priv key(mem) │        │  - unshare U|M|P|N ns     │     │
 │  │  - holds/refreshes keys   │        │  - builds deny-root       │     │
 │  │  - listens on             │        │  - execs cove-init (PID1) │     │
 │  │    ~/.local/state/cove/   │        └───────────┬──────────────┘     │
 │  │      proxyd.sock          │                    │ bind-mounts        │
 │  │  - allowlist match        │                    │ proxyd.sock ->     │
 │  │  - inject | allow | deny  │◄───unix stream─────┤ /proxy/proxy.sock  │
 │  │  - MITM h2/h1 for inject  │  (crosses netns)   │                    │
 │  │  - opaque tunnel for allow│                    ▼                    │
 │  │  - host-side DNS resolve  │        ┌──────────────────────────────┐ │
 │  │  - append audit log       │        │  THE BOX (namespaces)        │ │
 │  └───────────┬──────────────┘        │                              │ │
 │              │                        │  cove-init  (PID 1)          │ │
 │        DNS + TCP to                   │   - reap, signal+SIGWINCH fwd│ │
 │        real Internet                  │   - pty alloc for TTY agents │ │
 │              │                        │   - 127.0.0.1:8080 TCP <->   │ │
 │              ▼                        │     /proxy/proxy.sock shim   │ │
 │   api.anthropic.com, github.com,...   │        │                     │ │
 │                                       │        ▼                     │ │
 │                                       │  agent (claude/codex/…)      │ │
 │                                       │   HTTPS_PROXY=127.0.0.1:8080 │ │
 │                                       │   no secrets, loopback-only  │ │
 │                                       │   /work = project (rw)       │ │
 │                                       └──────────────────────────────┘ │
 └─────────────────────────────────────────────────────────────────────┘
```

*Diagram is illustrative; where it simplifies, the normative text wins. Two
refinements specified later: (a) the box binds a **per-session** socket
`sessions/<id>.sock` (not the shared `proxyd.sock`) so audit identity is
host-side and unforgeable (§4.1, M6); (b) `cove-init` forwards signals but NOT
`SIGWINCH` — the launcher owns window-resize and pushes sizes over a control
pipe (§3.4/§3.5, M1); (c) `HTTPS_PROXY`'s port is `options.proxy_port`, not a
hardcoded 8080; (d) the box has no secrets EXCEPT explicit opt-in `cred_mount`
entries (§5.7).*

### 2.2 The three roles of one binary

`cove` is a single static binary dispatched by `argv[0]`/subcommand into three
roles (§10 decision D1 fixes the dispatch mechanism):

1. **launcher** — `cove [flags] -- <agent> …`. Runs in the invoking shell.
   Ensures the proxy is up, forks a child, builds the namespaces and mounts,
   execs role 3 inside the box.
2. **proxyd** — `cove proxyd`. The long-lived shared daemon. Auto-spawned by the
   launcher on first use (or run as a systemd user unit). Holds keys + CA in
   memory. One per user.
3. **init** — `cove-init` (internal; not a user verb). PID 1 inside the box.
   Reaps, forwards signals, allocates the pty, runs the TCP↔unix shim, execs the
   agent.

### 2.3 Trust boundaries

- **Host user space** (full trust): the launcher, the proxy, the CA private key,
  all real credentials, the audit log. Everything here runs as the owner's uid.
- **The box** (zero trust): the agent and anything it spawns. Contains: system
  tools (ro), the project tree (`/work`, rw), a dummy/placeholder credential
  set, the CA *public* cert, and one Unix socket to the proxy. Contains **no**
  real Class-A key, **no** host dotfiles, **no** network route.
- **The boundary** is crossed only by: (a) the `/proxy/proxy.sock` Unix socket,
  and (b) the `/work` bind mount. Everything the agent can affect off-box goes
  through the proxy, which is policy-enforcing.

### 2.4 Lifecycle summary

- **One-time:** `cove setup` (root, once) installs the AppArmor profile and
  generates the CA. Idempotent.
- **Per session:** `cove -- <agent>` builds ephemeral namespaces, execs the
  agent, and on exit *everything evaporates* — the tmpfs root, all mounts, the
  netns. Nothing persists by construction except writes the agent made to
  `/work` (which is host-persistent) and appended audit-log lines.
- **Long-lived:** one `cove proxyd` process, shared by all sessions, keys + CA
  in memory. Fail-closed if it dies (box loses all egress).

---

## 3. THE BOX

The launcher builds the box in a forked child. Order matters: user namespace
first (to gain capabilities in the new namespace), then the rest.

### 3.1 Namespace creation (single mechanism — see §13.1)

There is exactly **one** namespace-creation mechanism (do not implement a second
`unshare`-in-thread path): the launcher re-execs the binary as `cove __init`
using `exec.Cmd` with a fully-populated `SysProcAttr` (Decision D2). The Go
runtime applies the clone flags and writes `uid_map`/`gid_map` atomically at
`clone(2)` time, and the re-exec'd child is PID 1 of the new PID namespace. The
exact `SysProcAttr` (clone flags, single-uid maps, `setgroups=deny`) is given
verbatim in §13.1 and is normative; this section does not restate it to avoid
drift. Namespaces created: `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS`. Single-uid map → no
`newuidmap`/`newgidmap` helper needed (foundational spike).

The launcher passes a readiness/error channel to the child via an inherited
**status pipe** (fd passed through `ExtraFiles`): `cove __init` writes a
one-byte `OK` (or a short error code + message) to this pipe once the mount plan
and `lo`-up have succeeded and immediately before `exec`ing the agent. This lets
the launcher distinguish *box-setup failure* from *the agent exiting with a
code* (see Minor fix on exit-code 70 collision, §6.1).

### 3.2 USER namespace (single-uid map, no setuid)

- Map exactly one uid and one gid: box-root (uid 0 inside) → invoking host uid.
  `0 <hostuid> 1`. Same for gid. `setgroups=deny`.
- **No range map, no `/etc/subuid`, no setuid helper.** This is the whole reason
  cove needs only a one-time AppArmor grant and no suid binary (foundational
  spike: single-uid map works with only the AppArmor profile; range maps need
  `newuidmap`).
- Consequence: files the agent creates in `/work` are owned by the host uid
  (box-root == host owner). No ownership translation problem.
- After the map is established, `cove-init` MUST `setresuid(0,0,0)` /
  `setresgid(0,0,0)` to become fully box-root within the namespace (the Go
  runtime child already starts as uid 0 in-ns; this is belt-and-suspenders for
  any dropped state).

### 3.3 MOUNT namespace (the full mount plan)

`cove-init` runs the mount plan. Deny-by-default: the new root is a fresh tmpfs
containing **only** curated mounts, so host secrets are **ABSENT**, not
denylisted. This is the robust construction proven by the foundational spike.

Steps, in order:

1. `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` — make the whole tree
   private so nothing propagates back to the host.
2. Create root: `mkdtemp` under host `/tmp` → e.g. `/tmp/cove-root.XXXXXX`, then
   `mount("tmpfs", root, "tmpfs", MS_NOSUID|MS_NODEV, "size=64m,mode=0755")`.
   (64 MiB is the root scaffold only; `/tmp` and `/dev` get their own tmpfs.)
3. **System tools (ro):** `bind_ro("/usr", root+"/usr")` where `bind_ro` =
   `mount(src,dst,BIND|REC)` then `mount(REMOUNT|BIND|RDONLY|NOSUID|NODEV|REC)`.
   Create symlinks `bin→usr/bin`, `lib→usr/lib`, `lib64→usr/lib` (arch-dep),
   `sbin→usr/sbin`. This gives the agent every host-installed system tool with
   zero accretion and nothing writable.
4. **Synthesized `/etc` (curated — the exact set):** create `root/etc`. Two
   kinds of entries: **synthesized** files cove writes, and **ro binds/copies**
   of a small allowlist of host `/etc` files real tools need (glibc TLS/DNS,
   OpenSSL, MIME/port tables, timezone). None of these contain host secrets.
   - **Synthesized (cove writes):**
     - `passwd`: `root:x:0:0:cove:/root:/bin/bash\n` (home is `/root`, a tmpfs —
       NOT `/work`; see step 6a. Shell = a shell that exists in `/usr/bin`; fall
       back to `/bin/sh` if bash absent).
     - `group`: `root:x:0:\n`.
     - `hosts`: `127.0.0.1 localhost\n::1 localhost\n`.
     - `hostname`: `cove\n`.
     - `resolv.conf`: **EMPTY** (zero bytes). The box has no resolver; DNS is
       eliminated by design (§4.6). Empty (not `nameserver 127.0.0.1`) so name
       resolution fails immediately rather than hanging; all egress is by CONNECT
       name to the proxy.
     - `nsswitch.conf`: `hosts: files\n` (glibc consults `/etc/hosts` only, no
       DNS/mDNS). Note: `res_query`/`res_send` (libresolv direct API) bypasses
       nsswitch, but such queries still have no network route (netns) and no
       nameserver — they fail closed. Documented edge, not a hole.
     - `gai.conf`: `precedence ::ffff:0:0/96 100\n` (prefer IPv4; avoids slow
       AAAA stalls in the box).
     - `machine-id`: a fixed dummy (`00000000000000000000000000000000\n`) — does
       NOT identify the host.
     - `ssl/certs/cove-ca.pem` and `ssl/certs/cove-ca-bundle.pem` (§7.5).
   - **Read-only bind or copy from host `/etc` (allowlist — exactly these):**
     `ssl/openssl.cnf`, `services`, `protocols`, `localtime`, `mime.types`,
     `ld.so.cache` (needed for dynamic-linker performance; contains no secrets).
     Bind read-only where the file exists on the host; skip silently if absent.
   - **Explicitly NOT present:** `/etc/ssh`, `/etc/pam.d`, `/etc/shadow`,
     `/etc/sudoers`, `/etc/krb5*`, any host credential/config dotfile. The
     allowlist is closed; nothing else is copied.
5. **`/proc` via the PID namespace:** `mkdir root/proc`, then
   `mount("proc", root+"/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)`.
   This succeeds because `cove-init` is PID 1 of a fresh PID namespace (the
   prototype's proc mount failed precisely because it had no PID ns — cove fixes
   this by design, see §3.4).
   - **`/sys` (cgroup-only by DEFAULT — consistency fix):** Node/Bun and some
     build tools read `/sys/fs/cgroup/memory.max` (or `.../memory.limit_in_bytes`)
     to size heaps; an absent cgroup path makes them over-allocate or crash. But a
     whole-`/sys` ro bind leaks host hardware/network topology into the box. So
     the **default is the minimal variant**: `mount("tmpfs", root+"/sys",
     "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RDONLY, "mode=0555")` then
     `mkdir root/sys/fs/cgroup` and `bind_ro("/sys/fs/cgroup",
     root+"/sys/fs/cgroup")`. Only the cgroup subtree (needed for the memory
     limit) is exposed; the rest of `/sys` is an empty ro tmpfs. A whole-`/sys`
     ro bind is available as an opt-in for tools that need more, but is NOT the
     default.
6. **Writable scratch tmpfs mounts (sizes are the OOM-budgeted defaults, §M8):**
   a. **`/root` (the box HOME):** `mount("tmpfs", root+"/root", "tmpfs",
      MS_NOSUID|MS_NODEV, "size=256m,mode=0700")`. The agent's `HOME` is `/root`,
      NOT `/work` — so agent dotfiles (`~/.claude`, `~/.npm`, `~/.config`,
      `~/.cache`) land in ephemeral tmpfs and never pollute the persistent
      project tree. (M2.)
   b. **`/tmp`:** `mount("tmpfs", root+"/tmp", "tmpfs", MS_NOSUID|MS_NODEV,
      "size=<tmp_size>,mode=1777")`. Default `tmp_size = "256m"` (was 1 GiB;
      shrunk for the ~30-session budget, §M8).
   c. **`/run`:** `mount("tmpfs", root+"/run", "tmpfs", MS_NOSUID|MS_NODEV,
      "size=16m,mode=0755")`.
   d. **`/var/tmp`:** `mount("tmpfs", root+"/var/tmp", "tmpfs",
      MS_NOSUID|MS_NODEV, "size=64m,mode=1777")` (mkdir `root/var` first).
7. **`/dev` (tmpfs + curated nodes):**
   - `mount("tmpfs", root+"/dev", "tmpfs", MS_NOSUID|MS_NOEXEC, "size=4m,mode=0755")`.
   - Bind these host device nodes read-write as files:
     `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
     `/dev/tty`. (Bind, not mknod: an unprivileged user namespace cannot
     `mknod` device nodes; bind-mounting existing nodes is allowed.)
   - **pts/ptmx for TTY agents:**
     `mkdir root/dev/pts`,
     `mount("devpts", root+"/dev/pts", "devpts", MS_NOSUID|MS_NOEXEC,
     "newinstance,ptmxmode=0666,mode=0620")`, then symlink
     `root/dev/ptmx → pts/ptmx`. This gives the box its own pty instance
     (`newinstance`), required for the in-box pty allocation (§3.5).
   - Symlinks: `/dev/fd→/proc/self/fd`, `/dev/stdin→/proc/self/fd/0`,
     `/dev/stdout→…/1`, `/dev/stderr→…/2`. `/dev/shm` as a tmpfs
     (`size=64m,mode=1777` — shrunk from 256 MiB, §M8).
8. **`/work` — the project mount (Decision D3, resolved):** bind-mount the
   project directory at the **canonical path `/work`** (NOT the host CWD identity
   path), read-write but `nosuid,nodev`:
   `mount(project, root+"/work", NULL, MS_BIND|MS_REC, NULL)` then
   `mount(NULL, root+"/work", NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_REC,
   NULL)` (remove any setuid bit power from files under the project; still
   writable — the agent must edit the project). Rationale for `/work` over
   identity mount: (a) box identity is stable and host-path-independent (owner
   constraint — "no host-CWD identity mount"); (b) simpler mount plan. The box
   HOME is `/root` (step 6a); the initial cwd is `/work` (step 11).
   **Known implication (documented, accepted):** Claude Code persists a
   per-directory conversation history keyed by absolute path. Under `/work` all
   projects share the path `/work`; but the box has no persistent `~/.claude`
   (HOME is ephemeral tmpfs), so history is not persisted across ephemeral
   sessions anyway. Optional per-project persistence via `cred_mount`/state dir
   is deferred (§10, D3).
9. **`/proxy/proxy.sock` — the one door:** `mkdir root/proxy`, create an empty
   file `root/proxy/proxy.sock`, then bind-mount the host proxy socket onto it:
   `mount(hostSockPath, root+"/proxy/proxy.sock", NULL, MS_BIND, NULL)`. Proven
   to cross the netns (foundational spike). Mode 0600.
9a. **Opt-in credential mounts (`cred_mount`, Class-B/C provisioning — B4/§5.7):**
   for each entry in `options.cred_mount` (e.g. `~/.codex`, `~/.config/gh`),
   bind-mount the host directory/file into the box at the **same relative path
   under the box HOME** (e.g. host `~/.codex` → box `/root/.codex`). **Read-only
   by DEFAULT (N5)**; only an explicit `:rw` suffix mounts read-write (for in-
   place token refresh — unsafe under concurrent sessions, §5.7). These are the
   ONLY host credential paths that ever enter a box, and only when the user
   explicitly lists them. Each mounted credential is thereby "in the box":
   exfil-contained by egress policy but NOT theft-proof. cove logs a one-line
   warning at launch naming each `cred_mount` and its ro/rw mode.
9b. **Runtime toolchain mounts (`runtime_mount`, reflex replacement — §1.6/§5.7):**
   before pivot, cove bind-mounts each resolved runtime toolchain directory at
   the **same absolute path** inside the box, read-only with `nosuid,nodev`. The
   launcher auto-resolves the invoked agent and its Node interpreter from the
   host `PATH`; for nvm/volta/asdf-style layouts it mounts the node version root
   that contains both `bin/` and `lib/node_modules/...`, not only `bin/`.
   Ancestors such as `/home/<user>`, `/home`, `/root`, `/etc`, or `/` MUST NOT be
   mounted. cove creates empty ancestor directories in the tmpfs root (e.g.
   `/home/<user>/.nvm/versions/node`) and binds only the toolchain leaf, so HOME
   dotfiles remain absent. Explicit `options.runtime_mount` entries are added on
   top of auto-resolution and use the same read-only same-path mount. cove logs a
   one-line launch note naming each runtime mount and its ro mode.
10. **Pivot into the new root (MANDATORY `pivot_root`; chroot fallback FORBIDDEN
    — B3):** `chdir(root)`; `mkdir(root+"/.oldroot")`;
    `pivot_root(root, root+"/.oldroot")`; `chdir("/")`;
    `mount(NULL, "/.oldroot", NULL, MS_REC|MS_PRIVATE, NULL)`;
    `umount2("/.oldroot", MNT_DETACH)`; `rmdir("/.oldroot")`. A plain
    `chroot(".")` MUST NOT be used and MUST NOT be a fallback: the agent runs as
    uid-0 with `CAP_SYS_ADMIN` in its user namespace, so a chroot is not a
    security boundary (it can be escaped with `chdir`/`fchdir` tricks) AND the
    old root would remain mounted underneath, exposing every host secret with no
    kernel bug required. If `pivot_root` fails, the box setup MUST abort (write
    the failure to the status pipe, §3.1) — it MUST NOT continue with a weaker
    isolation. (Decision D4, revised.)
11. `chdir("/work")` so the agent's initial cwd is the project.
12. **cove-init drops its OWN capabilities after netns-up, before forking the
    agent (B3/§M7/N6):** all cap-needing work (mounts, `pivot_root`, bringing up
    `lo`, §3.6) is done by now. `cove-init` (PID 1, running at the agent's uid)
    MUST then, for itself: `prctl(PR_SET_NO_NEW_PRIVS,1,…)`; clear its capability
    **bounding set** (`for cap in 0..CAP_LAST_CAP: prctl(PR_CAPBSET_DROP,cap)`);
    and `capset` its effective/permitted/inheritable sets to empty. cove-init
    needs no capabilities afterward (pty alloc, the shim, reaping, and signal
    forwarding require none). This closes the window where a `ptrace_scope=0`
    agent could ptrace-hijack PID 1 to reclaim `CAP_SYS_ADMIN` and re-mount /
    escape.
13. **The agent child inherits the empty sets; still set them explicitly.** After
    `cove-init` forks the agent child (and does the pty/setsid wiring, §3.5), the
    child — which already inherits empty capability sets and `no_new_privs` from
    step 12 — re-asserts `PR_SET_NO_NEW_PRIVS` and an empty `capset` as
    belt-and-suspenders, then `execve`s the agent. The agent runs with **no
    capabilities** and no ability to gain privileges.

**Secrets are absent by construction.** No `~/.ssh`, `~/.aws`, `~/.claude`,
`~/.config/*`, browser profiles, or host HOME contents appear anywhere in this
tree — EXCEPT explicit opt-in `cred_mount` entries (step 9a). Runtime mounts
(step 9b) may create an otherwise-empty `/home/<user>/...` ancestor chain, but
only the read-only toolchain leaf is bound there; HOME itself and its dotfiles
are not mounted. There is no denylist to get wrong.

### 3.4 PID namespace + in-box init responsibilities

`cove-init` is **PID 1** of a fresh PID namespace. It MUST:

- **Reap zombies:** loop `waitpid(-1, …, WNOHANG)` on `SIGCHLD` so orphaned
  grandchildren (agents spawn many subprocesses) do not accumulate. As PID 1
  this is mandatory or the box leaks zombies.
- **Forward signals:** install handlers for `SIGTERM`, `SIGINT`, `SIGHUP`,
  `SIGQUIT`, `SIGTSTP`, `SIGCONT` and forward each to the agent's process group.
  **Window resize is NOT handled here** — `cove-init` has no controlling terminal
  (see §3.5): the launcher owns `SIGWINCH` on the host and pushes new window
  sizes to `cove-init` over the control pipe, which then `TIOCSWINSZ`es the pty
  master. This is the one coherent recipe (M1).
- **Correct exit status:** when the agent exits, `cove-init` exits with the
  agent's exit code (or 128+signal). Its exit tears down the PID namespace,
  which kills any stragglers.
- **Own `/proc`:** because it is PID 1, the `/proc` mount (§3.3 step 5) reflects
  only in-box PIDs; the agent cannot see host processes.

### 3.5 pty allocation and window resize (interactive agents) — the coherent recipe

Ownership split (Decision D5, revised to remove the §3.4 contradiction). Neither
`cove-init` nor the launcher makes `cove-init` a session leader with a
controlling tty; only the **agent** gets a controlling terminal (the pts slave).

**Launcher (host side), when its stdout is a TTY:**
1. Put the **host** terminal into raw mode (`termios`), saving the original to
   restore on exit (always restore, even on panic/signal).
2. Pass its own `stdin/stdout/stderr` fds to `cove __init` via fd inheritance,
   plus a dedicated **control pipe** fd (via `ExtraFiles`) for winsize updates.
3. Install a host `SIGWINCH` handler. On start and on each `SIGWINCH`, read the
   host window size (`TIOCGWINSZ` on the host tty) and write the new `(rows,
   cols, xpix, ypix)` as a fixed 8-byte record to the control pipe.

**`cove-init` (box side), when a TTY is present:**
4. Open `/dev/ptmx` (the box `newinstance` devpts) → pty **master** fd + slave
   name.
5. Fork the agent child; in the child: `setsid()`, open the pts **slave**, set
   it as controlling terminal (`TIOCSCTTY`), `dup2` it to the agent's
   stdin/stdout/stderr, then `execve` the agent. **Only the agent is the session
   leader with the controlling tty.**
6. In `cove-init` (parent): run two copy loops between the **inherited host
   stdio fds** and the **pty master** (host-stdin→master, master→host-stdout).
7. Run a reader on the control pipe; each 8-byte winsize record →
   `ioctl(master, TIOCSWINSZ, &winsize)`. This is the only window-resize path.
   `cove-init` does NOT itself receive `SIGWINCH` (it has no controlling tty).

On agent exit, `cove-init` closes the master and exits with the agent's status;
the launcher restores the saved host `termios`. Budget ~100 lines; known recipe.

When stdout is **not** a TTY (piped / non-interactive), skip the pty and the
control pipe entirely; wire the agent's stdio directly to the inherited fds.

### 3.6 NET namespace (loopback only)

- The child is in a fresh network namespace with only the `lo` interface, which
  `cove-init` brings up: open an `AF_INET`/`SOCK_DGRAM` socket, `SIOCGIFFLAGS`
  on `lo`, OR-in `IFF_UP|IFF_RUNNING`, `SIOCSIFFLAGS` (exact recipe from the
  lockbox prototype). No veth, no route, no gateway, no bridge.
- Result: any raw socket to any external IP returns `ENETUNREACH` immediately
  (proven). A tool that ignores `HTTPS_PROXY` cannot reach the network at all —
  it fails closed. This is why cove needs no transparent redirection.
- The **only** egress is the bound Unix socket `/proxy/proxy.sock`, reached via
  the in-box TCP shim (§3.7).

### 3.7 In-box TCP↔unix shim and base-URL loopback

`cove-init` runs two kinds of loopback listeners inside the netns. Ports come
from config and dynamic allocation — **nothing is hardcoded to 8080/8091**.

**(a) The CONNECT shim** (for every proxy-honoring agent):
- Listen on `127.0.0.1:<options.proxy_port>` (default 8080; the value the
  `HTTPS_PROXY` env var is derived from, §3.8). TCP, inside the netns.
- For each accepted TCP connection, `dial` the Unix socket `/proxy/proxy.sock`
  and splice bytes bidirectionally, **1:1** (one TCP conn ↔ one Unix conn). The
  proxy sees a stream beginning with the client's HTTP `CONNECT`. Protocol-
  agnostic; it just moves bytes. ~30 lines.

**(b) The base-URL plain-HTTP loopback** (M3 — for tools that ignore
`HTTPS_PROXY`, e.g. kimi). One listener per `inject` stanza whose
`base_url_value` is `http://127.0.0.1:0` (port 0 = "cove picks a free port"):
- `cove-init` binds a fresh ephemeral `127.0.0.1:<dynamic>` listener and records
  the chosen port. It sets the stanza's `base_url_env` (e.g. `KIMI_BASE_URL`) to
  `http://127.0.0.1:<dynamic>` in the agent env (§3.8). Dynamic allocation
  guarantees no collision with the shim port or between multiple base-URL tools.
- **This listener is the single owner of the kimi flow** (resolving the §3.8
  contradiction). For each incoming plain-HTTP request it: opens a connection to
  the CONNECT shim (a), writes `CONNECT <stanza.host>:443\r\n\r\n`, waits for
  `200`, then **originates TLS to the proxy** using the box's cove-CA trust and
  replays the request over that TLS conn. (No preamble is involved anywhere —
  session identity is fixed host-side by the per-session socket, M6/§4.1.) The
  proxy therefore handles it via the **normal `inject` path** (§4.5/§14) —
  MITM-terminate, inject the key, upstream TLS — exactly as for a CONNECT-based
  tool. The real upstream host is conveyed by the `CONNECT <stanza.host>:443`
  line; the box never holds the key.
- Net effect: kimi is a normal Class-A `inject` at the proxy; the only extra
  machinery is this in-box adapter that turns kimi's plain-HTTP base-URL calls
  into a CONNECT the shim/proxy already understand. No hardcoded port; no second
  proxy design.

### 3.8 Environment variables injected into the agent

`cove-init` sets the agent's environment to a **curated** set (it does NOT
inherit the host environment, to avoid leaking host secrets in env vars).

**Env hygiene:** before `execve`, the agent env MUST contain none of cove's
bootstrap vars (`COVE_DIR_FD`, `COVE_STATUS_FD`, `COVE_CTL_FD`, `COVE_TERM`,
etc.); directives (CA bytes, dummy envs, cred_mounts, runtime_mounts) are passed
via a pipe `ExtraFiles` fd, never an env var, so they never appear in
`/proc/<agent>/environ`. (See §13.1.)

**Fd hygiene (N7):** the inherited control fds (`COVE_DIR_FD=3`,
`COVE_STATUS_FD=4`, `COVE_CTL_FD=5`) and the **pty master** MUST NOT be inherited
by the agent — otherwise the agent could write spurious `OK`/`ERR` to the status
pipe, or read/inject winsize records (resize-DoS / winsize theft). The **agent
child** closes fds 3/4/5 and the pty master immediately before `execve` (after
writing its one `OK` to fd 4); see §13.2 step 13. `cove-init` (PID 1) keeps
`COVE_CTL_FD` and the pty master for its own winsize/pty copy loops. (Marking
these `O_CLOEXEC` at creation is NOT sufficient, because cove-init itself must
keep `COVE_CTL_FD`/pty-master across its own lifetime; the explicit close in the
agent-child fork is the correct scoping.)

Base set:

- `HOME=/root` (ephemeral tmpfs home, §3.3 step 6a — NOT `/work`)
- `USER=root`, `LOGNAME=root`
- `PATH=<runtime bin dirs>:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
  where each runtime mount contributes its `bin/` directory when present (or the
  mount directory itself when it is already a `bin`/tool dir). Runtime prefixes
  come first so `claude`/`codex`/`node` from nvm/volta/asdf resolve exactly as
  they did in the host shell.
- `TERM` = copied from host (needed for TUI).
- `TMPDIR=/tmp`
- `LANG`/`LC_*` = copied from host if set (locale correctness), else `C.UTF-8`.
- Proxy routing (every agent). The port is `options.proxy_port` (default 8080);
  cove derives the URL string — it is NOT hardcoded:
  - `HTTPS_PROXY=http://127.0.0.1:<proxy_port>`
  - `HTTP_PROXY=http://127.0.0.1:<proxy_port>`
  - `https_proxy` / `http_proxy` (lowercase duplicates — some clients only read
    one case).
  - `NO_PROXY=127.0.0.1,localhost` / `no_proxy=…` (so the shim endpoint and any
    base-URL loopback endpoints are not double-proxied).
- CA trust (so the agent accepts the proxy's MITM cert for `inject` hosts):
  - `NODE_EXTRA_CA_CERTS=/etc/ssl/certs/cove-ca.pem`
  - `SSL_CERT_FILE=/etc/ssl/certs/cove-ca-bundle.pem` (cove CA appended to the
    system bundle copy — see §7.5)
  - `SSL_CERT_DIR=/etc/ssl/certs`
  - `REQUESTS_CA_BUNDLE=/etc/ssl/certs/cove-ca-bundle.pem` (python/requests)
  - `CURL_CA_BUNDLE=/etc/ssl/certs/cove-ca-bundle.pem`
  - `GIT_SSL_CAINFO=/etc/ssl/certs/cove-ca-bundle.pem`
  - `CODEX_CA_CERTIFICATE=/etc/ssl/certs/cove-ca.pem` (codex-specific, per docs)
  - `CLAUDE_CODE_CERT_STORE`/mTLS vars: not set (not needed).
- **Placeholder/dummy credentials** for `inject` tools (so the client believes
  it is authenticated and does not prompt for login): e.g. for a claude API-key
  tool, `ANTHROPIC_API_KEY=cove-dummy-do-not-use`. The real key is never here.
  The set of dummy vars is derived from the config's `inject` stanzas (§5).
- **`base_url_env` rewrites** (per config): for tools configured with a
  `base_url_env`, set that env var. Two cases distinguished by `base_url_value`:
  - **Plain-HTTP loopback** (`base_url_value = "http://127.0.0.1:0"`, e.g. kimi
    which ignores `HTTPS_PROXY`): cove-init sets the env var to
    `http://127.0.0.1:<dynamic>` where `<dynamic>` is the port of the base-URL
    loopback listener (§3.7b). That listener converts the call into a
    `CONNECT <host>:443` to the shim → the normal `inject` path. Dynamic port; no
    hardcoding.
  - **Real HTTPS host over proxy** (`base_url_value = "https://<host>"`, e.g.
    claude via `ANTHROPIC_BASE_URL=https://api.anthropic.com`): the value is set
    to the real host and `HTTPS_PROXY` + the cove CA route+MITM+inject it. (For
    claude the host holds the OAuth access token and delegates refresh — §5.4.)
  - The exact per-tool env var name comes from the stanza's `base_url_env`
    field; cove does not hardcode tool names in the launcher.
- **Dummy credential env vars** for `inject` stanzas with a `dummy_env`
  (§3.8 placeholder note above); the real key is never in the box.
- **`cred_mount` / `env_passthrough` (Class-B/C provisioning, §5.7):** for a
  `cred_mount` the credential arrives as a bind-mounted file/dir (§3.3 step 9a),
  no env var needed. For `env_passthrough`, the named host env vars (glob-matched,
  §D10) are copied into the agent env — these DO enter the box; only Class-B/C
  session material the user accepts containing should be listed.

The agent's own argv is passed through verbatim after `--`.

### 3.9 Teardown and crash cleanup

- **Normal exit:** when `cove-init` exits, the kernel destroys the PID/NET/IPC/
  UTS namespaces (last process gone). The mount namespace and its tmpfs root
  vanish when the last reference is dropped. The launcher, on reaping
  `cove-init`, MUST `umount2(rootdir, MNT_DETACH)` best-effort and
  `os.RemoveAll` the `/tmp/cove-root.XXXXXX` skeleton (the mkdtemp dir on the
  host side is just an empty mountpoint after teardown).
- **Crash / kill -9 of the launcher:** namespaces are refcounted by the kernel;
  when `cove-init` (child) also dies, they are reclaimed automatically. The only
  possible leak is the empty `/tmp/cove-root.XXXXXX` mountpoint directory. cove
  MUST, on every launcher start, sweep `/tmp/cove-root.*` older than a threshold
  (e.g. any that are not an active mountpoint) and remove them. A stale bind
  mount, if any, is detached with `MNT_DETACH`.
- **Crash of `cove-init` but agent survives:** impossible — killing PID 1 of a
  PID namespace kills the whole namespace (kernel guarantee). Agents cannot
  outlive `cove-init`.
- **Proxy dies mid-session:** the box's `/proxy/proxy.sock` connections break;
  new CONNECTs fail; the agent sees connection errors (fail-closed). cove does
  not auto-reconnect the box to a restarted proxy in v0 (the socket bind is
  fixed at launch); the session must be restarted. Documented limitation.

---

## 4. THE PROXY

`cove proxyd` is one shared host process. It is an **explicit** HTTP CONNECT
proxy (NOT transparent). Transparent capture (TPROXY/nft/SNI/DNS-intercept) is
rejected: loopback-only already makes egress unbypassable, so transparency's
only benefit (catching proxy-ignoring tools) is moot — those tools fail closed —
and it would drag back podman-class network complexity.

### 4.1 Socket and connection model (per-session sockets — identity is host-side)

To make audit identity **unforgeable by the in-box adversary** (M6), each session
gets its **own** Unix listening socket owned by the proxy; the session/agent
identity is fixed host-side at registration, never taken from an in-box
preamble.

- **Control socket:** the proxy listens on a Unix stream control socket at
  `$XDG_STATE_HOME/cove/proxyd.sock` (default `~/.local/state/cove/proxyd.sock`;
  mode 0600; owner-only). The launcher connects here to register a session.
- **Registration:** before building a box, the launcher sends a single control
  line `REGISTER <session_id> <agent_name>\n`. The proxy:
  1. creates a fresh per-session listener at
     `$XDG_STATE_HOME/cove/sessions/<session_id>.sock` (mode 0600),
  2. starts an accept goroutine that tags **every** connection on that socket
     with the registered `(session_id, agent_name)` — identity is structural,
     not self-reported,
  3. replies `OK <path>\n`.
  The launcher then bind-mounts `<path>` into the box at `/proxy/proxy.sock`
  (§3.3 step 9). The in-box adversary can open connections on that socket but
  every such connection is definitionally this session; it cannot spoof another
  session's id or a different agent name. **There is no in-box `X-Cove-Session`
  preamble** (removed — it was forgeable).
- **Teardown:** when the launcher's control connection closes (session over or
  launcher crash), the proxy closes and unlinks the per-session socket and drops
  the tag. A sweep on proxy start removes orphaned `sessions/*.sock`.
- **1:1 connection mapping.** Each accepted per-session Unix connection carries
  one client proxy stream (one goroutine per conn). No cross-session pooling.

### 4.2 The proxy request lifecycle

Per accepted per-session Unix connection:

1. Wrap the connection in a `*bufio.Reader` (`br`) and read the first request
   line using `br`. It MUST be `CONNECT host:port HTTP/1.1` (all agents use
   CONNECT for HTTPS). Parse `host` and `port`. **Plain-HTTP forward-proxy
   requests (absolute-form `GET http://…`, port 80) are explicitly NOT supported
   in v0** — the proxy responds `HTTP/1.1 405 Method Not Allowed` and audits a
   `deny`. (All seed traffic is HTTPS; a plaintext egress path is an
   unnecessary exfil surface. Package registries are all HTTPS.) A malformed or
   empty first line → `400`, audit `deny`, close (no crash).
2. **Allowlist match BEFORE any DNS resolution** (§4.3, §4.6). If the host is
   not matched, respond `HTTP/1.1 403 Forbidden\r\n\r\n` with a short body
   naming the denied host, write an audit `deny` record, and close.
3. Dispatch by policy, passing a reader that concatenates **`br`'s buffered
   remainder with the raw conn** (M5): after reading the CONNECT line, `br` may
   already hold pipelined bytes (a client may send the TLS ClientHello
   immediately). The `tls.Server` / splice MUST be handed
   `struct{ io.Reader; net.Conn }{ io.MultiReader(br.Buffered-as-Reader, conn),
   conn }` — i.e. a `net.Conn` wrapper whose `Read` first drains `br`'s buffered
   bytes then reads the raw conn. Never hand `tls.Server`/splice the bare `conn`
   (it would lose buffered ClientHello bytes). See §14 `bufConn`.
   - **`allow`** → opaque tunnel (§4.4).
   - **`inject`** → TLS-terminate + credential inject (§4.5 / authoritative §14).
4. Append an audit record (§4.9).

### 4.3 Allowlist matching (precise)

The allowlist is the union of all `allow` hosts and all `inject` hosts from the
config (§5). Matching is on the **CONNECT target host string** (the name the
client sent), case-insensitive, before resolution.

Rule syntax and precedence:

- **Exact host:** `api.anthropic.com` matches only `api.anthropic.com`.
- **Wildcard (single-label leftmost only):** `*.githubusercontent.com` matches
  `objects.githubusercontent.com` and `raw.githubusercontent.com` but NOT
  `githubusercontent.com` itself and NOT `a.b.githubusercontent.com` (exactly
  one label replaces the `*`). A bare `*` is **forbidden** in config (would
  allow everything) and MUST be rejected at config load.
- **Port:** a rule MAY specify `host:port`; if it does, the CONNECT port must
  match. If a rule omits the port, port `443` is assumed. Plain-HTTP (port 80,
  absolute-form `GET`) is NOT supported in v0 and is rejected `405` regardless of
  allowlist (§4.2), so no rule grants port 80. CONNECT to any port not `443`
  (or the explicit `:port` in a rule) is denied.
- **Precedence:** exact match wins over wildcard. If both an `allow` and an
  `inject` rule match the same host (misconfiguration), `inject` wins and a
  warning is logged at config load. Otherwise first-match by specificity;
  ties are a config-load error.
- **IP-literal CONNECT** (`CONNECT 1.2.3.4:443`): denied unless an exact rule
  lists that IP literal. Prevents DNS-rebind-style bypass via numeric targets.
- **No suffix-anywhere matching**, no regex. Two forms only: exact and
  single-label leftmost wildcard. This keeps the matcher auditable (~30 lines).

### 4.4 `allow` path — opaque tunnel

For an `allow` host:

1. Resolve the host **host-side** (§4.6), respecting a resolve timeout.
2. `net.Dial("tcp", resolvedIP:port)` to the upstream.
3. Respond to the client `HTTP/1.1 200 Connection Established\r\n\r\n`.
4. Splice bytes bidirectionally between the client conn and the upstream conn
   until either closes. **No TLS termination** — cove never sees plaintext for
   `allow` hosts; the client does real end-to-end TLS with the upstream. The
   in-box credential (OAuth token, SigV4 key) is used by the client directly and
   is only *egress-contained*, never seen by cove.
5. Audit record is emitted **at tunnel close** (NEW-2) with the final host, byte
   counts in/out, and duration (these are only known once the splice ends).
   Path/method are unknown (encrypted) — recorded as `-`. (Contrast: `deny`
   records are emitted immediately, §12.3.)

### 4.5 `inject` path — TLS-terminate + credential inject (overview; §14 authoritative)

This subsection is the conceptual overview. **The concrete, normative
implementation — including how the HTTP server is run so h2 is actually spoken
and streaming is preserved — is §14. Where this prose and §14 differ, §14
wins.** Do not implement the "manual read one request, forward" loop implied by
older prose; implement §14's `http2.Server.ServeConn` + `httputil.ReverseProxy`.

For an `inject` host, cove MITMs the connection with its own CA so it can add the
real credential the box does not hold:

1. Match + resolve (§4.6).
2. Respond `200 Connection Established`.
3. **TLS-terminate toward the client** with a cove-CA leaf for the host (§4.7);
   the box trusts the cove CA (§3.8).
4. **Originate TLS toward the upstream** with the **host's real root store**
   (upstream verification is never weakened).
5. **Per request (via ReverseProxy `Rewrite`, §14):**
   - **Inject:** `Header.Set(header_name, subst(header_template, secret))` —
     overwrite, not append.
   - **Strip conflicting auth headers (C1):** delete every header in the
     stanza's `strip_headers` list (§5.3) BEFORE setting the injected one. This
     is essential: the in-box client holds a **dummy** credential and will send
     it (e.g. claude sends `x-api-key: cove-dummy…`). If cove injects
     `Authorization: Bearer <oauth>` but leaves the dummy `x-api-key` present,
     Anthropic may honor the dummy and reject the request. For the anthropic
     stanza `strip_headers = ["x-api-key"]`; sensible defaults ship per seed
     stanza (§5.5). cove also always strips hop-by-hop and `X-Forwarded-*`
     headers.
   - Set `Host`/authority to the real host.
6. **Audit** host, method, path, status, bytes (§4.9). This is the only point
   cove sees request metadata — exactly what the audit log needs.

Only `inject` hosts are MITM'd. `allow` hosts remain opaque. MITM'd hosts are few
(1–2 in the default config).

### 4.6 Host-side DNS + allowlist-before-resolve

- The box has an empty `resolv.conf` and `nsswitch hosts: files` — it cannot
  resolve names. All name resolution happens **host-side in the proxy**.
- **Order is mandatory:** match the CONNECT host string against the allowlist
  **first**; only if it matches does the proxy call `net.Resolver.LookupHost`.
  This prevents a denied name from ever hitting DNS (no DNS-based exfil channel;
  closes the CVE-2025-55284-style DNS exfil vector at the design level).
- Resolution uses the host's normal resolver. Resolved IPs are used immediately
  for the dial; cove does not re-check the IP against a rule (the *name* was the
  policy unit). To prevent a TOCTOU rebind between resolve and connect, cove
  dials the exact IP it resolved (single lookup, single dial).

### 4.7 The CA (generation, storage, distribution, MITM scope)

- **Generation:** `cove setup` (and lazily `cove proxyd` on first start if
  absent) generates an **RSA-2048** self-signed CA (RSA chosen deterministically
  over ECDSA for the widest client compatibility — every TLS stack on the seed
  list accepts RSA; some embedded/older stacks are picky about P-256 chains):
  - CA cert → `~/.config/cove/ca.pem` (0644; it is public).
  - CA private key → `~/.config/cove/ca-key.pem` (**0600**, host-only, NEVER in
    a box). Subject `CN=cove local CA, O=cove`. `notAfter` ~10 years.
    `BasicConstraints: CA:TRUE, pathlen:0`. `KeyUsage: certSign, crlSign`.
- **In-memory:** `cove proxyd` loads the CA key into memory at startup and
  mints per-host **RSA-2048 leaf** certs on demand (SAN = the requested host),
  signed by the CA, cached by host name for the process lifetime. Leaf validity
  ~short (e.g. 30 days) — irrelevant since regenerated per process.
- **Distribution to the box:** only the CA *public* cert is placed in the box,
  at `/etc/ssl/certs/cove-ca.pem`, plus a concatenation of the system bundle +
  cove CA at `/etc/ssl/certs/cove-ca-bundle.pem`. The box trusts it via the env
  vars in §3.8. The private key never enters any box.
- **Which hosts get MITM'd:** exactly and only the `inject` hosts. `allow` hosts
  are opaque tunnels and are never presented a cove-signed cert (the client does
  real TLS to the real host).
- **Pinning fallback:** if any provider ever pins its certificate (none on the
  seed list do — verified), the fix is to switch that host from `inject` to
  `allow` and put the credential *in the box* (Class-A degrades to Class-B
  handling for that one host). The audit log still contains the (now opaque)
  connection. This fallback requires only a config edit.

### 4.8 HTTP/2 handling for MITM inject hosts (sharpest correctness point)

`api.anthropic.com` (claude) negotiates **HTTP/2**. Terminating and
re-originating h2 while injecting a header, preserving streaming, is the single
riskiest implementation detail. Specification:

- **ALPN:** during the client-facing TLS handshake, cove's `tls.Config`
  advertises `NextProtos: ["h2", "http/1.1"]`. The client (node/claude) will
  select `h2`. cove MUST honor whatever ALPN the client selects and speak that
  protocol on the client side.
- **Client-side h2 server (CORRECTED — B2):** cove does NOT get automatic h2 by
  handing a hand-handshaked `tls.Conn` to `http.Server.Serve` over a fake
  listener — that path does **not** speak h2 (the stdlib only wires its bundled
  http2 when it owns the TLS handshake via `ServeTLS`/`ListenAndServeTLS`, which
  cove cannot use because it already terminated TLS after CONNECT). Two consequences
  the earlier draft got wrong: (a) a bare `http.Server.Serve` would speak only
  HTTP/1.1 to an h2 client → protocol error; (b) a one-shot listener returning
  the conn then `io.EOF` makes `Serve` return **while the stream is still in
  flight**, tearing down every real response mid-stream. The fix is to drive the
  connection with an explicit **`golang.org/x/net/http2` server** whose
  `ServeConn` **blocks** until the connection is fully done:
  ```go
  h2s := &http2.Server{}
  h2s.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: rp}) // blocks correctly, speaks h2
  ```
  If ALPN negotiated `http/1.1` (downgrade or an h1 host), cove serves that conn
  with `http.Serve` over a **blocking one-shot listener** (§14, N2) — the correct
  stdlib h1 path, NOT a hand-rolled loop. This makes `golang.org/x/net/http2` a
  **sanctioned dependency** (dep list in §16 alongside `BurntSushi/toml`). Each h2
  stream surfaces as one `http.Request` to cove's `ReverseProxy` handler.
- **The handler is a reverse proxy with injection:** use
  `net/http/httputil.ReverseProxy` (stdlib) with:
  - `Director`/`Rewrite` that sets the target scheme/host and injects the
    credential header (overwriting any dummy).
  - `Transport` = an `*http.Transport` with `ForceAttemptHTTP2: true` and the
    **host's real root CAs**, so the upstream leg is independently negotiated h2
    (or h1 — the Transport negotiates per upstream ALPN). This decouples
    client-side and upstream protocol versions: client h2 ↔ upstream h2, but
    cove is not manually framing h2 — the stdlib does it on both legs.
  - **Streaming preserved:** `ReverseProxy` streams request and response bodies;
    for SSE/streaming completions set `FlushInterval = -1` (immediate flush) so
    token-by-token streaming is not buffered. This is critical for claude's
    streaming responses.
  - Trailers, keepalive, and chunking are handled by the stdlib on both legs;
    cove does not hand-roll framing.
- **Why this is safe:** cove never bridges raw h2 frames across the boundary; it
  fully terminates one HTTP semantic request per stream and re-issues it. Header
  injection happens at the `http.Request` level (`req.Header.Set`). This is the
  standard, correct way and avoids the fragile "rewrite bytes in an h2 stream"
  trap.
- **FIRST THING TO PROVE (see §9):** a real `claude` completion (200, streamed)
  through MITM+injection over h2. The precode/generic-cred spikes proved CA
  acceptance to a *synthetic 401* only; a real streamed 200 was NOT yet spiked.
  This is milestone M4 and gates the whole `inject` feature.
- **Fallback if h2 injection misbehaves for a host:** downgrade that host's
  client-facing ALPN to `http/1.1` only (`NextProtos: ["http/1.1"]`) — claude
  supports h1 too; injection over h1 is trivial and already proven-adjacent. If
  even that fails, fall back to `allow` + in-box key (§4.7 pinning fallback).

### 4.9 Audit log

- **Location:** `~/.local/state/cove/audit.log` (`$XDG_STATE_HOME`), append-only,
  0600. Rotated by size (e.g. 64 MiB → `audit.log.1`, keep N=5) — cove's own
  rotation, no logrotate dependency.
- **Format:** one JSON object per line (JSONL), fields:
  ```
  {"ts":"2026-07-05T14:03:22.145Z","session":"<8-hex>","policy":"inject|allow|deny",
   "host":"api.anthropic.com","port":443,"method":"POST","path":"/v1/messages",
   "status":200,"bytes_up":1234,"bytes_down":56789,"dur_ms":812,"agent":"claude"}
  ```
  For `allow` (opaque) records, `method`/`path`/`status` are `"-"`/`null`
  (encrypted, unknown). For `deny`, `status` is 403 and the rest of the request
  is unknown.
- **`session`/`agent`** are the identity fixed **host-side** at registration
  (§4.1, Decision D6 revised): every connection on a session's dedicated socket
  is tagged with that session's `(id, agent)` by the proxy. These fields are
  therefore **trustworthy** — the in-box adversary cannot forge them. (There is
  no in-box preamble.) They correlate all requests of one `cove -- claude` run.
- **Purpose:** when enabled, the audit log is the detection control for the
  misuse/oracle residual (§8). It is nearly free and MUST be enabled by default;
  an explicitly audit-disabled session writes no records.

### 4.10 Proxy lifecycle

- **Auto-spawn + health check:** the launcher connects to `proxyd.sock` and
  sends a control line `PING\n`; a healthy proxy replies `PONG <version>\n`
  within a short deadline (250 ms). If the socket is absent, refuses connection,
  or does not answer `PONG`, the launcher starts `cove proxyd` (double-fork/
  detach, or a systemd user unit if installed) and retries `PING` on a bounded
  loop (e.g. up to 2 s). Only a successful `PONG` (and a matching `version`)
  counts as live; a stale socket file with no listener is treated as down and the
  launcher unlinks it before spawning. The `REGISTER` handshake (§4.1) follows a
  successful `PING`.
- **Singleton:** `cove proxyd` takes an exclusive `flock` on
  `~/.local/state/cove/proxyd.lock`; a second instance exits 0 if one is
  already healthy.
- **Config reload:** `cove proxyd` reloads the config on `SIGHUP` and on
  detecting mtime change of the config file (re-read before each new *session*,
  cheap). Secret *values* are read per-request with an mtime cache (§5.4).
- **Fail-closed:** if the proxy cannot start, the launcher aborts the run with a
  clear error (it will NOT run an agent with no proxy — that would be a box with
  a dead-end socket, harmless but useless). If the proxy dies mid-session, boxes
  lose egress (fail-closed).

---

## 5. CREDENTIAL MODEL & CONFIG

### 5.1 Policy model and specialized inject modes

Every destination host maps to exactly one policy kind:

- **`allow`** — opaque tunnel; whatever credential the client holds is used
  directly and only egress-contained. The credential lives *in the box*.
- **`inject`** — header replacement, including the `github-basic` transform;
  the real key is *never in the box*.
- **`sigv4`** — the v1 S3-only re-signer. It MITMs, enforces its S3 policy,
  spools finite bodies, and signs with host-side credentials.
- **`mtls`** — upstream client-certificate termination restricted by exact host,
  method, and path-prefix policy.

`allow`, `inject`, `sigv4`, and `mtls` are mutually exclusive for a host rule;
equal-key cross-kind duplicates are configuration errors. These are specialized
proxy injection modes, not a general signing broker. `sigv4` is deliberately a
policy-defined S3 subset, not general AWS support.

### 5.2 Credential classes → policy mapping

From the CLI-auth research (three classes):

| Class | Nature | Example | Policy | Why |
|---|---|---|---|---|
| **A** | Simple bearer / API key | Anthropic API key, Hetzner token, GitHub PAT, Cloudflare token, Runpod key, HF token, Gemini API key, **kimi API key** | **`inject`** | Key can be added as a header host-side; keep it out of the box. |
| **B** | OAuth session (access+refresh) | claude OAuth, codex ChatGPT, gemini Google, gh OAuth, wrangler OAuth | **`allow`** + **`cred_mount`** (session lives in box) — EXCEPT claude OAuth, which is `inject` via host-side token+refresh (§5.4) | The session token *is* the auth material the client refreshes; generally cannot be injected. |
| **C** | Request-signed (SigV4) / mTLS | aws, s5cmd / partner API | **`sigv4`** or **`mtls`** when the narrow policy fits; otherwise **`allow`** + short-lived `cred_mount`/`env_passthrough` | A generic header cannot replace a request signature or client certificate, but cove implements these two constrained host-side forms. |

**kimi reclassification (explicit, was Class-B in FINAL-DESIGN):** kimi is run in
its **API-key mode** here, which is a simple bearer → **Class-A `inject`**. This
is a deliberate change from the FINAL-DESIGN "kimi = Class-B OAuth" note, made
because (a) kimi's OAuth client ignores `HTTPS_PROXY` and is awkward to contain,
while (b) its API-key mode honors `KIMI_BASE_URL`, so the strong "key never in
the box" guarantee is achievable via the base-URL loopback (§3.7b). Users who
insist on kimi OAuth instead add kimi's OAuth hosts to `allow` + `cred_mount`
`~/.kimi` (Class-B handling); that path is documented but not the seed default.

**Class-B/C provisioning:** OAuth sessions and unsupported request-signed modes
still need explicit `cred_mount` or `env_passthrough` and therefore live in the
box. The exception is a configured `[[sigv4]]` or `[[mtls]]` policy: it keeps
its constrained host-side credential material outside the box. Without an
active specialized stanza or explicit mount/passthrough, cove does not silently
provide a credential.

**Honest limits per class:** Class-B/C credentials, once `cred_mount`ed, **live
in the box**: exfil-contained by egress policy but NOT theft-proof (a compromised
agent can read the mounted session file) and misusable at their allowed host (the
oracle residual, §8). Only Class-A keys get the strong "never in the box"
guarantee.

### 5.3 Current config schema, outcomes, and local verification

`[[inject]]` supplies header credentials. Its normal schema is `host`,
`header_name`, `header_template` containing `{secret}`, `secret`, optional
`strip_headers`, `dummy_env`, `base_url_env`/`base_url_value`, `alpn`, and
credential metadata (`issuer`, `max_ttl`, `bootstrap_ref`). The Git transform is
instead `host = "github.com"`, `transform = "github-basic"`,
`header_name = "Authorization"`, `basic_username = "x-access-token"`, `secret`,
`github_repositories`, and `allowed_methods`; it is limited to scoped Git
smart-HTTP requests. GitHub API PAT injection is an ordinary Bearer `[[inject]]`
for `api.github.com`. The shipped defaults retain GitHub OAuth `allow` entries;
PAT migration removes both `github.com` and `api.github.com` allow entries and
enables both commented stanzas.

`[[sigv4]]` requires `host`, `access_key_id`, `secret_access_key`, optional
`session_token`, `account_id`, `service = "s3"`, `region`,
`allowed_methods`, `allowed_operations`, `allowed_resources`,
`max_body_bytes`, and optional `allow_unsigned_payload`, `alpn`, and credential
metadata. `[[mtls]]` requires exact `host`, `client_cert`, `client_key`,
`rules` (each `{ method, path_prefix }` pair), and optional `alpn` and metadata.
Secret references are `file:`, `env:`, or `json:`; examples must never contain
real values or `keyring:` references.

#### 5.3.1 S3 SigV4 supported/rejected matrix

| Mode | Result |
|---|---|
| Header `AWS4-HMAC-SHA256`, finite S3 payload, empty payload, ordinary transfer chunking | Supported: buffer/hash the true payload and replace the dummy signature. |
| `UNSIGNED-PAYLOAD` | Supported only with `allow_unsigned_payload=true`; still buffered and capped. |
| Session credentials and rotated file/json sources | Supported; real session token is injected and file/json sources are resolved per request. |
| Get/Head/Put/Delete/List and constrained Copy | Supported only when method, classifier operation, and every resource match policy. |
| Presigned query | 400 `presigned_url`. |
| AWS streaming payload/trailers, `aws-chunked`, WebSocket/event stream | 400 `streaming_signature`. |
| SigV4a/MRAP | 400 `sigv4a`; unsupported endpoint forms are config errors. |
| Multipart | 403 `policy_operation`. |
| Non-S3, FIPS/dualstack/accelerate/access-point/Outposts/China/Gov/custom endpoint forms | Config error. |
| Body cap/spool failure; missing real secret or signer/certificate construction | 413 `body_too_large`; spool failure is 502 `spool_failure` (local host-storage failure, audited `policy:"deny"`, no upstream contacted); otherwise 502 `secret_unavailable`; no upstream dial. |

#### 5.3.2 Audit and test contract

Audit `policy` remains `allow`, `inject`, or `deny` (with the existing separate
`warn` record). `reason` is a stable non-secret code: `malformed_request`, `presigned_url`,
`streaming_signature`, `sigv4a`, `policy_method`, `policy_operation`,
`policy_resource`, `policy_header`, `body_too_large`, `spool_failure`,
`secret_unavailable`, `mtls_not_requested`, or `upstream_tls`.
Successful specialized requests use `policy:"inject"`; local policy/malformed
failures use `policy:"deny"`. Optional non-secret fields are `auth_mode`
(`header`, `github-basic`, `sigv4`, `mtls`), `operation`, `resource`, `account`,
`region`, and `service`. Audit records never include credential values, access
key IDs, signatures, tokens, canonical requests, or certificate private keys.

The test suite uses only local harnesses: a Git smart-HTTP backend for the
GitHub Basic transform, a hand-rolled SigV4 verifier that does not import the
AWS SDK, and a locally generated mTLS verifying upstream. No test contacts AWS,
GitHub, an issuer, or hardware.

### 5.3a Legacy v0 configuration reference (superseded; non-normative)

- **Location:** `~/.config/cove/config.toml` (`$XDG_CONFIG_HOME` respected).
  **Decision D7 (resolved, single path):** the config is TOML and cove **vendors
  `github.com/BurntSushi/toml`**. There is exactly ONE config-parsing path; the
  hand-rolled-parser alternative is DELETED (it was a maintenance and
  correctness hazard). This is a sanctioned dependency (see §16 dep list).
- **Top-level structure:**

```toml
# Global options
[options]
tmp_size   = "256m"      # /tmp tmpfs size (default 256m; see OOM budget §M8)
proxy_port = 8080        # in-box shim TCP port (rarely changed). MUST be >=1024:
                         # the shim binds it AFTER cove-init drops CAP_NET_BIND_SERVICE
                         # (§13.2 step 12a), so a privileged port (<1024) would fail
                         # to bind. Validate() rejects <1024 (NEW-3).
audit      = true        # audit log on/off (default true)

# Class-B/C provisioning (§5.7). Host paths bind-mounted INTO the box at the same
# relative path under box HOME (/root). These credentials DO enter the box.
# Mounted READ-ONLY by default (N5); append ":rw" to allow in-place token refresh
# (unsafe under concurrent sessions — §5.7). Empty by default (nothing enters box).
cred_mount = []          # e.g. ["~/.codex:rw", "~/.config/gh"] for codex/gh

# Runtime toolchain dirs mounted read-only at the SAME absolute path (§3.3 step
# 9b). Usually empty: cove auto-resolves nvm/volta/asdf-installed agent
# runtimes. System-installing the tool under /usr/local/bin is the
# max-isolation path and needs no runtime mount.
runtime_mount = []       # e.g. ["~/.nvm/versions/node/v22.0.0"]

# Env vars copied into the box (glob-matched, §D10). These values DO enter the
# box. Only Class-B/C session material you accept containing. No bare "*".
env_passthrough = []     # e.g. ["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN"]

# ALLOW entries: opaque-tunnel hosts. Credential lives in the box.
# A list of host rules (exact or single-label leftmost wildcard).
allow = [
  "chatgpt.com",
  "auth.openai.com",
  "*.githubusercontent.com",
  "registry.npmjs.org",
]

# INJECT stanzas: key kept OUT of the box, added host-side.
[[inject]]
host          = "api.anthropic.com"     # exact host (or wildcard) to MITM
header_name   = "x-api-key"             # header cove sets on each request
header_template = "{secret}"            # value; {secret} = real key
secret        = "file:~/.config/cove/secrets/anthropic-api-key"  # secret ref
dummy_env     = "ANTHROPIC_API_KEY"     # env var set to a dummy in the box
dummy_value   = "cove-dummy-do-not-use" # placeholder the client sees
base_url_env  = "ANTHROPIC_BASE_URL"    # OPTIONAL: env var pointed at endpoint
base_url_value = "https://api.anthropic.com"  # OPTIONAL: what to set it to
alpn          = "h2"                     # OPTIONAL: force client-facing ALPN
                                         # ("h2" default-negotiated; set
                                         #  "http/1.1" to downgrade)
```

**`inject` stanza fields (complete):**

| Field | Required | Meaning |
|---|---|---|
| `host` | yes | Host to MITM (exact or leftmost-wildcard). |
| `header_name` | yes | Header cove sets (`Authorization`, `x-api-key`, `x-goog-api-key`, …). |
| `header_template` | yes | Header value; `{secret}` substituted with the real secret. e.g. `Bearer {secret}`. |
| `secret` | yes | Secret reference (§5.5). |
| `dummy_env` | no | Env var to set in the box so the client believes it is authed. |
| `dummy_value` | no | Placeholder value (default `cove-dummy-do-not-use`). |
| `base_url_env` | no | If set, cove sets this env var in the box (base-URL rewrite; §3.8). |
| `base_url_value` | no | The endpoint to set `base_url_env` to. If it is `http://127.0.0.1:PORT`, cove runs the plain-HTTP loopback path (kimi case) and does upstream TLS itself. |
| `strip_headers` | no | List of request headers cove DELETES before injecting (C1). Prevents a dummy the client still sends from conflicting with the injected credential. Default per stanza (e.g. `["x-api-key"]` for the anthropic Authorization stanza). |
| `alpn` | no | `h2` (default) or `http/1.1` (downgrade for a misbehaving host). |
| `mode` | no | `oauth-refresh` triggers the claude-style host-side token+refresh reader (§5.4). Default: static secret. |

**`allow`** is just a flat list of host rules — no stanza.

**Validate() must additionally:** reject a `cred_mount`/`runtime_mount`/
`env_passthrough` entry of `*`, `~`, `/`, or any glob that would match
everything (D10); reject `runtime_mount` values that are `/home`, `/root`,
`/etc`, or HOME-or-above; warn if a `cred_mount` or `runtime_mount` path does
not exist on the host.

### 5.4 Secret references and the claude OAuth-refresh case

- **`secret` reference forms:**
  - `file:<path>` — read the secret from a host file (0600 expected; cove warns
    if world-readable). Path `~` expands.
  - `env:<NAME>` — read from the proxy's own environment at startup (for CI /
    systemd `Environment=`). Value captured once at proxyd start.
  - `keyring:<service>/<account>` — read from the Secret Service (libsecret) if
    available. **Decision D8:** v0 implements `file:` and `env:` only; `keyring:`
    is parsed and reserved but returns "not implemented" — keep the seam.
  - `json:<path>#<dotted.path>` — read a field from a JSON file (needed for
    claude OAuth, where the token lives at
    `~/.claude/.credentials.json#claudeAiOauth.accessToken`).
- **mtime cache:** the proxy reads the secret file's mtime; if unchanged since
  last read, it uses the cached value; otherwise re-reads. Avoids a disk read per
  request while picking up rotations.
- **claude OAuth (`mode = "oauth-refresh"`):** the host holds the real
  `~/.claude/.credentials.json`. The proxy reads `claudeAiOauth.accessToken` per
  request (mtime-cached). It injects `Authorization: Bearer <accessToken>` to
  `api.anthropic.com`. The precode spike proved that if the token is expired,
  claude on the *host* handles refresh normally on next host login; **cove does
  NOT implement OAuth refresh in v0.** The box has
  `ANTHROPIC_BASE_URL=https://api.anthropic.com` and trusts the cove CA; the box
  never sees the token. (This is the one Class-B credential promoted to `inject`
  because the token is a simple bearer once read, and refresh is delegated to the
  host.)
- **The expired-token hint mechanism (M9 — corrected):** the launcher is NOT in
  the response path, so it cannot print this message. On an upstream `401` for a
  `mode = "oauth-refresh"` stanza, the **proxy** (which sees the response):
  (a) passes the `401` through to the agent unchanged (the agent handles it as
  its own auth error), and (b) writes a distinct line to **`cove proxyd`'s own
  stderr and a `warn`-level audit record**: `cove: Anthropic OAuth token rejected
  (401) — run 'claude' once on the host to re-login`. Under a systemd user unit
  this lands in the journal; when auto-spawned, proxyd's stderr is redirected to
  `~/.local/state/cove/proxyd.log`. `cove log --deny-only`/a future `--warn`
  filter surfaces it. The proxy rate-limits this warning (once per token value)
  to avoid log spam.

### 5.5 The complete pre-seeded default config

The authoritative shipped seed is
[`internal/config/default_config.toml`](../internal/config/default_config.toml).
It keeps GitHub OAuth `allow` defaults enabled and contains two commented PAT
stanzas (API Bearer and scoped Git Basic); the documented migration removes both
conflicting allow entries before enabling them. It contains no enabled
GitHub-Basic, SigV4, or mTLS destination. The following historical v0 seed
illustration is retained only for background and is not normative.

```toml
[options]
audit = true
cred_mount = []          # add Class-B/C session dirs here to enable those tools (§5.7)
runtime_mount = []       # usually empty; auto-resolves nvm/volta/asdf toolchains (§5.7)
env_passthrough = []     # e.g. AWS_* for aws/s5cmd SigV4 (§5.7)

# ── ALLOW: opaque-tunnel hosts (credential lives in the box, exfil-contained) ──
# NOTE: no host here also appears in an [[inject]] stanza below (B1 de-conflict).
allow = [
  # codex (ChatGPT OAuth, class B) — needs cred_mount ["~/.codex:rw"] to initialize/authenticate
  "chatgpt.com", "auth.openai.com",
  # gemini Google OAuth (class B) — needs cred_mount ["~/.gemini"]; API-key mode is inject below
  "accounts.google.com", "oauth2.googleapis.com", "cloudcode-pa.googleapis.com",
  # gh OAuth (class B) — needs cred_mount ["~/.config/gh"]
  "github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com",
  # wrangler OAuth (class B) — needs cred_mount ["~/.wrangler"] (or use token inject below)
  "dash.cloudflare.com",
  # aws / s5cmd (SigV4, class C) — env_passthrough AWS_* or cred_mount ["~/.aws"], STS creds
  "sts.amazonaws.com", "s3.amazonaws.com", "*.s3.amazonaws.com",
  # package registries (no credential, needed for installs)
  "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
  "proxy.golang.org", "sum.golang.org",
  "index.crates.io", "static.crates.io",
  "objects.githubusercontent.com",
  # huggingface LFS/model-file CDN (N9): huggingface.co (metadata) is inject below,
  # but LFS/model downloads 302-redirect to these CDN hosts — allow (tunnel) them,
  # else `hf download` / model pulls fail. Verify current CDN domains at ship time.
  "cdn-lfs.huggingface.co", "cdn-lfs-us-1.huggingface.co", "cdn-lfs-eu-1.huggingface.co",
  "*.hf.co",
]

# ── INJECT: key kept OUT of the box ──

# claude — OAuth (Claude Max), host holds token + delegates refresh (class B→inject)
[[inject]]
host          = "api.anthropic.com"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "json:~/.claude/.credentials.json#claudeAiOauth.accessToken"
mode          = "oauth-refresh"
dummy_env     = "ANTHROPIC_API_KEY"
strip_headers = ["x-api-key"]            # C1: box sends dummy x-api-key; strip it
base_url_env  = "ANTHROPIC_BASE_URL"
base_url_value = "https://api.anthropic.com"
alpn          = "h2"

# codex / any OpenAI API-key mode (class A) — used only if user runs API-key mode
[[inject]]
host          = "api.openai.com"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/openai-api-key"
dummy_env     = "OPENAI_API_KEY"
strip_headers = ["x-api-key"]
base_url_env  = "OPENAI_BASE_URL"
base_url_value = "https://api.openai.com/v1"

# kimi — API-key mode; client ignores HTTPS_PROXY → base-URL plain-HTTP loopback (class A)
[[inject]]
host          = "api.moonshot.cn"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/kimi-api-key"
dummy_env     = "KIMI_API_KEY"
base_url_env  = "KIMI_BASE_URL"
base_url_value = "http://127.0.0.1:0"    # :0 = cove picks a free port (§3.7b); no hardcode

# gemini — API-key mode (class A)
[[inject]]
host          = "generativelanguage.googleapis.com"
header_name   = "x-goog-api-key"
header_template = "{secret}"
secret        = "file:~/.config/cove/secrets/gemini-api-key"
dummy_env     = "GEMINI_API_KEY"
base_url_env  = "GOOGLE_GEMINI_BASE_URL"
base_url_value = "https://generativelanguage.googleapis.com"

# huggingface metadata (class A) — anonymous access works via inert-inject if no token.
# LFS/model FILE downloads redirect to cdn-lfs*.huggingface.co / *.hf.co, which are in
# the allow list above (opaque tunnel) so large pulls work (N9).
[[inject]]
host          = "huggingface.co"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/hf-token"
dummy_env     = "HF_TOKEN"

# hetzner hcloud (class A)
[[inject]]
host          = "api.hetzner.cloud"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/hcloud-token"
dummy_env     = "HCLOUD_TOKEN"

# cloudflare wrangler — API-token mode (class A). dash.cloudflare.com stays in allow (OAuth UI).
[[inject]]
host          = "api.cloudflare.com"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/cloudflare-token"
dummy_env     = "CLOUDFLARE_API_TOKEN"

# runpod (class A)
[[inject]]
host          = "api.runpod.io"
header_name   = "Authorization"
header_template = "Bearer {secret}"
secret        = "file:~/.config/cove/secrets/runpod-key"
dummy_env     = "RUNPOD_API_KEY"

# Historical v0 example only; the shipped seed documents the current paired
# GitHub API Bearer + Git Basic migration.
# [[inject]]
# host          = "api.github.com"
# header_name   = "Authorization"
# header_template = "Bearer {secret}"
# secret        = "file:~/.config/cove/secrets/github-pat"
# dummy_env     = "GH_TOKEN"
```

Notes baked into the seed:
- Every host is `allow` XOR `inject` — the seed passes `Validate()` (B1). The
  three previously-conflicting hosts (`generativelanguage.googleapis.com`,
  `huggingface.co`, `api.cloudflare.com`) are `inject`-only now; their OAuth-mode
  siblings (`cloudcode-pa`, `dash.cloudflare.com`, etc.) stay in `allow`.
- Nobody on this list pins certs (verified). Everything except kimi honors
  `HTTPS_PROXY`; kimi is rescued by `KIMI_BASE_URL` plain-HTTP loopback.
- **codex/gemini-OAuth/gh/aws are `allow` but need a `cred_mount`/`env_passthrough`
  to authenticate** (§5.7); the seed leaves those empty so nothing enters the box
  until the user opts in. To make current Codex CLI versions work, the user sets
  `cred_mount = ["~/.codex:rw"]` once. This is an explicit writable credential
  mount, so the §5.7 concurrency caveat applies: concurrent cove Codex sessions
  and host-side Codex can race while writing the same auth file.

### 5.6 Adding a new CLI with zero code (legacy general guidance)

The procedure, no recompile:

1. **Determine the class** (A/B/C) — bearer key? OAuth session? request-signed?
2. **Class A** (injectable): add one `[[inject]]` stanza (host, header_name,
   header_template, secret ref, dummy_env, and a `base_url_env` if the tool
   needs one), drop the secret into `~/.config/cove/secrets/…` (0600).
3. **Class B/C** (contain-only): add the tool's host(s) to the `allow` list AND
   provision its session into the box via `cred_mount` (session files) or
   `env_passthrough` (env-delivered creds) — see §5.7.
4. `SIGHUP` the proxy (or it auto-reloads on next session). New signing or mTLS
   shapes require an explicit implementation and test harness; do not treat this
   legacy recipe as permission to configure generic signing.

No Go code changes for any of the researched CLIs or new ones matching these
shapes. Only genuinely novel auth (mTLS, non-HTTP, new signing) needs code — and
that is explicitly out of scope (§1.5).

### 5.7 Class-B/C credential provisioning (for allow fallback)

OAuth sessions and any unsupported SigV4/mTLS mode use these explicit, opt-in
mechanisms. Both are **off by default** (empty lists) so the deny-by-default box
stays secret-free until the user consciously opts in. This section describes the
`allow` fallback, not the specialized `[[sigv4]]`/`[[mtls]]` modes in §5.3.

- **`cred_mount` (session FILES):** a list in `[options]` of host paths
  bind-mounted into the box at the **same relative path under the box HOME
  (`/root`)**. Examples:
  - `~/.codex:rw` → `/root/.codex` (codex ChatGPT OAuth: current Codex CLI
    writes under this dir during init)
  - `~/.config/gh` → `/root/.config/gh` (gh OAuth `hosts.yml`)
  - `~/.gemini` → `/root/.gemini` (gemini Google OAuth)
  - `~/.aws` → `/root/.aws` (aws/s5cmd SigV4 profiles)
  - **DEFAULT IS READ-ONLY (N5).** A plain entry (`"~/.codex"`) mounts
    **read-only**. Current Codex CLI versions fail during init on a read-only
    `~/.codex` mount because they create local path aliases/app-server state
    there. To permit those writes, the user must explicitly append `:rw`
    (`"~/.codex:rw"`). Mount mechanics: §3.3 step 9a.
  - **Concurrency safety (N5):** every `cove -- codex` session `:rw`-binding the
    SAME host `~/.codex/auth.json` (one inode), plus any host-side `codex`, can
    race on concurrent OAuth refresh-writes and **corrupt the shared token**.
    Therefore `:rw` of one credential file across concurrent sessions is UNSAFE
    and must be avoided; the safe default `:ro` prevents this by construction.
  - **Honest cost of `:ro`:** a read-only mount can BLOCK a tool's in-place token
    refresh (the tool tries to write a refreshed token, fails on the ro mount).
    The tool then surfaces an auth error; the fix is a **host-side re-login**
    (run the tool once on the host to refresh, which all sessions then read). For
    long-lived sessions that outlast the token, either re-login on the host
    periodically or accept the (unsafe-under-concurrency) `:rw`.
  - **Deferred real fix (sketch, not v0):** per-session copy-in/copy-out — cove
    copies the credential dir into the box's ephemeral tmpfs at launch (so each
    session has a private, writable copy that can refresh independently) and, on
    clean exit of the *sole* session holding it, optionally copies a refreshed
    token back under a host-side lock. This removes both the corruption race and
    the `:ro` refresh block. Out of scope for v0 (adds copy + lock + merge
    machinery); the `:ro` default is the safe v0 stance.
- **`env_passthrough` (session ENV VARS):** a glob-matched list of host env var
  names copied into the agent env (§3.8). For SigV4 with STS this is the natural
  shape: `["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN","AWS_REGION"]`.
  Glob semantics and the ban on over-broad patterns are in D10.
- **`runtime_mount` (toolchain FILES, not credentials):** a separate escape hatch
  for agent runtimes auto-resolution misses. Entries are concrete host
  directories mounted read-only at the **same absolute path** inside the box
  (§3.3 step 9b), and their `bin/` directory is prepended to PATH (§3.8). Values
  MUST NOT be `*`, bare `~`, `/`, `/home`, `/root`, `/etc`, the user's HOME, or
  an ancestor of HOME. This key is for narrow toolchain roots such as
  `~/.nvm/versions/node/v22.0.0`; it MUST NOT be used to mount HOME. The
  max-isolation alternative is to system-install the agent under `/usr/local/bin`
  (already visible via the read-only `/usr` bind), which needs no runtime mount.

**Honesty requirement:** for every active `cred_mount`/`env_passthrough` entry,
cove prints a one-line warning at launch: `cove: credential '~/.codex' is mounted
INTO the box read-only (exfil-contained, not theft-proof)` (or `read-write —
UNSAFE under concurrent sessions` for `:rw`). This makes the class-B/C tradeoff
explicit and never silent. These credentials are subject to the oracle/misuse and
in-box-theft residuals (§8.2), unlike Class-A injected keys.
For every active `runtime_mount`, cove prints a separate one-line note naming the
toolchain directory and read-only same-path mode.

**Friction reconciliation (§1.6):** the kill metric is bare-`claude`/`codex`
count. claude works at zero config (Class-A inject, seed default). codex works
after a **one-time** `cred_mount = ["~/.codex:rw"]` edit. This keeps the
ChatGPT session in the box and egress-bounded while allowing current Codex CLI
init writes. The cost is the N5 concurrency caveat: every cove Codex session
`:rw`-binding the same host `~/.codex/auth.json`, plus any host-side Codex, can
race on refresh writes. Users should avoid concurrent writable Codex sessions
until the deferred per-session copy-in/copy-out design exists. Running codex
with NO containment mechanism would have been the DOA failure B4 flagged.

---

## 6. COMMAND SURFACE

Tiny by design. cove is not a session manager.

### 6.1 `cove <agent> [args…]`

Run an agent in a fresh box. The friction guarantee: `cove claude` MUST be as
close to `claude` as possible (same TTY behavior, same argv passthrough, same
exit code). `cove [flags] -- <agent> [args…]` remains the permanent escape hatch
when an agent name collides with a public cove command.

- **Flags (before `--`):**
  - `--project DIR` / `-C DIR` — project to mount at `/work`. Default: the
    current working directory.
  - `--no-audit` — disable audit for this run (overrides config `audit=true`).
  - `--verbose` / `-v` — launcher diagnostics to stderr (namespace setup steps).
  - `--dry-run` — print the mount plan + env + policy decisions and exit without
    execing (debugging).
  - `--` — everything after is the agent argv, passed verbatim.
- **Behavior:**
  1. Load config; if malformed, exit `78` (EX_CONFIG) with the parse error.
  2. Ensure the proxy is up (auto-spawn, §4.10); if it cannot start, exit `69`
     (EX_UNAVAILABLE).
  3. Resolve `--project` to an absolute path; error `66` (EX_NOINPUT) if it does
     not exist or is not a directory.
  4. Build the box (§3), exec the agent.
  5. Wait; propagate the agent's exit status.
- **Exit codes:** `0` success; **the agent's own code on normal agent exit
  (including 70 — do NOT reuse 70 for setup failure)**; `128+signal` if the agent
  was signalled; `64` (EX_USAGE) bad flags; `66` bad project; `69` proxy
  unavailable; `77` (EX_NOPERM) AppArmor/userns denied (run `cove setup`); `78`
  bad config.
- **Box-setup vs agent-exit disambiguation (minor fix):** the launcher must NOT
  infer setup failure from a numeric exit code (an agent may legitimately exit
  70). Instead it reads the **status pipe** (§3.1): `cove __init` writes `OK`
  right before `execve`, or an explicit `ERR <stage> <errno>` if any mount /
  `pivot_root` / cap-drop step fails. If the launcher sees `ERR…` (or the child
  dies with nothing written), it reports a box-setup failure and exits **75**
  (EX_TEMPFAIL, reserved here for internal setup failure — distinct from any
  agent code). If it sees `OK`, the child's later exit status IS the agent's and
  is propagated verbatim.

### 6.2 `cove setup`

One-time, needs `sudo` for the AppArmor step. Idempotent. Behavior in §7.

### 6.3 `cove proxyd`

Start the proxy in the foreground (used by the systemd unit and by auto-spawn
via a detached re-exec). Not typically run by hand. Honors `SIGHUP` (reload),
`SIGTERM` (graceful drain then exit).

### 6.4 `cove log` — DECISION D9: SHIP IT

`cove log [--follow] [--session ID] [--host HOST] [--deny-only]` tails/filters
the audit log (`~/.local/state/cove/audit.log`). It is a thin JSONL reader with
optional filters and `--follow` (tail -f). Rationale for shipping the verb (vs
"just cat the file"): the audit log is *the* mitigation for the misuse residual
(§8), so making it one keystroke away materially improves the only defense cove
has against the oracle problem. ~40 lines. This is the sole exception to the
"no extra verbs" minimalism, justified by the security argument.

On a terminal it renders a compact protected/allowed/blocked view; `--json` or
non-terminal output preserves original JSONL bytes for scripts. `--follow`,
`--session`, `--host`, and block-only filters do not alter those raw bytes.

### 6.5 Policy and diagnostic commands

`cove add`, `cove allow`, `cove remove`, and `cove list` manage named
connections. `cove config check` validates hand-authored TOML and
`cove config edit` is its escape hatch. `cove sessions` lists recent sessions;
`cove explain last` maps the latest stored block to a safe fix. Mutations preview
their effect and require confirmation (or `--yes` outside a TTY). They edit only
the versioned COVE MANAGED block and never rewrite an existing configuration at
setup time.

`[[expose]]` explicitly describes a host path that must enter the box, including
its mode and reason. It is for non-injectable credentials and retains the
documented in-box theft and authorized-misuse residual. `[[mtls]]` uses paired
`rules = [{ method = "GET", path_prefix = "/v1/reports/" }]`; separate method
and path arrays are rejected so no Cartesian over-grant is possible. Audit is
enabled by default; `--no-audit` (or config audit disable) produces no audit
records for that session.

### 6.6 Exit status

Command failures use sysexits: 64 usage, 66 input, 69 unavailable, 73 create,
74 I/O, 75 temporary, 77 permission, and 78 configuration. A started agent is
different: its exit code, or `128+signal`, is propagated verbatim.

### 6.7 Explicitly absent verbs

No `ls`, `attach`, `ps`, `stop`, `exec`, session names, or TUI. No
`build`/`upgrade`/`test`/image management (the old bash `cove` verbs are
retired — there is no image). cove is not a session manager.

---

## 7. SETUP & PLATFORM

### 7.1 Target and portability boundary

- **Primary target:** Ubuntu 24.04 LTS on ARM64 (also amd64), a KVM guest with
  no `/dev/kvm`, running kernel with
  `kernel.apparmor_restrict_unprivileged_userns=1` (the 24.04 default).
- **Portability boundary:**
  - On distros **without** `apparmor_restrict_unprivileged_userns=1` (older
    Ubuntu, most non-AppArmor distros) unprivileged user namespaces already work
    and `cove setup` skips the AppArmor step (detects and reports "userns already
    permitted"). cove still generates the CA and default config.
  - On distros with a **different LSM** (SELinux/Fedora): cove does not ship an
    SELinux policy in v0; if userns is permitted it works; if a sysctl
    (`kernel.unprivileged_userns_clone=0` on old Debian) blocks it, `cove setup`
    reports the exact sysctl to flip and does not silently modify it.
  - **If setup was never run** and userns is denied: the launcher fails at
    `unshare(CLONE_NEWUSER)` with EPERM → exit `77` and the message "run
    `cove setup` (needs sudo, once)".

### 7.2 The AppArmor profile (exact content and why)

Ubuntu 24.04 confines *unprivileged* user-namespace creation: an arbitrary
binary may enter `CLONE_NEWUSER` but AppArmor transitions it into the
`unprivileged_userns` profile, stripping the capabilities needed to write
`uid_map`/`gid_map` and do mount setup (foundational spike: `open
/proc/self/setgroups: Permission denied` before the profile; works after). The
fix is the same one-time root-installed profile Podman and bwrap use: grant the
`userns` permission to the cove binary by path.

`cove setup` writes `/etc/apparmor.d/cove` (root):

```
abi <abi/4.0>,
include <tunables/global>

profile cove /usr/local/bin/cove flags=(unconfined) {
  userns,
  include if exists <local/cove>
}
```

- `flags=(unconfined)` + explicit `userns` matches the Podman/bwrap approach:
  cove is not otherwise confined (it is trusted host code), but it is granted
  the `userns` capability so it can create user namespaces and write single-uid
  maps.
- The profile is keyed to the **absolute install path** `/usr/local/bin/cove`.
  If cove is installed elsewhere, `cove setup` substitutes the real path (from
  `/proc/self/exe`).
- After writing, `cove setup` runs `apparmor_parser -r /etc/apparmor.d/cove` to
  load it. Idempotent: re-running rewrites and reloads the same profile.
- **Why not a suid helper:** single-uid mapping needs no `newuidmap`; the
  AppArmor grant is sufficient and avoids shipping a setuid binary (smaller
  attack surface). Range maps (unused by cove) would need the setuid helpers.

### 7.3 `cove setup` steps (idempotent, split-privilege — B5)

**The critical rule (B5): the root-only step is JUST the AppArmor write+load.
Everything else — CA, config, state dirs — is created as the INVOKING user, in
the invoking user's HOME, so that `cove proxyd` (which runs as the user) finds
them.** If setup writes the CA into root's `/root/.config/cove` while proxyd
reads `~user/.config/cove`, the install silently does not work.

Concretely `cove setup` runs in two phases:

1. **Determine the invoking user.** If `cove setup` is running under `sudo`,
   `SUDO_UID`/`SUDO_GID`/`SUDO_USER` identify the real user; otherwise the
   current uid is the user. Resolve that user's `HOME` (from `getpwuid`, not the
   possibly-root `$HOME`).
2. **User-owned artifacts (create as the invoking user; if running as root via
   sudo, `chown` them to `SUDO_UID:SUDO_GID` and set modes explicitly):**
   - `~user/.config/cove/` (0700), `~user/.config/cove/secrets/` (0700),
     `~user/.local/state/cove/` (0700), `~user/.local/state/cove/sessions/`
     (0700).
   - CA (§4.7): `~user/.config/cove/ca.pem` (0644 root-readable-ok, it is
     public) and `ca-key.pem` (0600, owned by the user).
   - `~user/.config/cove/config.toml` from the seed (§5.5) if absent — never
     overwrite an existing config.
   - Every file/dir here MUST end up owned `SUDO_UID:SUDO_GID` with the modes
     above. **Recommended implementation:** do phase 2 BEFORE escalating — i.e.
     `cove setup` first does all user-HOME work as the unescalated user, THEN, if
     the AppArmor grant is needed, re-invokes only the AppArmor step under sudo as
     the internal role **`sudo cove __apparmor`** (wired in §11.2 dispatch; it
     writes the profile and reloads it, nothing else). This avoids any root-owned
     files in the user's HOME entirely.
3. **Detect whether the AppArmor grant is needed:** probe `unshare(CLONE_NEWUSER)`
   in a child; if it fails with EPERM under AppArmor, the grant is needed.
4. **Root-only step (`cove __apparmor`, needs sudo):** if needed, this internal
   role writes `/etc/apparmor.d/cove` (§7.2, path substituted from
   `/proc/self/exe`) and runs `apparmor_parser -r /etc/apparmor.d/cove`. This is
   the ONLY step requiring root. If not needed, report "userns already permitted"
   and skip.
5. **Verify** (before printing success): re-probe `unshare(CLONE_NEWUSER)` as the
   user succeeds; the user owns `ca-key.pem` (0600) and can read it; the config
   exists. If any check fails, print the specific failure and exit non-zero.
6. Print a "cove is ready" summary: userns status, CA SHA-256 fingerprint, config
   path, and which `inject` secrets / `cred_mount` entries are still unpopulated.
7. Idempotent: every step checks-then-acts; re-running reports "no changes".

### 7.4 The single-uid mapping (recap)

`0 <hostuid> 1` for uid and gid, `setgroups=deny`. No `/etc/subuid`,
`/etc/subgid`, or setuid helper. Files in `/work` are owned by the invoking
host user. (Proven by the foundational spike.)

### 7.5 CA bootstrap and in-box trust distribution

- CA generated in `cove setup` (or lazily by `cove proxyd`).
- Per box, `cove-init` writes into the box's synthesized `/etc/ssl/certs/`:
  - `cove-ca.pem` — the CA public cert (copied from `~/.config/cove/ca.pem`,
    read by the launcher host-side and passed to `cove-init`).
  - `cove-ca-bundle.pem` — the host's system CA bundle (read from
    `/etc/ssl/certs/ca-certificates.crt` on the host at launch) **concatenated**
    with the cove CA, so tools using a single bundle path trust both real roots
    and the cove CA.
- Env vars in §3.8 point tools at these files. The CA **private** key is read
  only by `cove proxyd` and never leaves the host / never enters a box.

---

## 8. SECURITY ANALYSIS (brutally honest)

### 8.1 What cove guarantees

1. **No host secret at rest is readable from the box — UNLESS explicitly
   `cred_mount`ed (§5.7).** Deny-by-default mount construction: `~/.ssh`,
   `~/.aws`, `~/.claude`, all dotfiles, other projects, and browser data are
   *absent*, not denied. There is no denylist to bypass. (Proven: foundational
   spike.) The sole exception is the opt-in `cred_mount`/`env_passthrough`
   allowlist, which the user consciously enables per credential and which cove
   warns about at launch; those specific credentials are in the box and are
   covered by the Class-B/C residuals (§8.2), not this guarantee.
2. **No egress except to allowlisted hosts.** Loopback-only netns → raw sockets
   `ENETUNREACH` (proven). The one door is the proxy, which denies any host not
   in the config *before resolving DNS* — closing DNS-exfil channels by design.
   Proxy-ignoring tools fail closed.
3. **Class-A keys never enter the box.** The proxy injects them host-side; the
   box holds only a dummy. A compromised agent cannot read or exfiltrate the
   real Anthropic/Hetzner/GitHub-PAT/etc. key.
4. **Auditability of policy-relevant egress when audit is enabled.** Every
   CONNECT (allowed, injected, denied) in an audited session is logged;
   injected requests log method+path+status. An explicitly audit-disabled
   session writes no records.

### 8.2 What cove explicitly does NOT guarantee

1. **No protection against misuse at an allowed host (the oracle residual).**
   If `api.anthropic.com` is injected, a compromised agent can still make
   authorized Anthropic calls. The proxy is a usable oracle for exactly the
   allowed operations. Mitigation: audit log only. v0 ships no per-path policy,
   no rate limits, no approval gates.
2. **No protection for Class-B/C credentials in the box.** In the
   unsupported-mode `allow` fallback, codex ChatGPT OAuth, gemini Google OAuth,
   gh OAuth, and general AWS SigV4 keys live in the box. They are
   exfil-contained (cannot leave to a non-allowed host) but can be *misused* at
   their allowed host, and a box-escape would read them. The supported
   policy-defined S3 subset instead uses the host-side SigV4 signer described
   in [the supported/rejected matrix](#35-supportedrejected-matrix); its
   residual is a credentialed S3-operation oracle within that policy.
3. **No defense against kernel escape.** Namespaces, not a hypervisor, not
   gVisor. A kernel exploit defeats every boundary. This was a deliberate cost
   trade (gVisor's 1.64x CPU / ~6x RSS rejected; kernel escape is not this
   owner's threat).
4. **No defense against in-policy destruction.** An allowed, in-scope cloud
   token can still delete a production database (the PocketOS/Replit failure
   mode). cove's answer is *user-supplied scoped/short-lived tokens* + the audit
   log, not blocking.
5. **No host hardening.** The `/work` tree is fully writable by the agent (it
   must be). Damage there is in scope for the agent and not defended.

### 8.3 Residual risks named explicitly

- **Misuse-oracle:** injected + allowed hosts are usable by a compromised agent
  within the credential's authority. *Mitigation: audit log; user keeps tokens
  scoped/short-lived.*
- **Signed-class keys in box:** in the unsupported-mode `allow` fallback,
  general SigV4/OAuth material lives in the box; box escape or misuse exposes
  it. The supported host-side S3 SigV4 signer keeps its keys out of the box but
  remains an authorized, policy-bounded operation oracle. *Mitigation:
  STS/short-lived creds; egress containment limits exfil.*
- **Kernel escape:** unpatched namespace/kernel bug. *Mitigation: keep the host
  patched; accept the residual (documented, deliberate).*
- **h2 MITM correctness bug:** a subtle streaming/framing bug could corrupt or
  stall injected traffic. *Mitigation: use stdlib ReverseProxy (no hand-rolled
  framing), test both supported ALPN paths, and fail closed; never fall back to
  an opaque allow.*
- **Compromised proxy / CA key theft:** the CA private key on the host is a
  high-value target; if stolen, an attacker can MITM the user's own inject hosts
  from that host. *Mitigation: 0600 key, host-only, never in a box; it is no
  more exposed than any other host secret cove itself must trust.*

### 8.4 The audit log as the mitigation

When enabled, the audit log is cove's detection control against the
misuse/oracle residual. It is append-only and records method+path+status for
injected hosts. `cove log` makes it one command away. This is an honest
"detect, not prevent" posture for misuse — the prevention story is
scoped/short-lived credentials, which is the user's responsibility. A user who
explicitly disables audit also disables this detection control for that session.

**Integrity of the audit fields (M6):** `session` and `agent` are fixed
**host-side** at registration on a per-session socket (§4.1); the in-box
adversary cannot forge them — every connection on a session's socket is that
session by construction, even if the adversary bypasses the shim and connects to
`/proxy/proxy.sock` directly. The `host`/`method`/`path`/`status` fields for
`inject` hosts are observed by the proxy itself (it terminates TLS), so they are
accurate. The residual is granularity, not forgery: cove attributes traffic to a
*session*, not to "the agent vs. a subprocess the agent spawned" — within one
box all traffic is one trust domain, which is the correct model. For `allow`
hosts the proxy cannot see method/path (opaque tunnel), so those are logged as
`-`; this is a known limitation, not a forgeable field.

---

## 9. BUILD PLAN

Ordered, each milestone independently verifiable. The first milestone that beats
bare YOLO is **M3** (box with no secrets + no egress). The riskiest step
(h2 MITM inject) is pulled forward to **M4** and gates the `inject` feature.

Complexity budget (**~1800–2200 lines Go** + 1 AppArmor file, one binary —
revised up from an earlier ~1200–1500 estimate to reflect the subsystems added in
review: per-session sockets + REGISTER, PING/PONG, control/status/dir pipes,
`cred_mount`, the base-URL loopback adapter, cap-drop, counting readers,
`blockingOneShotListener` (h1 inject), `cove log`):
- namespace setup + mount plan + cap-drop + pivot_root (proven core) — M2/M3 ~400
- in-box init (reap/signal/pty+winsize/shim/base-URL loopback/fd hygiene) — M2/M5/M6 ~350
- host proxy daemon (unix accept, per-session sockets+REGISTER, PING/PONG,
  CONNECT parse, allowlist, tunnel, h2+h1 inject, strip, counting/audit) — M3/M4/M6/M7 ~700–900
- CA gen + leaf minting + config loader/validate + secret backends — M1/M4/M6 ~250
- setup (split-privilege, AppArmor writer, `cove __apparmor` re-exec) — M1 ~120
- `cove log` — M8 ~60
- launcher glue (flags, proxy spawn/health, cleanup sweep, exit-code mapping) — M0/M7 ~150

### M0 — Skeleton and dispatch
- Single binary, argv dispatch into launcher/proxyd/init roles (Decision D1).
- `cove --version`, flag parsing, config-path resolution.
- **Verify:** `cove --help`/`--version` work; dispatch routes correctly.

### M1 — `cove setup`, AppArmor, CA
- Write/parse AppArmor profile; `apparmor_parser -r`; userns probe; CA gen;
  seed config.
- **Verify:** on a fresh 24.04 box, `sudo cove setup` makes a probe `unshare
  (CLONE_NEWUSER)` succeed where it failed before; `ca.pem`/`ca-key.pem` exist
  with correct modes; re-running reports no changes (idempotent).

### M2 — The box, no proxy (namespaces + mounts + init + pty)
- Launcher forks with the clone flags; `cove-init` builds the mount plan (§3.3),
  brings up `lo`, allocates pty, execs a shell.
- **Verify (beats nothing yet, but proves containment):**
  - `cove -- /bin/sh -c 'cat ~/.ssh/id_rsa'` → no such file (secret absent).
  - `cove -- /bin/sh -c 'ls /work'` shows the project.
  - `cove -- /bin/sh -c 'curl -m3 https://1.1.1.1'` → network unreachable.
  - `cove -- /bin/bash` gives an interactive shell with working TTY resize.
  - `/proc` shows only in-box PIDs; PID 1 is `cove-init`.

### M3 — First milestone that beats bare YOLO
- Same as M2 but run a **real agent in `allow`-only mode** against a
  minimal proxy that does opaque tunnels only (no inject yet). The agent runs
  with its own in-box credential, egress-contained.
- Minimal proxy: Unix accept, CONNECT parse, allowlist match, opaque tunnel
  (§4.4), host-side resolve, audit log.
- **Verify:** `cove -- codex exec 'say ok'` completes through `chatgpt.com`+
  `auth.openai.com` allow; a CONNECT to `github.com` (not in a minimal allow)
  is denied with 403 and audit-logged; secrets still absent; raw egress still
  fails. **This is a strictly safer `codex` than bare YOLO** — no dotfile theft,
  no arbitrary exfil. Ship-gate candidate.

### M4 — h2 MITM inject (the risk, pulled forward)
- Add the `inject` path (§4.5, §4.8): per-host leaf cert minting, client-facing
  h2 TLS termination, `ReverseProxy` with header injection and `FlushInterval
  = -1`, upstream h2 via `http.Transport`.
- **Verify (the make-or-break test):** `cove -- claude` with a real Claude
  OAuth token host-side and only a dummy `ANTHROPIC_API_KEY` in the box produces
  a **real streamed 200 completion** through MITM+injection over h2. Confirm via
  audit log (`POST /v1/messages status 200`) and that the box never held the
  token. If h2 misbehaves, exercise the `alpn="http/1.1"` downgrade and confirm
  it works there. **This gates the entire inject feature.**

### M5 — Interactive polish (pty/signals/SIGWINCH)
- Full signal forwarding, SIGWINCH resize, exit-code propagation, termios
  save/restore.
- **Verify:** `cove -- claude` (TUI) resizes on window change; Ctrl-C
  interrupts the agent, not the launcher; exit codes match bare runs.

### M6 — Full proxy: base_url paths, kimi plain-loopback, all inject stanzas
- Implement `base_url_env` rewrites, the kimi plain-HTTP loopback listener, the
  full seed config, config validation (conflict detection, wildcard rules).
- **Verify:** kimi runs via `KIMI_BASE_URL` loopback with injected key; each
  seed inject stanza round-trips against a stub upstream; config with a
  host in both allow and inject fails to load.

### M7 — Lifecycle, robustness, cleanup
- Proxy auto-spawn + `flock` singleton + SIGHUP reload; crash-cleanup sweep of
  `/tmp/cove-root.*`; fail-closed behaviors; audit rotation.
- **Verify:** killing the proxy mid-session fails egress closed; launcher
  auto-spawns a fresh proxy on next run; 20 concurrent `cove -- …` sessions all
  proxy correctly (mirrors the socat concurrency spike: 20/20 200s); no leaked
  mountpoints after `kill -9` of a launcher.

### M8 — `cove log` and docs
- The audit tailer/filter verb; man-page-quality `--help`; honest positioning
  copy.
- **Verify:** `cove log --follow --deny-only` shows denials live; positioning
  text contains no "secure sandbox".

### Ship gate
Ship when M3 is solid (beats bare YOLO safely) *and* M4 proves h2 inject; M5–M8
harden and complete. The success metric (§1.6) starts counting at M5 (when
`cove -- claude` is frictionless enough to become reflex).

---

## 10. OPEN QUESTIONS / DECISIONS DEFERRED

Each item has a **recommended default** so the spec is actionable now.

- **D1 (resolved): role dispatch.** Use a subcommand + argv convention: `cove
  proxyd` and an internal `cove __init` (hidden) re-exec of `/proc/self/exe`.
  The launcher re-execs itself as `cove __init` inside the namespaces. *Default:
  as stated.*
- **D2 (resolved): unshare mechanism.** Use `exec.Cmd` + `SysProcAttr`
  Cloneflags/UidMappings so the Go runtime writes the maps and we get a clean
  PID-1 child, rather than `unshare()` on the live multi-threaded runtime.
- **D3 (resolved): `/work` vs identity mount.** Canonical `/work` (owner
  constraint). *Deferred nicety:* optional per-project persistent Claude history
  via a host state dir bind-mounted into `~/.claude/projects/<slug>` — not in
  v0; recommended default is non-persistent in-box history.
- **D4 (resolved, REVISED — B3): pivot_root only, chroot forbidden.**
  `pivot_root` + `umount2(MNT_DETACH)` of the old root is MANDATORY. `chroot` is
  NOT a fallback: the agent is uid-0 with `CAP_SYS_ADMIN` in its userns, so a
  chroot is escapable and the old root would remain mounted (host-secret
  exposure with no kernel bug). If `pivot_root` fails, box setup aborts (§13.2
  step 10). Additionally the agent execs with an empty capability bounding set +
  `PR_SET_NO_NEW_PRIVS` (§13.2 step 13).
- **D5 (resolved, REVISED — M1): pty ownership split.** The launcher owns host
  termios-raw + host `SIGWINCH`, forwarding winsize over the control pipe
  (`COVE_CTL_FD`). `cove-init` allocates the pty and runs the copy loops and does
  `TIOCSWINSZ` on the master. Only the AGENT child is a session leader with the
  controlling tty (pts slave). `cove-init` is NOT a session leader (no
  `Setsid`).
- **D6 (resolved, REVISED — M6): session identity is host-side.** Each session
  gets its own proxy-owned Unix socket (`sessions/<id>.sock`); the proxy tags all
  its connections with the `(session, agent)` registered by the launcher over the
  control socket. **The forgeable in-box `X-Cove-Session` preamble is removed.**
  Audit `session`/`agent` fields are therefore trustworthy (§8.4).
- **D7 (resolved, REVISED): one config path.** TOML via vendored
  `github.com/BurntSushi/toml`. The hand-rolled-parser alternative is DELETED —
  exactly one parsing path (§5.3).
- **D8 (open, default set): secret backends in v0.** Implement `file:`, `env:`,
  and `json:` (json needed for claude OAuth). Reserve `keyring:` (Secret
  Service) — parse but return "not implemented". *Default: ship file/env/json.*
- **D9 (resolved): `cove log` verb.** Ship it (the audit log is the sole misuse
  mitigation; one-keystroke access is worth ~40 lines).
- **D10 (resolved — B4): Class-B/C provisioning via `cred_mount` + `env_passthrough`.**
  Class-B session state is FILES (`~/.codex/auth.json`, `~/.config/gh/hosts.yml`),
  not env vars, so the primary mechanism is **`cred_mount`** — an opt-in
  bind-mount of named host paths into the box under `/root` (§3.3 step 9a, §5.7).
  **`env_passthrough`** handles env-delivered creds (AWS STS: `AWS_ACCESS_KEY_ID`
  etc.). Both are empty by default (nothing enters the box) and each active entry
  prints a "credential is in the box" warning.
  **Glob semantics for `env_passthrough`:** each entry is either an exact env
  name or a prefix glob ending in a single trailing `*` (e.g. `AWS_*` matches
  `AWS_ACCESS_KEY_ID`). No other wildcard positions. `Validate()` MUST reject a
  bare `*`, an empty string, or any pattern that would match every variable.
  `cred_mount` entries MUST be concrete paths under the user's HOME (reject `~`,
  `/`, `*`). An entry is `PATH` (read-only, default) or `PATH:rw` (read-write,
  for in-place refresh — unsafe under concurrent sessions, N5/§5.7). `Validate()`
  parses the optional `:rw` suffix; any other suffix is an error.
- **D11 (open, default set): proxy reconnect after restart.** v0 does not
  reconnect a live box to a restarted proxy (socket bind is fixed at launch).
  *Default: document as a restart-the-session limitation;* a future version
  could bind a stable well-known socket path and have the proxy re-listen on it.
- **D12 (open, default set): IPv6.** The seed resolves and dials whatever the
  host resolver returns (A or AAAA). *Default: allow both;* if a host's AAAA is
  reachable but policy is name-based, this is fine (name is the policy unit).

---

---

## 11. IMPLEMENTATION REFERENCE (build from this file alone)

**Bar:** an implementing coding agent (e.g. OpenAI Codex) MUST be able to build
cove end-to-end from this document with no other context. Sections 11–16 provide
the module layout, concrete Go types, the exact syscall sequence, the h2 inject
code shape, the test plan, and the ordered build notes. Where any detail is
undecided, a concrete default is stated so the agent is never blocked.

### 11.1 Module / file breakdown (single binary, `module cove`)

One Go module, one binary at `./cmd/cove`. Suggested package layout:

```
cove/
  go.mod                     # module cove; go 1.22+; dep: github.com/BurntSushi/toml (D7)
  cmd/cove/main.go           # argv dispatch -> role; flag parsing; exit-code mapping
  internal/config/
      config.go              # Config, InjectStanza, AllowRule types; Load(); Validate()
      seed.go                # the embedded default config.toml (go:embed)
  internal/launcher/
      launcher.go            # Run(): ensure proxy, resolve project, fork+clone, wait
      spawn.go               # exec.Cmd + SysProcAttr assembly (clone flags, uid/gid maps)
      cleanup.go             # /tmp/cove-root.* sweep; MNT_DETACH teardown
  internal/box/              # runs INSIDE the box (role: __init), PID 1
      init.go                # main init loop: mounts, netns lo, pty, shim, exec agent
      mount.go               # buildRoot(): the full mount plan (§13)
      pty.go                 # allocatePTY(), copy loops, control-pipe winsize -> TIOCSWINSZ
      reaper.go              # SIGCHLD reap loop; signal forwarding
      shim.go                # 127.0.0.1:8080 TCP <-> /proxy/proxy.sock; base_url loopbacks
      env.go                 # buildEnv(): the injected env var set (§3.8)
  internal/proxy/
      proxyd.go              # Serve(): control socket, PING/PONG, REGISTER, per-session
                             #          sockets, flock singleton, SIGHUP reload
      conn.go                # per-connection handler: read CONNECT, match, dispatch (identity from socket tag, M6)
      allowlist.go           # Matcher: exact + leftmost-wildcard; match(host,port)->Policy
      tunnel.go              # allow path: opaque bidirectional splice
      inject.go              # inject path: TLS-terminate + ReverseProxy + header inject
      ca.go                  # CA load/gen; per-host leaf minting + cache
      resolve.go             # host-side DNS (allowlist-before-resolve enforced by caller)
      audit.go               # AuditRecord; append-only JSONL writer; size rotation
  internal/secret/
      secret.go              # Resolve(ref) for file:/env:/json: ; mtime cache
  internal/setup/
      setup.go               # cove setup: apparmor write+parse, CA gen, seed config, dirs
      apparmor.go            # profile template; write /etc/apparmor.d/cove; apparmor_parser
  internal/logcmd/
      log.go                 # cove log: JSONL reader + filters + --follow
```

Public function surface (the contract each role calls):

- `config.Load(path string) (*Config, error)` and `(*Config).Validate() error`.
- `launcher.Run(cfg *Config, opts LaunchOpts) (exitCode int, err error)`.
- `box.InitMain() int` — entry when argv role is `__init`; returns exit code.
- `proxy.Serve(cfg *Config, sockPath string) error` — the daemon loop.
- `proxy.NewMatcher(cfg *Config) *Matcher`; `(*Matcher).Match(host string, port int) (Policy, *InjectStanza)`.
- `proxy.CA.LeafFor(host string) (*tls.Certificate, error)`.
- `secret.Resolve(ref string) (string, error)`.
- `setup.Run() error` (user-owned work + sudo re-exec of `cove __apparmor`);
  `setup.ApparmorOnly() error` (the root-only profile write+reload).
- `logcmd.Run(opts LogOpts) error`.

### 11.2 argv dispatch (cmd/cove/main.go)

```
switch role := detectRole(os.Args); role {
case "proxyd":     os.Exit(proxydMain())               // cove proxyd
case "__init":     os.Exit(box.InitMain())             // internal re-exec inside ns
case "__apparmor": os.Exit(exitFor(setup.ApparmorOnly())) // internal: root-only AppArmor step (§7.3)
case "setup":      os.Exit(exitFor(setup.Run()))       // cove setup (does user-owned work,
                                                       //   then sudo-re-execs `cove __apparmor`)
case "log":        os.Exit(exitFor(logcmd.Run()))      // cove log ...
default:           os.Exit(launcherMain())             // cove [flags] -- agent ...
}
```

`detectRole` checks `os.Args[1]` against the reserved verbs (`proxyd`,
`__init`, `__apparmor`, `setup`, `log`); anything else (or a leading `--`/`-C`)
is the launcher. `__init` and `__apparmor` are hidden internal roles (not shown
in `--help`). **`__apparmor` wiring (consistency fix):** §7.3 escalates by
re-invoking `sudo cove __apparmor` (NOT `sudo cove setup --apparmor-only`, which
was prose-only) — this internal role writes `/etc/apparmor.d/cove` and runs
`apparmor_parser -r`, and does nothing else, so no root-owned files land in the
user's HOME (B5). `setup.Run()` does all user-owned work first, then shells out
to `sudo cove __apparmor` only if the userns probe shows the grant is needed.

---

## 12. CONCRETE GO DATA STRUCTURES

These are the load-bearing types; field names and tags are normative.

### 12.1 Config

```go
package config

type Config struct {
    Options Options        `toml:"options"`
    Allow   []string       `toml:"allow"`   // raw host rules (exact or *.leftmost)
    Inject  []InjectStanza `toml:"inject"`

    // Derived at Load()/Validate(); not in TOML.
    AllowRules []AllowRule `toml:"-"`
}

type Options struct {
    TmpSize        string   `toml:"tmp_size"`        // default "256m" (§M8)
    ProxyPort      int      `toml:"proxy_port"`      // default 8080; MUST be >=1024 (NEW-3)
    Audit          bool     `toml:"audit"`           // default true
    CredMount      []string `toml:"cred_mount"`      // §5.7: host paths bound INTO box, RO by default ("~/.codex", "~/.aws:rw")
    RuntimeMount   []string `toml:"runtime_mount"`   // §5.7: ro toolchain dirs bound at same absolute path
    EnvPassthrough []string `toml:"env_passthrough"` // §5.7/D10: env-name globs copied INTO box
}

type InjectStanza struct {
    Host          string   `toml:"host"`            // exact or *.leftmost-wildcard
    HeaderName    string   `toml:"header_name"`     // e.g. "Authorization", "x-api-key"
    HeaderTemplate string  `toml:"header_template"` // contains "{secret}"
    Secret        string   `toml:"secret"`          // file:/env:/json: ref (§5.4)
    StripHeaders  []string `toml:"strip_headers"`   // C1: headers deleted before inject
    DummyEnv      string   `toml:"dummy_env"`        // env var set to a placeholder in box
    DummyValue    string   `toml:"dummy_value"`      // default "cove-dummy-do-not-use"
    BaseURLEnv    string   `toml:"base_url_env"`     // optional; env var to set in box
    BaseURLValue  string   `toml:"base_url_value"`   // optional; "https://host" or "http://127.0.0.1:0"
    ALPN          string   `toml:"alpn"`             // "h2" (default) | "http/1.1"
    Mode          string   `toml:"mode"`             // "" (static) | "oauth-refresh"

    Port int `toml:"-"` // parsed from host if host has :port, else 443
}

// AllowRule and InjectStanza share this compiled matcher form.
type AllowRule struct {
    Pattern  string // original
    Host     string // exact host or the label suffix for wildcard
    Wildcard bool   // true if leftmost "*." form
    Port     int    // 443 default, or explicit
}
```

`Validate()` MUST: reject a bare `*` rule; reject any host appearing in both an
active `allow` rule and an `inject` stanza; reject `mode`/`secret` values it does
not implement; reject an `inject` whose `header_template` lacks `{secret}`;
**reject `proxy_port < 1024`** with a clear error ("proxy_port must be >=1024;
the shim binds it after CAP_NET_BIND_SERVICE is dropped", NEW-3); warn (not fail)
on an `inject` whose `secret` file is missing or world-readable.

### 12.2 Proxy per-connection state

```go
package proxy

type Policy int
const (
    PolicyDeny Policy = iota
    PolicyAllow
    PolicyInject
)

type Session struct {
    ID    string // 8-hex, fixed HOST-SIDE at REGISTER (§4.1); never in-box-sourced
    Agent string // agent name from the launcher's REGISTER line (for audit)
}

// Conn (below) no longer reads a preamble; the proxy tags each conn with the
// Session bound to the per-session socket it arrived on (M6).

type Conn struct {
    raw     net.Conn        // the accepted per-session unix connection
    br      *bufio.Reader   // buffered reader over raw (CONNECT line; may hold pipelined ClientHello)
    sess    Session         // tagged from the per-session socket (M6), not a preamble
    proxy   *Proxyd         // back-ref for warnReloginRateLimited, config, resolver
    matcher *Matcher
    ca      *CA
    secrets *secret.Cache
    audit   *AuditWriter
    started time.Time
}

// Result of parsing the CONNECT line.
type Target struct {
    Host string
    Port int
}
```

### 12.3 Audit record

```go
package proxy

type AuditRecord struct {
    TS       time.Time `json:"ts"`
    Session  string    `json:"session"`
    Policy   string    `json:"policy"`            // "inject" | "allow" | "deny"
    Host     string    `json:"host"`
    Port     int       `json:"port"`
    Method   string    `json:"method,omitempty"`  // inject only; "-" for allow/deny
    Path     string    `json:"path,omitempty"`    // inject only
    Status   int       `json:"status,omitempty"`  // inject: upstream status; deny: 403
    BytesUp  int64     `json:"bytes_up"`
    BytesDn  int64     `json:"bytes_down"`
    DurMS    int64     `json:"dur_ms"`
    Agent    string    `json:"agent,omitempty"`
}
```

The `AuditWriter` holds an `*os.File` (append, 0600) behind a mutex, and exposes
`Emit(rec *AuditRecord)` which marshals one record per line + `\n` and rotates
when size exceeds 64 MiB (rename `audit.log.1`.. keep 5).

**Two-phase emit for streamed inject (N3):** for the `inject` path, the record is
BUILT at response-header time (`newInjectRecord` fills TS/session/host/method/
path/status) but NOT emitted then — `bytes_down`/`dur_ms` are still zero while the
SSE body streams (FlushInterval=-1). The response body is wrapped in a
`countingReadCloser` whose `onClose(n int64)` sets `rec.BytesDn=n`,
`rec.DurMS=…`, and calls `audit.Emit(rec)` at body EOF/close, so the persisted
record has real byte counts and duration. `bytes_up` is similarly accumulated by
a counting reader wrapping the request body.

**Emit timing for the other policies (NEW-2):**
- **`allow` (opaque tunnel):** `method`/`path` are `-` (cove cannot see inside
  TLS), but `bytes_up`/`bytes_down`/`dur_ms` are only known when the tunnel
  CLOSES. So the `allow` record is emitted **at tunnel close** with the final
  spliced byte counts and duration (§4.4) — NOT at CONNECT time (that would log
  zeros).
- **`deny`:** emitted **immediately** at the 403/405 (no bytes flow; `bytes_*`
  are 0, `method`/`path` = `-`, `status` reflects the rejection).

```go
type countingReadCloser struct {
    rc      io.ReadCloser
    n       int64
    onClose func(n int64)
    once    sync.Once
}
func (c *countingReadCloser) Read(p []byte) (int, error) {
    m, err := c.rc.Read(p); c.n += int64(m); return m, err
}
func (c *countingReadCloser) Close() error {
    c.once.Do(func() { c.onClose(c.n) }); return c.rc.Close()
}
```

---

## 13. EXACT NAMESPACE SYSCALL SEQUENCE

This is the proven `lockbox.c` mechanics translated to cove's fork model. The
launcher builds the `exec.Cmd` for the `__init` re-exec; the kernel applies the
namespaces at `clone`; `box.InitMain` finishes the mount plan.

### 13.1 Launcher side (spawn.go) — clone + maps

```go
cmd := exec.Command("/proc/self/exe", "__init")
cmd.Args[0] = "cove"
cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

// Directives (dummy envs, base_url rewrites, cred_mounts, runtime_mounts, CA bytes, agent argv)
// are passed over a PIPE fd, NOT an env var, so they never appear in
// /proc/<agent>/environ (hygiene). Two more pipes: status (child->parent setup
// result) and control (parent->child winsize updates).
dirR, dirW, _    := os.Pipe()   // parent writes serialized directives to dirW
statusR, statusW, _ := os.Pipe() // child writes "OK"/"ERR ..." to statusW
ctlR, ctlW, _    := os.Pipe()    // parent writes 8-byte winsize records to ctlW
cmd.ExtraFiles = []*os.File{dirR, statusW, ctlR} // become fds 3,4,5 in the child

cmd.Env = []string{ // MINIMAL bootstrap env; scrubbed before the agent execs (§3.8)
    "COVE_DIR_FD=3", "COVE_STATUS_FD=4", "COVE_CTL_FD=5",
    "COVE_TERM=" + os.Getenv("TERM"),
    // project/proxy-sock/session/agent are inside the serialized directives, not env.
}
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
                syscall.CLONE_NEWPID  | syscall.CLONE_NEWNET |
                syscall.CLONE_NEWIPC  | syscall.CLONE_NEWUTS,
    UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
    GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
    GidMappingsEnableSetgroups: false, // => writes "deny" to /proc/pid/setgroups
    // NO Setsid here: cove-init must NOT be a session leader with a controlling
    // tty. Only the AGENT child (forked inside cove-init) does setsid+TIOCSCTTY
    // on the pts slave (§3.5). The launcher owns host SIGWINCH and pushes sizes
    // over COVE_CTL_FD.
}
err := cmd.Start()   // Go runtime writes uid_map/gid_map for us (single-uid; no helper)
// Then: parent writes directives to dirW, closes it; blocks reading statusR to
// learn OK vs ERR (exit 75 on ERR/EOF-without-OK, §6.1); on OK, forwards winsize
// on ctlW for the session's life; waits; propagates the agent exit status.
```

Notes matching the foundational spike:
- `GidMappingsEnableSetgroups=false` reproduces the mandatory `setgroups: deny`
  write before `gid_map` for an unprivileged single-uid map.
- Single-uid map (`Size:1`) → the AppArmor `userns` grant is the only
  prerequisite; no `newuidmap`/`newgidmap` (`maprange.c` shows range maps need
  the setuid helpers, single maps do not).
- The child starts as uid 0 **inside** the new userns and is PID 1 of the new
  pidns.

### 13.2 Box side (box.InitMain -> mount.go) — the mount plan

Translated from `lockbox.c` `setup_deny()` and `setup_netns()`, with the PID-ns
`/proc` fix and devpts:

Read directives from `COVE_DIR_FD` first (project path, proxy-sock path, session
id, agent name, dummy envs, base_url rewrites, cred_mounts, runtime_mounts, CA bytes, agent
argv). On ANY failure below, write `ERR <stage> <errno>` to `COVE_STATUS_FD` and
exit — never continue with weaker isolation.

```
1.  mount("", "/", "", MS_REC|MS_PRIVATE, "")                       // private tree
2.  root := mkdtemp("/tmp/cove-root.XXXXXX")
    mount("tmpfs", root, "tmpfs", MS_NOSUID|MS_NODEV, "size=64m,mode=0755")
3.  bindRO("/usr", root+"/usr")                                     // = bind + remount ro,nosuid,nodev,rec
    symlink("usr/bin",  root+"/bin"); symlink("usr/sbin", root+"/sbin")
    symlink("usr/lib",  root+"/lib"); symlink("usr/lib",  root+"/lib64")  // arch-dep; skip if absent
4.  mkdir(root+"/etc")                                              // §3.3 step 4 — exact set:
    write passwd(home=/root),group,hosts,hostname,resolv.conf(EMPTY),
          nsswitch.conf("hosts: files"),gai.conf,machine-id(dummy)
    mkdir(root+"/etc/ssl/certs"); write cove-ca.pem + cove-ca-bundle.pem (from directives, via fd)
    for f in {ssl/openssl.cnf,services,protocols,localtime,mime.types,ld.so.cache}:
        if host has /etc/f: bindRO("/etc/"+f, root+"/etc/"+f)      // ro; skip if absent
5.  mkdir(root+"/proc"); mount("proc", root+"/proc","proc", MS_NOSUID|MS_NODEV|MS_NOEXEC,"") // PID1 of new pidns
    // /sys: cgroup-only by DEFAULT (no host-topology leak; §3.3 step 5):
    mount("tmpfs", root+"/sys","tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RDONLY,"mode=0555")
    mkdir(root+"/sys/fs/cgroup"); bindRO("/sys/fs/cgroup", root+"/sys/fs/cgroup")  // memory.max for heap sizing
6.  mkdir(root+"/root"); mount("tmpfs", root+"/root","tmpfs", MS_NOSUID|MS_NODEV,"size=256m,mode=0700")  // box HOME
    mkdir(root+"/tmp");  mount("tmpfs", root+"/tmp", "tmpfs", MS_NOSUID|MS_NODEV,"size=<tmp_size>,mode=1777")  // default 256m
    mkdir(root+"/run");  mount("tmpfs", root+"/run", "tmpfs", MS_NOSUID|MS_NODEV,"size=16m,mode=0755")
    mkdir(root+"/var"); mkdir(root+"/var/tmp"); mount("tmpfs", root+"/var/tmp","tmpfs", MS_NOSUID|MS_NODEV,"size=64m,mode=1777")
7.  mkdir(root+"/dev");  mount("tmpfs", root+"/dev", "tmpfs", MS_NOSUID|MS_NOEXEC, "size=4m,mode=0755")
    for n in {null,zero,full,random,urandom,tty}:  touch root+/dev/n ; mount(bind "/dev/"+n -> root+/dev/n)
    mkdir(root+"/dev/pts"); mount("devpts", root+"/dev/pts","devpts", MS_NOSUID|MS_NOEXEC,"newinstance,ptmxmode=0666,mode=0620")
    symlink("pts/ptmx", root+"/dev/ptmx")
    symlink("/proc/self/fd", root+"/dev/fd"); std{in,out,err} symlinks; mount tmpfs root+/dev/shm size=64m,mode=1777
8.  mkdir(root+"/work"); mount(project, root+"/work","", MS_BIND|MS_REC,"")
    mount("", root+"/work","", MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_REC,"")     // RW but nosuid,nodev
9.  mkdir(root+"/proxy"); touch root+"/proxy/proxy.sock";
    mount(proxySock, root+"/proxy/proxy.sock","", MS_BIND,"")                        // crosses netns (proven)
9a. for m in cred_mounts:  // §3.3 step 9a — the ONLY host creds entering the box
       dst := root+"/root/"+relUnderHome(m.path)   // e.g. ~/.codex -> /root/.codex
       mkdirs(dst-parent); mount(m.path, dst,"", MS_BIND|MS_REC,"")
       if !m.rw: mount("", dst,"", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC,"")  // DEFAULT ro (N5); :rw opts out
       warn("credential %s mounted INTO box %s (exfil-contained, not theft-proof)", m.path, m.rw?"read-write UNSAFE-concurrent":"read-only")
9b. for dir in runtime_mounts:  // §3.3 step 9b — ro toolchains only, never HOME
       dst := root+dir          // same absolute path inside the box
       mkdirs(dst-parent); mount(dir, dst,"", MS_BIND|MS_REC,"")
       mount("", dst,"", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_REC,"")
       note("runtime %s mounted INTO box read-only at same path", dir)
10. // MANDATORY pivot_root; chroot FORBIDDEN (B3):
    chdir(root); mkdir(root+"/.oldroot")
    pivot_root(root, root+"/.oldroot"); chdir("/")
    mount("", "/.oldroot","", MS_REC|MS_PRIVATE,""); umount2("/.oldroot", MNT_DETACH); rmdir("/.oldroot")
    // if pivot_root fails: ERR to status fd + exit. NEVER fall back to chroot.
11. chdir("/work")
12. netns lo up:  s := socket(AF_INET, SOCK_DGRAM); ioctl(s, SIOCGIFFLAGS,"lo")
                  flags |= IFF_UP|IFF_RUNNING; ioctl(s, SIOCSIFFLAGS,"lo")
12a.// cove-init (PID 1) drops its OWN caps now — all cap-needing work is done (N6):
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0,0,0)
    for cap in 0..CAP_LAST_CAP: prctl(PR_CAPBSET_DROP, cap)   // empty bounding set
    capset(empty eff/perm/inherit)                            // PID1 now has no caps
    // (init duties + shim start here — §13.3 — then fork the agent child:)
13. // In the agent child (inherits empty caps+no_new_privs; re-assert then exec):
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0,0,0)
    capset(empty eff/perm/inherit)                            // belt-and-suspenders
    write "OK" to COVE_STATUS_FD                              // signal setup success FIRST
    close(COVE_DIR_FD); close(COVE_STATUS_FD); close(COVE_CTL_FD); close(ptyMaster) // N7: never inherited by agent
    execve(agent)
    // (cove-init/PID1 keeps COVE_CTL_FD + ptyMaster for its own winsize/pty loops.)
```

`bindRO` = `mount(src,dst,"",MS_BIND|MS_REC,"")` then
`mount("",dst,"",MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_REC,"")`
(exactly `lockbox.c` `bind_ro`).

### 13.3 Box side — start init duties, then exec agent

After the mount plan and `lo` up (steps 1–12), `box.InitMain`:
1. Starts the reaper goroutine (`SIGCHLD` → `wait4(-1, WNOHANG)` loop).
2. Installs signal forwarding (`SIGTERM/INT/HUP/QUIT/TSTP/CONT` → agent pgrp).
   **NOT `SIGWINCH`** (cove-init has no controlling tty; §3.4).
3. Starts the shim goroutine: listen `127.0.0.1:<proxy_port>`, per-conn dial
   `/proxy/proxy.sock`, splice 1:1. **No preamble** — session/agent identity is
   fixed host-side by the per-session socket (§4.1, M6). Also start any base-URL
   plain-HTTP loopback listeners for stanzas with `base_url_value=http://127.0.0.1:0`
   (§3.7b), recording each chosen dynamic port for the agent env.
4. Builds the agent env (§3.8) including dummy creds, base-URL rewrites (with the
   dynamic ports), and `env_passthrough` values.
5. Forks the agent child. If a TTY: child does `setsid`+pts-slave+`TIOCSCTTY`
   (§3.5); cove-init parent runs the pty copy loops and the `COVE_CTL_FD` winsize
   reader (`TIOCSWINSZ` on the master). The agent child does the §13.2 step-13
   privilege drop, writes `OK` to `COVE_STATUS_FD`, then `execve`s the agent.
6. cove-init (PID 1) waits for the agent, propagates its exit status, and its own
   exit tears down the namespace (killing any stragglers).

---

## 14. HTTP/2 MITM INJECT — IMPLEMENTABLE DETAIL

Goal: for an `inject` host (e.g. `api.anthropic.com`, ALPN h2), terminate the
client TLS with a cove-CA leaf, inject the real host-side secret (and strip
conflicting dummy auth headers), forward to the real upstream over its own TLS,
and stream the response back token-by-token. Dependencies: `crypto/tls`,
`net/http`, `net/http/httputil`, and **`golang.org/x/net/http2`** (required — the
stdlib will NOT speak h2 on a hand-handshaked conn; B2).

```go
// inject.go — br is the *bufio.Reader used to read the CONNECT line (§4.2).
// After writing "200 Connection Established" to the raw conn:

// bufConn: a net.Conn whose Read first drains br's buffered bytes (pipelined
// ClientHello) then the raw conn (M5). MUST be used for tls.Server / splice.
type bufConn struct { r io.Reader; net.Conn }
func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func newBufConn(br *bufio.Reader, c net.Conn) net.Conn {
    return bufConn{ r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c), Conn: c }
}

func (c *Conn) serveInject(raw net.Conn, br *bufio.Reader, t Target, st *InjectStanza) error {
    leaf, err := c.ca.LeafFor(t.Host)                 // cached; SAN=t.Host; signed by cove CA (RSA-2048)
    if err != nil { return err }

    alpn := []string{"h2", "http/1.1"}
    if st.ALPN == "http/1.1" { alpn = []string{"http/1.1"} }   // per-host downgrade escape hatch

    srvTLS := &tls.Config{
        Certificates: []tls.Certificate{*leaf},
        NextProtos:   alpn,
        MinVersion:   tls.VersionTLS12,
    }

    secretVal, err := c.secrets.Resolve(st.Secret)    // mtime-cached; json:/file:/env:
    if err != nil { return err }
    inject := secretVal != ""                          // inert-inject: empty => tunnel, no header (§5.5)
    headerVal := strings.ReplaceAll(st.HeaderTemplate, "{secret}", secretVal)

    upstream := &http.Transport{
        ForceAttemptHTTP2: true,                       // negotiate h2 upstream if offered
        TLSClientConfig:   &tls.Config{ServerName: t.Host}, // HOST's real roots (default pool)
        DialContext:       c.dialResolved(t),          // dial the exact IP resolved after allowlist (§4.6)
        IdleConnTimeout:   30 * time.Second,
    }
    defer upstream.CloseIdleConnections()              // minor fix: no leaked idle conns/fds per CONNECT

    // Audit is recorded in TWO stages (N3): status/method/path are known at
    // response-header time, but bytes_down/dur_ms are only final after the SSE
    // body finishes streaming (FlushInterval=-1). So ModifyResponse opens a
    // pending record and wraps resp.Body in a counting reader that FINALIZES the
    // record (real bytes_down + dur_ms) on EOF/Close. Do NOT emit at header time.
    rp := &httputil.ReverseProxy{
        Rewrite: func(pr *httputil.ProxyRequest) {
            pr.Out.URL.Scheme = "https"
            pr.Out.URL.Host   = t.Host
            pr.Out.Host       = t.Host
            for _, h := range st.StripHeaders { pr.Out.Header.Del(h) } // C1: drop dummy x-api-key etc FIRST
            pr.Out.Header.Del("X-Forwarded-For")
            pr.Out.Header.Del("X-Forwarded-Host")
            pr.Out.Header.Del("X-Forwarded-Proto")
            if inject { pr.Out.Header.Set(st.HeaderName, headerVal) } // OVERWRITE with real secret
            // bytes_up: wrap pr.Out.Body in a counting reader here (request body).
        },
        Transport:     upstream,
        FlushInterval: -1,                             // immediate flush => SSE/streaming preserved
        ModifyResponse: func(resp *http.Response) error {
            rec := c.newInjectRecord(t, resp)          // status/method/path now; bytes/dur pending
            if resp.StatusCode == 401 && st.Mode == "oauth-refresh" {
                c.proxy.warnReloginRateLimited(secretVal) // proxyd stderr + audit (M9); NOT the launcher
            }
            // Finalize bytes_down + dur_ms when the (possibly streamed) body ends:
            resp.Body = &countingReadCloser{rc: resp.Body, onClose: func(n int64) {
                rec.BytesDn = n
                rec.DurMS   = time.Since(c.started).Milliseconds()
                c.audit.Emit(rec)                      // write the completed record
            }}
            return nil
        },
    }

    conn := newBufConn(br, raw)
    tlsConn := tls.Server(conn, srvTLS)
    if err := tlsConn.Handshake(); err != nil { return err }

    switch tlsConn.ConnectionState().NegotiatedProtocol {
    case "h2":
        // BLOCKS until the whole connection (all streams) is done — correct for streaming (B2).
        (&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: rp})
        return nil
    default: // "http/1.1" or ""
        rp.FlushInterval = -1
        // CORRECT h1 path (N2): http.Serve over a BLOCKING one-shot listener that
        // yields tlsConn once then blocks until the conn closes. This gives a real
        // http.ResponseWriter (chunked encoding, keepalive, Flusher for SSE) for
        // free — do NOT hand-roll HTTP/1.1 framing.
        return http.Serve(newBlockingOneShotListener(tlsConn), rp)
    }
}

// blockingOneShotListener: Accept() returns the single conn once, then BLOCKS on
// a channel closed by the conn's Close(), then returns io.EOF so http.Serve exits
// cleanly AFTER the connection (and any in-flight streamed response) is finished.
// This is the correct h1 pattern; the FORBIDDEN variant (B2) is the NON-blocking
// listener that returns EOF immediately and tears streams down early.
type blockingOneShotListener struct {
    ch   chan net.Conn // buffered(1), holds the conn for the first Accept
    done chan struct{} // closed by notifyConn.Close()
}
type dummyAddr struct{}
func (dummyAddr) Network() string { return "cove" }
func (dummyAddr) String() string  { return "cove-oneshot" }
type notifyConn struct {
    net.Conn
    done chan struct{}
    once sync.Once
}
func (n *notifyConn) Close() error { n.once.Do(func() { close(n.done) }); return n.Conn.Close() }
func newBlockingOneShotListener(c net.Conn) *blockingOneShotListener {
    done := make(chan struct{})
    l := &blockingOneShotListener{ch: make(chan net.Conn, 1), done: done}
    l.ch <- &notifyConn{Conn: c, done: done}
    close(l.ch) // so the SECOND Accept receives the zero value with ok==false
    return l
}
func (l *blockingOneShotListener) Accept() (net.Conn, error) {
    if c, ok := <-l.ch; ok { return c, nil } // first call: return the conn
    <-l.done                                  // later calls: block until conn closed
    return nil, io.EOF
}
func (l *blockingOneShotListener) Close() error { return nil }
func (l *blockingOneShotListener) Addr() net.Addr { return dummyAddr{} }
// `ch` is closed in the constructor, so the first Accept receives the conn and
// the second (http.Serve loops on Accept) gets ok==false and blocks on `done`
// until the conn's Close() fires — then returns io.EOF and Serve exits cleanly.
```

Key correctness points (must not be violated):
- **h2 leg — blocking `ServeConn`, NOT a listener (B2).** `http2.Server.ServeConn`
  blocks until every stream completes, so a streamed claude 200 is never torn
  down. For h2, `http.Server.Serve(oneShotListener)` is FORBIDDEN — it does not
  negotiate h2 on a pre-handshaked conn AND a non-blocking one-shot listener
  returns while streams are live.
- **h1 leg — `http.Serve` over a BLOCKING one-shot listener IS correct (N2).**
  The forbiddance above is scoped to h2. For h1 this pattern yields a real
  `http.ResponseWriter` (chunked framing, keepalive, `Flusher` for SSE) — use it;
  do NOT hand-roll HTTP/1.1 framing. The only bug to avoid is a NON-blocking
  listener; `blockingOneShotListener` above blocks until the conn closes.
- **`FlushInterval = -1`** on BOTH legs — mandatory for claude streaming.
- **Audit finalized at body EOF (N3)** — `bytes_down`/`dur_ms` are written when
  the streamed body closes, not at response headers, so counts are real.
- **`bufConn` (M5)** — TLS/splice must read `br`'s buffered bytes first, then the
  raw conn, or the pipelined ClientHello is lost.
- **Strip THEN inject (C1)** — delete `strip_headers` (e.g. dummy `x-api-key`)
  before `Set`ting the injected credential.
- **Inert-inject** — empty secret ⇒ tunnel without a header (§5.5), so anonymous
  use (e.g. HF metadata) still works.
- **Upstream uses the host's real roots** (never the cove CA).
- **`CloseIdleConnections` on return** — no fd/conn leak per CONNECT.
- **Byte counting** — counting readers on request body (`bytes_up`) and response
  body (`bytes_down`, finalized on close) → accurate audit (§12.3).

---

## 15. TEST PLAN

### 15.1 Unit tests

- **`config` — SEED-VALIDATES (B1, mandatory):** load the EXACT embedded seed
  (`go:embed`) and assert `Config.Validate()` returns `nil` — no host in both
  `allow` and an active `inject`. This test is the guard against the DOA
  regression that shipped a self-conflicting seed. Also: reject bare `*`; reject
  a synthetic config with a host in both allow+inject; reject inject without
  `{secret}`; reject `cred_mount`/`env_passthrough` = `*`/`~`/`/`; port parsing
  from `host:port`.
- `allowlist`: exact match; leftmost-wildcard match/non-match
  (`objects.githubusercontent.com` ✓, `githubusercontent.com` ✗,
  `a.b.githubusercontent.com` ✗); IP-literal denied unless listed; port rules.
- `secret`: `file:` reads + mtime cache invalidation; `json:` dotted-path
  extraction from a fixture `.credentials.json`; `env:` capture; missing file →
  warn + inert (empty value ⇒ tunnel-without-header).
- `ca`: generated RSA-2048 CA signs a leaf whose SAN matches; leaf verifies
  against the CA pool; leaf cache returns the same cert for the same host.
- `audit`: record marshals to expected JSON; rotation at size threshold; counting
  readers report accurate `bytes_up`/`bytes_down`.
- **`inject` (httptest, the C1 flow):** a local `httptest.NewTLSServer` upstream
  that echoes received auth headers + a client trusting the cove CA. Send a
  request bearing BOTH a dummy `x-api-key` and no `Authorization`. Assert
  upstream receives the injected `Authorization: Bearer <real>` AND that
  `x-api-key` is ABSENT (strip_headers worked). Assert a streamed body flushes
  incrementally (FlushInterval=-1). Run the same test over h2
  (`http2.Server.ServeConn`) and h1 to cover both legs.
- `bufConn`: a conn with a pipelined ClientHello in the bufio buffer is read
  correctly by the wrapper (M5 regression test).

### 15.2 Manual end-to-end script (`scripts/e2e.sh`)

Run on a fresh Ubuntu 24.04 box after `sudo cove setup`. This is the acceptance
gate; it proves the three core guarantees plus a working agent.

```sh
#!/usr/bin/env bash
set -euo pipefail

# 0. Setup must be idempotent and grant userns.
sudo cove setup
cove setup            # second run: reports "no changes"

# 1. BAIT SECRET IS UNREADABLE (theft-at-rest defended).
echo "TOP-SECRET-BAIT-$(date +%s)" > "$HOME/.ssh/cove_bait" || true
out=$(cove -- /bin/sh -c 'cat ~/.ssh/cove_bait 2>&1 || echo ABSENT')
[ "$out" = "ABSENT" ] || { echo "FAIL: bait readable"; exit 1; }
echo "PASS: host secret absent in box"

# 2. OFF-ALLOWLIST EGRESS IS BLOCKED (exfil defended).
out=$(cove -- /bin/sh -c 'curl -m3 -s -o /dev/null -w "%{http_code}" https://1.1.1.1 2>&1 || echo BLOCKED')
echo "$out" | grep -q BLOCKED || { echo "FAIL: raw egress succeeded"; exit 1; }
out=$(cove -- /bin/sh -c 'curl -m5 -s -o /dev/null -w "%{http_code}" https://evil.example.com 2>&1 || echo DENIED')
echo "$out" | grep -Eq '403|DENIED' || { echo "FAIL: off-allowlist not denied"; exit 1; }
echo "PASS: off-allowlist egress blocked; audit has a deny record"
cove log --deny-only | tail -1 | grep -q evil.example.com

# 3. PROJECT IS MOUNTED RW AT /work.
cove -- /bin/sh -c 'echo hi > /work/.cove_e2e && test -f /work/.cove_e2e' && rm -f ./.cove_e2e
echo "PASS: /work is the project, writable"

# 4. THE MAKE-OR-BREAK: real claude completion through the FULL dummy→strip→inject
#    flow over h2. Requires a valid host-side Claude OAuth token in
#    ~/.claude/.credentials.json. The box holds only a dummy ANTHROPIC_API_KEY
#    (and the client sends dummy x-api-key), which strip_headers must remove and
#    the injected Authorization: Bearer <oauth> must replace — else Anthropic 401s.
cove -- claude -p "reply with exactly: COVE-OK" | tee /tmp/cove_claude_out
grep -q "COVE-OK" /tmp/cove_claude_out || { echo "FAIL: claude did not complete via inject"; exit 1; }
cove log --host api.anthropic.com | tail -1 | grep -q '"status":200'
echo "PASS: claude 200 via h2 MITM strip+inject; dummy x-api-key stripped; token never in box"

# 5. CODEX works via cred_mount (B4). One-time config edit assumed:
#    cred_mount = ["~/.codex:rw"] in ~/.config/cove/config.toml.
#    Assumes the host-side ChatGPT token is currently valid. The writable mount is
#    needed by current Codex CLI init; avoid concurrent writable Codex sessions (N5).
cove -- codex exec 'reply with exactly: CODEX-OK' | tee /tmp/cove_codex_out
grep -q "CODEX-OK" /tmp/cove_codex_out || { echo "FAIL: codex did not complete"; exit 1; }
cove log --host chatgpt.com | tail -1 | grep -q '"policy":"allow"'
echo "PASS: codex works (session cred_mounted read-write, egress-contained)"

echo "ALL E2E CHECKS PASSED"
```

A passing run of steps 1–3 means cove already beats bare YOLO (M3). Step 4 proves
the `inject` feature incl. the strip+dummy flow (M4). Step 5 proves the Class-B
`cred_mount` provisioning that makes codex usable (B4).

---

## 16. IMPLEMENTATION NOTES FOR THE CODING AGENT

Build in this order; do not proceed past a step whose verification fails.

1. **M0 skeleton + argv dispatch** (§11.2). `cove --version` works.
2. **M1 `cove setup`** (§7.3, AppArmor §7.2, CA §4.7). Verify a probe
   `unshare(CLONE_NEWUSER)` succeeds after setup on Ubuntu 24.04.
3. **M2 the box** (§13). `cove -- /bin/bash` gives a TTY shell; bait absent; raw
   egress fails; `/proc` shows only in-box PIDs. (E2E steps 1–3 minus the proxy
   deny in step 2.)
4. **M3 minimal proxy, allow-only** (§4.1–4.4, §4.6, §4.9). `cove -- codex` runs
   through allow hosts; off-allowlist denied + audited. **This is the ship-gate
   candidate — it already beats bare YOLO.**
5. **M4 — PROVE THIS FIRST among the hard parts: the h2 MITM inject 200
   completion** (§14, E2E step 4). Do a real streamed `claude` completion through
   MITM+injection over h2, token host-side only, box holds a dummy. If h2
   misbehaves, prove the `alpn="http/1.1"` downgrade path. **This single test
   gates the entire inject feature; write it before polishing anything else.**
6. **M5 pty/signal polish + capability drop** (§3.5, §13.3, §13.2 step 13).
   WINCH resize via the launcher→control-pipe path; Ctrl-C reaches the agent;
   exit codes match bare runs; agent runs with empty capability bounding set and
   `no_new_privs`.
7. **M6 full config: base_url rewrites, kimi plain-loopback, cred_mount/
   env_passthrough (B4), all seed stanzas, validation** (§3.7b, §3.8, §5).
   Config conflicts fail to load; the seed validates (§15.1); codex works via
   `cred_mount` (E2E step 5).
8. **M7 lifecycle: auto-spawn + PING/PONG health check + flock singleton +
   SIGHUP reload; per-session socket registration; crash-cleanup sweep;
   fail-closed; audit rotation** (§4.1, §4.10, §3.9). 20 concurrent sessions all
   200; no leaked `sessions/*.sock` or `/tmp/cove-root.*` after `kill -9`.
9. **M8 `cove log` + honest-positioning copy** (§6.4). No "secure sandbox" in any
   string.

Guardrails while implementing:
- **Sanctioned dependencies (exactly two beyond stdlib + x/sys):**
  `github.com/BurntSushi/toml` (config, D7) and `golang.org/x/net/http2` (h2 MITM
  serve, B2). Everything else is stdlib: `net`, `net/http`, `net/http/httputil`,
  `crypto/tls`, `crypto/x509`, `crypto/rsa`, `crypto/rand`, `os`, `os/exec`,
  `syscall`, plus `golang.org/x/sys/unix` for namespace/ioctl/prctl/capset calls
  not in `syscall`.
- Never place a real Class-A secret or the CA private key into any box mount or
  box env. The box gets dummies + the CA *public* cert only. Class-B/C creds
  enter ONLY via explicit `cred_mount`/`env_passthrough` (§5.7), with a warning.
- The allowlist match MUST happen before any DNS resolution (§4.6).
- **h2 inject leg:** drive the terminated TLS conn with `http2.Server.ServeConn`
  (blocks) — NOT `http.Server.Serve(oneShotListener)` for h2 (does not negotiate
  h2 on a pre-handshaked conn; B2). Never hand-roll h2 framing.
- **h1 inject leg (N2):** `http.Serve` over a **`blockingOneShotListener`** (§14)
  IS the correct pattern — it yields a real `http.ResponseWriter` (chunked,
  keepalive, `Flusher`). Do NOT hand-roll HTTP/1.1 framing. The forbiddance above
  is h2-only; the h1 defect to avoid is a NON-blocking listener.
- Both legs: `FlushInterval=-1`; strip conflicting headers before injecting (C1);
  finalize audit bytes at body close (N3).
- **Box isolation:** `pivot_root` is mandatory; `chroot` is FORBIDDEN as a
  fallback (B3). cove-init drops its own caps after netns-up (N6); the agent
  child drops caps + `no_new_privs` and closes control fds (N7) before exec.
- **Setup:** only the AppArmor write runs as root; CA/config/state are the
  invoking user's, owned by the user (B5).
- Fail closed everywhere: if the proxy is down, do not run the agent with a
  dead-end socket silently — exit 69 with a clear message.

### 16.1 Consolidated failure-mode → exit-code table

| Condition | Detection | Exit | User-facing message |
|---|---|---|---|
| Bad flags / usage | flag parse | 64 | usage help |
| `--project` missing / not a dir | stat | 66 | "project path … not found" |
| Proxy cannot start / not reachable | PING/PONG fail after spawn | 69 | "cove proxy unavailable" |
| Namespace/mount/pivot_root setup failed | `ERR` on status pipe (§3.1/§6.1) | **75** | "box setup failed at <stage>: …" |
| userns denied (setup not run) | `unshare` EPERM | 77 | "run `cove setup` (needs sudo, once)" |
| Config malformed / seed-conflict | Load/Validate err | 78 | parse error + conflicting host |
| Agent binary not found | exec ENOENT (child reports via status pipe) | 127 | "agent '…' not found in box PATH" |
| Host OAuth token expired | upstream 401, mode oauth-refresh | agent's own code (401 passed through) | proxyd stderr + warn audit: "run `claude` on host to re-login" (M9) |
| Agent exited normally | wait | agent code | — |
| Agent signalled | wait | 128+signo | — |

---

---

## 17. REVISION LOG (R1)

Every item from the two adversarial reviews, and how it was addressed. Re-read
against the review list: all B/M/C/Minor items are fixed in place; none deferred.

**Blockers**
- **B1 — seed self-conflict (DOA):** removed `generativelanguage.googleapis.com`,
  `huggingface.co`, `api.cloudflare.com` from `allow` (they are `inject`-only);
  each host is now `allow` XOR `inject` (§5.5). Added a mandatory unit test that
  loads the embedded seed and asserts `Validate()==nil` (§15.1).
- **B2 — h2 serve teardown / false "automatic h2":** §4.8 and §14 rewritten to
  drive the terminated TLS conn with `golang.org/x/net/http2`
  `Server.ServeConn` (blocks until all streams complete; guarantees h2). The
  `oneShotListener`+`http.Server.Serve` pattern is explicitly FORBIDDEN. h1 uses
  a blocking single-conn serve loop. `x/net/http2` added as a sanctioned dep
  (§16).
- **B3 — chroot escape:** `pivot_root`+`umount2(MNT_DETACH)` mandated; chroot
  fallback FORBIDDEN with the escape rationale (§3.3 step 10, §13.2 step 10,
  D4). Added empty capability bounding set + `PR_SET_NO_NEW_PRIVS` + empty
  capset before exec (§3.3 step 12, §13.2 step 13).
- **B4 — Class-B provisioning / codex unusable:** added the concrete
  `cred_mount` bind-mount mechanism (files) + `env_passthrough` (env creds) in a
  new §5.7, §3.3 step 9a, config schema (§5.3/§12.1), with a mandatory in-box
  warning. Reconciled §1.6/§5.2/§5.6/D10/§8.2. codex now works after a one-time
  `cred_mount=["~/.codex:rw"]` edit; E2E step 5 proves it.
- **B5 — setup privilege split:** §7.3 rewritten — only the AppArmor write+parse
  runs as root; CA/config/state are created as the invoking user (via
  `SUDO_UID`/`getpwuid`, recommended pre-escalation) with explicit owners/modes;
  a verify step confirms the user can read `ca-key.pem` and re-probe userns.

**Majors**
- **M1 — pty/WINCH contradiction:** one coherent recipe — launcher owns host
  termios-raw + `SIGWINCH`, forwards winsize over `COVE_CTL_FD`; `cove-init` (no
  `Setsid`) does `TIOCSWINSZ`; only the agent child is the session leader
  (§3.4, §3.5, §13.1, D5).
- **M2 — HOME pollution:** box HOME is a dedicated tmpfs `/root` (mode 0700);
  initial cwd stays `/work` (§3.3 step 6a/step 8, §3.8).
- **M3 — kimi base_url contradiction:** single owner — the in-box base-URL
  loopback converts the plain-HTTP call into `CONNECT <host>:443` to the shim →
  normal inject path; dynamic port (`http://127.0.0.1:0`), no hardcode (§3.7b,
  §3.8, §5.5).
- **M4 — /etc too sparse:** enumerated exact set incl. `openssl.cnf`, `localtime`,
  `services`, `protocols`, `gai.conf`, `mime.types`, `ld.so.cache`; added
  `/run`, `/var/tmp`, ro-bind `/sys` for cgroup memory sizing (§3.3 steps 4/5/6,
  §13.2).
- **M5 — dropped post-CONNECT bytes:** specified the `bufConn` wrapper
  (`io.MultiReader` of buffered remainder + raw conn) handed to `tls.Server`/
  splice (§4.2, §14).
- **M6 — forgeable audit identity:** per-session proxy-owned sockets; identity
  fixed host-side at `REGISTER`; in-box preamble removed; §8.4 corrected to state
  the fields are trustworthy (§4.1, §4.9, §13.3, D6).
- **M7 — cap-drop/no_new_privs:** folded into B3 (§3.3 step 12, §13.2 step 13,
  M5 build step).
- **M8 — tmpfs OOM:** shrank defaults (`/tmp` 256 MiB, `/dev/shm` 64 MiB, `/root`
  256 MiB, `/run` 16 MiB, `/var/tmp` 64 MiB); documented the ~30-session
  aggregate in the mount plan (§3.3 step 6/7, §13.2).
- **M9 — 401 hint mis-routed:** proxy passes the 401 to the agent and writes the
  re-login hint to proxyd stderr + a warn audit record (rate-limited); the
  launcher is no longer claimed to be in the response path (§5.4, §14).

**Coordinator additions**
- **C1 — strip conflicting auth headers:** added per-stanza `strip_headers`
  (default `["x-api-key"]` on the anthropic/openai stanzas); §14 strips before
  injecting; M4/E2E step 4 exercises the dummy→strip→inject flow (§4.5, §5.3,
  §5.5, §14, §15).
- **C2 — §4.5 vs §14:** §4.5 marked as overview and explicitly deferring to §14
  as authoritative; the manual read-forward prose removed.

**Minors (all swept)**
- §3.1 leftover fork-writes-uid_map model deleted (now points to the single §13.1
  mechanism).
- `HTTPS_PROXY` derived from `options.proxy_port`; base-URL loopback ports are
  dynamically allocated so no collision (§3.7, §3.8).
- §14 `Transport.CloseIdleConnections()` on return — no idle-conn/fd leak.
- Counting readers specified for audit `bytes_up`/`bytes_down` (§12.3, §14, §15).
- `res_query`-bypasses-nsswitch edge noted (fails closed anyway) (§3.3 step 4).
- `/work` bind remounted `nosuid,nodev` (§3.3 step 8, §13.2 step 8).
- exit-code-70 collision fixed: box-setup failure uses a status pipe and exit
  **75**; an agent may legitimately exit 70 (§3.1, §6.1, §16.1).
- plain-HTTP port-80 forward-proxy path explicitly EXCLUDED (405) in v0 (§4.2).
- D7: vendor `BurntSushi/toml`, hand-rolled alternative deleted — one path
  (§5.3, D7).
- §4.7: CA is deterministically **RSA-2048** (client compat), not "ECDSA or RSA".
- §4.10: proxy health check specified as `PING`/`PONG <version>` handshake.
- D10: `env_passthrough` glob semantics defined (exact or single trailing `*`);
  over-broad patterns and bare `*`/`~`/`/` rejected by `Validate()`.
- `COVE_CONFIG_JSON` hygiene: directives passed via an `ExtraFiles` pipe fd
  (`COVE_DIR_FD`), never an env var, and bootstrap vars scrubbed before exec, so
  nothing sensitive appears in `/proc/<agent>/environ` (§3.8, §13.1).

**FINAL-DESIGN drift**
- codex now works (B4) → success-metric mention of codex is honest.
- kimi reclassification (FINAL-DESIGN Class-B → seed Class-A `inject`) made
  explicit and justified (§5.2); M3/inject path supports it (§3.7b).

---

---

## 18. REVISION LOG (R2)

Final-polish round. Each item confirmed addressed in place.

- **N2 — h1 inject leg under-specified / wrongly forbidden.** §14 now gives a
  concrete `blockingOneShotListener` (~15 lines) and uses `http.Serve(l, rp)`
  with `FlushInterval=-1` for the h1 leg — the correct pattern that yields a real
  `http.ResponseWriter`. The "forbidden `oneShotListener`+Serve" language is
  scoped to the **h2** case only (the defect was the non-blocking listener + no h2
  negotiation, not the pattern). §16 guardrails updated to distinguish the two
  legs.
- **N3 — audit bytes/dur emitted too early.** §14 no longer emits in
  `ModifyResponse`; it builds the record at header time and wraps `resp.Body` in
  a `countingReadCloser` that finalizes `bytes_down`+`dur_ms` and calls
  `audit.Emit` on body EOF/close. Two-phase emit + the `countingReadCloser` type
  specified in §12.3.
- **N4 — §8.1 #1 falsely absolute.** Appended "…UNLESS explicitly `cred_mount`ed
  (§5.7)"; the guarantee now points those creds to the §8.2 residuals.
- **N5 — rw cred_mount corruption under concurrency (elevated).** `cred_mount`
  entries now default to **read-only**; `:rw` is explicit and documented as unsafe
  under concurrent sessions; `:ro`'s honest cost (blocks in-place refresh → needs
  host re-login) stated; per-session copy-in/copy-out sketched as the deferred
  real fix. Updated §5.7, schema (§5.3/§12.1), §3.3 step 9a, §13.2, seed comments,
  D10.
- **N6 — PID 1 keeps CAP_SYS_ADMIN (ptrace-hijack).** `cove-init` now drops its
  OWN bounding + eff/perm/inherit caps and sets `no_new_privs` right after
  netns-up (§3.3 step 12, §13.2 step 12a), before forking the agent; the agent
  child re-asserts (belt-and-suspenders, step 13).
- **N7 — control/status/dir fds + pty master inherited by agent.** The agent
  child now explicitly closes fds 3/4/5 and the pty master immediately before
  `execve` (after writing its one `OK`); cove-init keeps CTL_FD + pty master for
  itself. Documented in §3.8 (fd hygiene) and §13.2 step 13. (CLOEXEC-at-creation
  rejected because cove-init must retain those fds.)
- **N8 — stale references deleted.** §11.1 `conn.go` comment no longer says "read
  preamble"; §3.7b no longer mentions a session preamble; §4.3 port rule now
  states plain-HTTP/80 is `405`-rejected (consistent with §4.2), no port-80 rules.
- **N9 — HF LFS/model downloads denied.** Added `cdn-lfs.huggingface.co`,
  `cdn-lfs-us-1.huggingface.co`, `cdn-lfs-eu-1.huggingface.co`, `*.hf.co` to the
  seed `allow` (opaque tunnel) with a comment to verify current CDN domains at
  ship time; hf inject stanza comment updated.
- **Budget** — §9 revised from ~1200–1500 to **~1800–2200** lines with a
  per-subsystem breakdown reflecting the added machinery.
- **Consistency 1 — `--apparmor-only`.** Replaced the prose-only flag with a wired
  internal role **`cove __apparmor`** in §11.2 dispatch + the function surface
  (`setup.ApparmorOnly()`); §7.3 escalation updated to `sudo cove __apparmor`.
- **Consistency 2 — `/sys` default.** Default is now the **cgroup-only** variant
  (ro tmpfs `/sys` with only `/sys/fs/cgroup` bound ro) to avoid leaking host
  topology while still giving Node a real cgroup memory limit (§3.3 step 5,
  §13.2). Whole-`/sys` ro bind is opt-in, not default.

Status target: IMPLEMENTABLE-AS-IS.

---

## 19. REVISION LOG (R3)

Five trivial non-gating nits from the IMPLEMENTABLE-AS-IS review, each fixed:
- **NEW-1** (honesty): the codex references (§5.7 friction reconciliation,
  §5.5 seed note, E2E step 5) now agree with observed Codex CLI behavior:
  current Codex needs `cred_mount = ["~/.codex:rw"]` to initialize, and that
  explicit writable mount carries the N5 concurrency caveat.
- **NEW-2** (audit accuracy): `allow` records are now emitted **at tunnel close**
  with final byte counts + duration (only `deny` is immediate); §12.3 and §4.4
  agree.
- **NEW-3** (config edge): `proxy_port` MUST be ≥1024 (the shim binds it after
  `CAP_NET_BIND_SERVICE` is dropped); `Validate()` rejects <1024; noted in §5.3
  Options doc and §12.1.
- **COSMETIC-1**: added the trivial `dummyAddr` type used by
  `blockingOneShotListener.Addr()` (§14).
- **COSMETIC-2**: removed the unused `c net.Conn` field from
  `blockingOneShotListener` (§14).

---

*End of specification.*
