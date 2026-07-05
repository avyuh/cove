Capability probe complete. Install log is at `/tmp/probe-installs.txt`; it records the apt package delta plus the manual `runsc` binary install.

| Primitive | Runs here? | Rootless? | Needs KVM? | Setup friction | YOLO-inside friction | Host protection | RAM/parallelism | Egress-allowlist feasible? |
|---|---:|---:|---:|---|---|---|---|---|
| Docker `sbx` / Docker Sandboxes | **No** | N/A | **Yes on Linux** | Would require Docker repo + `docker-sbx` + `kvm` group | Low if it ran | Strong microVM boundary | Per-sandbox microVM; likely heavier than containers | **Yes**, built-in policy model |
| Rootless Podman | **Yes**: `podman run --rm busybox echo podman-ok` | **Yes** | No | Moderate apt install: 18 new packages, 127 MB disk | Low; full root-in-container possible | Medium: userns/container isolation, shared host kernel | Cheap; measured trivial run max RSS ~40 MB client/runtime path, BusyBox image 8.8 MB. Many parallel sandboxes plausible on 7.5 GB. Shared long-lived sandbox also natural. | Partial: `--network=none` works; `pasta` and `slirp4netns` work. Fine allowlist needs wrapper/proxy/firewall design, not native rootless iptables. |
| Podman `--userns=keep-id` | **Yes**: UID/GID stayed `1000:1000` | **Yes** | No | Already works after Podman install | Low | Medium | Same as Podman | Same as Podman |
| gVisor `runsc` systrap via rootless Podman | **No, via requested path** | Intended yes | No for systrap | Manual ARM64 binary install worked | Would be low if integrated | Better than plain containers if working | Not measured; failed before start | Would inherit Podman/user-mode networking |
| Bubblewrap | **No unprivileged on this host** | Intended yes | No | Binary already present | Would be very low | Would be medium-light if userns/netns worked | Very cheap in principle; failed before running | No, because net namespace setup failed |
| Dagger / Container Use | **Not as a rootless buy here** | Not for Dagger+Podman per docs | No | Container Use requires Docker; Dagger Podman docs require rootful Podman | Low | Depends on Docker/container backend | Container-level | Depends on backend |
| Imbue `mngr` | **Orchestrator only, not sufficient by itself** | Can run local/SSH/Docker providers | No unless backend does | Would need install/config | Low | Depends on chosen host/provider | Natural for many agents | Docs mention Modal allowlists; local Docker/container protection depends on backend |

**Tested host facts**

- ARM64: `aarch64`, Ubuntu 24.04, kernel `6.8.0-124-generic`.
- `/dev/kvm`: **absent**; no loaded `kvm*` modules.
- User namespaces: `kernel.unprivileged_userns_clone=1`, `user.max_user_namespaces=30630`.
- AppArmor restriction: `kernel.apparmor_restrict_unprivileged_userns=1`.
- cgroups: v2, controllers include `cpu memory pids io cpuset`.
- seccomp: `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`.
- subuid/subgid: `dev:100000:65536` present.
- rootless networking helpers: `pasta` and `slirp4netns` installed and working.
- Podman network tests: `--network=pasta` and `--network=slirp4netns` reached `example.com`; `--network=none` blocked DNS/egress.

**Exact blockers found**

- Docker `sbx`: Docker’s Linux prerequisites require KVM and say if KVM is unavailable, `sbx` will not start. This machine has no `/dev/kvm`, so `sbx` is a hard no here. Docs: https://docs.docker.com/ai/sandboxes/get-started/
- bwrap: failed with `bwrap: setting up uid map: Permission denied`; with net: `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. Likely AppArmor unprivileged userns restriction plus non-setuid `/usr/bin/bwrap`.
- `runsc` rootless Podman: ARM64 `runsc` installed and verified, but Podman failed:
  - default/systemd: `creating container: systemd error: Interactive authentication required`
  - cgroupfs: `open /sys/fs/cgroup/cgroup.subtree_control: permission denied`
  - `--cgroups=disabled`: `requested OCI runtime /usr/local/bin/runsc is not compatible with NoCgroups`

**Make-vs-buy bottom line**

No clean “just buy it” answer on this box. Docker `sbx` is the closest fit for YOLO agents plus egress governance, but it is blocked by missing KVM/nested virt. Container Use/Dagger and `mngr` are useful workflow tools, but they do not replace the missing local isolation primitive; Dagger’s Podman backend wants rootful Podman, and Container Use requires Docker.

The single best-supported primitive on this machine is **rootless Podman with `pasta`/`slirp4netns`**, plus a design pass for network egress control. It works today, is cheap enough for many parallel sandboxes on 7.5 GB, supports a shared long-lived sandbox model, and has low friction for YOLO-inside workflows. Its main weakness is that it is still shared-kernel container isolation, not a microVM boundary.