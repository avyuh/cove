**BUBBLEWRAP: VERDICT = UNBLOCKED (clean)**

Working fix: added a narrow AppArmor allowlist profile at `/etc/apparmor.d/bwrap`:

```apparmor
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
```

Loaded with:

```bash
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Empirical result:

```bash
bwrap --ro-bind / / --dev /dev --proc /proc \
  --unshare-user --uid 0 --gid 0 /bin/true
# final_bwrap_ok
```

Final state:

```text
kernel.apparmor_restrict_unprivileged_userns = 1
/usr/bin/bwrap is NOT setuid: -rwxr-xr-x
AppArmor profile bwrap is loaded
```

I also tested the two alternatives:

- **GLOBAL WEAKENING:** `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` works.
  - Loud warning: this weakens Ubuntu’s unprivileged user namespace restriction globally for all unconfined processes.
  - I restored it to `1`.
  - Do not use this since the per-binary AppArmor profile works.

- **setuid bwrap:** `sudo chmod u+s /usr/bin/bwrap` works.
  - Tradeoff: adds a setuid-root attack surface to a sandboxing tool.
  - I restored mode to `0755`.
  - Not recommended here.

bwrap sandbox with bound workdir and isolated namespaces worked. A file created as root inside appeared as `dev` on the host, confirming user namespace isolation:

```bash
bwrap --unshare-user --uid 0 --gid 0 \
  --unshare-pid --unshare-ipc --unshare-uts \
  --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /etc /etc \
  --dev /dev --proc /proc --tmpfs /tmp \
  --bind /tmp/bwrap-work /work --chdir /work \
  /bin/sh -c 'id; printf inside > inside-created'
```

Networking: `pasta --config-net` failed on this box with UID map errors. `slirp4netns` worked when attached to bwrap’s child netns via `--info-fd`; DNS required an ephemeral sandbox resolver pointing at `10.0.2.3`. HTTP fetch succeeded:

```text
tap0: 10.0.2.100/24
default via 10.0.2.2
nameserver 10.0.2.3
curl example.com -> 559 bytes
```

Startup measurement for trivial bwrap command:

```text
bwrap true: 0.00s elapsed, ~1792 KiB max RSS
```

Recommendation: **worth considering as a DEFAULT only if you build a small wrapper around it.** It is much lighter than Podman for many short-lived sessions, but bwrap alone does not give you images, image updates, named volumes/cache management, lifecycle APIs, `podman exec`, logs, or container metadata. It is a namespace/mount primitive, not a container manager.

**gVisor / runsc: VERDICT = UNBLOCKED (clean rootless, with cgroup accounting tradeoff)**

Rootless works now with Podman using `runsc` systrap plus `--ignore-cgroups`.

The direct working command was:

```bash
podman --runtime /usr/local/bin/runsc \
  --runtime-flag=platform=systrap \
  --runtime-flag=ignore-cgroups \
  run --rm alpine echo ok_ignore
```

Result:

```text
ok_ignore
```

I then registered a rootless named runtime:

`/home/dev/.local/bin/runsc-podman-rootless`:

```sh
#!/bin/sh
exec /usr/local/bin/runsc --platform=systrap --ignore-cgroups "$@"
```

`/home/dev/.config/containers/containers.conf`:

```toml
[engine.runtimes]
runsc = ["/home/dev/.local/bin/runsc-podman-rootless"]
```

Final test:

```bash
podman --runtime runsc run --rm alpine echo final_runsc_ok
# final_runsc_ok
```

I also added the requested systemd delegation drop-in:

```ini
# /etc/systemd/system/user@.service.d/delegate.conf
[Service]
Delegate=cpu cpuset io memory pids
```

Tradeoff: this is normal rootless-container plumbing, not a global security weakening. However, the already-running user manager still had only `cpu memory pids` active in `cgroup.subtree_control`; the decisive fix for this session was `runsc --ignore-cgroups`, not delegation alone.

The original failure modes after delegation:

```text
systemd cgroup manager: Interactive authentication required
cgroupfs without runsc ignore-cgroups: open /sys/fs/cgroup/cgroup.subtree_control: permission denied
```

With `--ignore-cgroups`, both systemd and cgroupfs Podman paths ran.

gVisor rootless doc note: the current gVisor docs describe Podman/Docker rootless as the “caller-configured userns” path and separately document `runsc --rootless` as mainly suitable for direct `runsc do`, with limitations around `create`, save/restore, and netstack. Source: https://gvisor.dev/docs/user_guide/rootless/

Measurements, cached Alpine:

```text
podman+crun true:   0.19-0.20s
podman+runsc true:  0.32-0.37s
```

Trivial sleeping runsc container host RSS:

```text
runsc-gofer:   ~24 MiB RSS
runsc-sandbox: ~33 MiB RSS
```

Plain crun sleep process was ~0.9 MiB RSS, though that excludes transient Podman/conmon overhead.

Mounted-workdir smoke test also worked:

```bash
podman --runtime runsc run --rm \
  -v /home/dev/cove:/work:rw -w /work \
  alpine sh -c 'find . -maxdepth 1 | wc -l'
# rc 0
```

Recommendation: **adopt gVisor as an OPT-IN tier, not the default.** It gives materially stronger kernel-escape isolation than plain rootless Podman, which is valuable for higher-risk YOLO runs. But on this 4-core / 7.5GB ARM64 guest, the startup and RSS overhead are real, and agent workloads with git/npm/file churn may feel the documented file/network I/O overhead. Also, `--ignore-cgroups` means runsc is not enforcing/configuring cgroups internally, so resource accounting/limits are weaker than a fully delegated setup.

**Persistent Changes Logged**

All persistent changes are in `/tmp/unblock-changes.txt`.

Active changes:

```text
/etc/apparmor.d/bwrap
/etc/systemd/system/user@.service.d/delegate.conf
/home/dev/.local/bin/runsc-podman-rootless
/home/dev/.config/containers/containers.conf
```

Revert:

```bash
sudo apparmor_parser -R /etc/apparmor.d/bwrap 2>/dev/null || true
sudo rm /etc/apparmor.d/bwrap

sudo rm /etc/systemd/system/user@.service.d/delegate.conf
sudo systemctl daemon-reload
loginctl terminate-user dev

rm /home/dev/.local/bin/runsc-podman-rootless
rm /home/dev/.config/containers/containers.conf
```

Temporary changes already reverted:

```text
kernel.apparmor_restrict_unprivileged_userns=0 test restored to 1
/usr/bin/bwrap setuid test restored to mode 0755
```