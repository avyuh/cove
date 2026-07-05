You are a Linux systems engineer. A prior minimal probe found that on THIS box, two isolation primitives are BLOCKED. Your job: determine whether each blocker is SURMOUNTABLE with reasonable configuration, actually try to unblock them, and report the exact steps + the security/operational tradeoffs. You have passwordless sudo. LOG every persistent system change you make to /tmp/unblock-changes.txt and be prepared to describe how to revert each. Flag loudly anything that weakens the system globally.

THE BOX: ARM64 (aarch64) Ubuntu 24.04, kernel 6.8.0-124-generic, KVM guest, NO /dev/kvm, 4 cores / 7.5GB. cgroups v2. Rootless podman is installed and works. subuid/subgid: dev:100000:65536. Relevant sysctls observed: kernel.unprivileged_userns_clone=1, user.max_user_namespaces=30630, kernel.apparmor_restrict_unprivileged_userns=1.

USE CASE CONTEXT: The goal is low-friction containment for running AI coding agents in YOLO mode (agent runs UNRESTRICTED inside a boundary; boundary protects the host). Rootless podman already provides this and is the current default. The question is whether bubblewrap and/or gVisor can be made to work here and whether either is materially BETTER than plain rootless podman for this use case (e.g. bwrap = lighter/faster startup for many parallel sessions; gVisor = stronger kernel-escape isolation as an opt-in tier).

=== TASK 1: Unblock BUBBLEWRAP ===
Prior failure: `bwrap: setting up uid map: Permission denied`; with net: `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. Likely cause: Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns=1` restricting unprivileged user namespaces, plus /usr/bin/bwrap not being setuid.
Try, and report which works + its tradeoff:
1. An AppArmor profile that grants bwrap the `userns` permission (Ubuntu 24.04 ships this mechanism; e.g. an unconfined or userns-permitting profile for /usr/bin/bwrap in /etc/apparmor.d/). This is the LEAST-global fix — preferred if it works.
2. Setting `kernel.apparmor_restrict_unprivileged_userns=0` (GLOBAL weakening — note this loudly; test but recommend against if the profile approach works).
3. A setuid bwrap (tradeoff: setuid attack surface).
After unblocking, actually run a low-friction bwrap sandbox: bind a workdir, unshare namespaces, set up networking (slirp4netns/pasta with bwrap, or a net namespace), run a shell command inside, confirm host isolation but unrestricted execution INSIDE (NO landlock/seccomp layer — the point is low friction). Assess: could bwrap-alone be a lighter primitive than podman for many parallel agent sessions? What does it NOT give you (image, named cache volume, lifecycle/exec)?

=== TASK 2: Unblock gVisor / runsc (rootless under podman) ===
Prior failures: default/systemd `creating container: systemd error: Interactive authentication required`; cgroupfs `open /sys/fs/cgroup/cgroup.subtree_control: permission denied`; `--cgroups=disabled` -> `runsc is not compatible with NoCgroups`. runsc ARM64 binary is installed at /usr/local/bin/runsc and self-verifies.
Try, and report which works + tradeoff:
1. Enable cgroup v2 DELEGATION for the rootless user: `loginctl enable-linger`, and a systemd drop-in delegating controllers to the user slice (e.g. /etc/systemd/system/user@.service.d/delegate.conf with `Delegate=cpu cpuset io memory pids`). Re-test `podman --runtime runsc run --rm alpine echo ok` rootless with the systrap platform.
2. Proper gVisor rootless config per https://gvisor.dev/docs/user_guide/rootless/ and podman integration (/etc/containers or ~/.config/containers runtimes entry for runsc with systrap platform, and any required runsc flags like --ignore-cgroups or --rootless).
3. If rootless genuinely cannot work, test ROOTFUL podman + runsc (sudo) as a fallback opt-in tier, and measure whether it runs the agent workload.
If runsc runs: measure startup time and RSS overhead for a trivial container, and note the documented ~10-30% net/file-IO overhead relevance for agent workloads (git/npm/file churn) on 4 cores/7.5GB.

=== OUTPUT ===
For EACH primitive: VERDICT = UNBLOCKED (clean) / UNBLOCKED (with global weakening) / UNBLOCKED (rootful only) / STILL BLOCKED, with the exact working steps, the security/operational tradeoff, and a recommendation: is it worth adopting over plain rootless podman for this safe-YOLO use case — as the DEFAULT, as an OPT-IN tier, or not worth it? Keep changes reversible; list them in /tmp/unblock-changes.txt and summarize how to revert. Be concrete and empirical — actually run the tests, don't theorize.