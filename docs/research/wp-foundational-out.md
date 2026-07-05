**Verdict**

A single static binary using only Linux namespaces is feasible on this box for the narrow goal: credential absence plus deny-by-default network egress.

But it is not “zero setup” on stock Ubuntu 24.04 with `kernel.apparmor_restrict_unprivileged_userns=1`. An arbitrary binary can enter `CLONE_NEWUSER`, but AppArmor transitions it into `unprivileged_userns`, stripping the capabilities needed to write UID/GID maps and do useful namespace setup. It needs a one-time root-installed AppArmor profile granting `userns`, same pattern as Podman and bwrap.

Runtime can then be unprivileged.

**Prototype**

Code added here:

- [lockbox.c](/home/dev/cove/spikes/lockbox/lockbox.c)
- [maprange.c](/home/dev/cove/spikes/lockbox/maprange.c)

Built static with:

```sh
gcc -O2 -Wall -Wextra -static -o /tmp/lockbox spikes/lockbox/lockbox.c
gcc -O2 -Wall -Wextra -static -o /tmp/maprange spikes/lockbox/maprange.c
```

Persistent changes were logged in `/tmp/foundational-changes.txt`. I installed temporary AppArmor profiles:

```text
/etc/apparmor.d/tmp.lockbox
/etc/apparmor.d/tmp.maprange
```

Both are `flags=(unconfined)` plus `userns`, matching the existing Podman/bwrap approach.

**User Namespace Findings**

Before the AppArmor profile:

```sh
/tmp/lockbox --mode deny --project /home/dev/cove -- /bin/sh -lc 'id'
```

failed with:

```text
open /proc/self/setgroups: Permission denied
```

After the profile, single current UID/GID mapping works without `newuidmap`:

```sh
/tmp/lockbox --mode mask -- /bin/sh -lc 'id; cat /proc/self/uid_map; cat /proc/self/gid_map'
```

Subordinate range mapping does require the setuid helpers:

```sh
/tmp/maprange
```

proved:

```text
direct uid_map range write=-1 errno=Operation not permitted
newuidmap exit=0
newgidmap exit=0
uid_map
         0     100000      65536
gid_map
         0     100000      65536
```

So minimal requirement for this tool is:

- single UID map: AppArmor profile only, no setuid helper
- UID range: AppArmor profile plus `newuidmap`/`newgidmap`

**Mount Namespace Findings**

Deny-by-default root worked:

```sh
printf 'HOST_SECRET_BAIT\n' > /tmp/host-secret-bait
/tmp/lockbox --mode deny --project /home/dev/cove -- /bin/sh -lc \
  'ls -la /; cat /tmp/host-secret-bait 2>&1 || echo absent; ls -la /work | head'
```

Observed:

```text
cat: /tmp/host-secret-bait: No such file or directory
absent
```

This is the robust approach. Secrets are absent because the new root only contains curated mounts: `/usr`, minimal `/etc`, `/tmp`, `/dev`, `/work`, and optional `/proxy`.

The mask approach also worked for bait and `~/.ssh`:

```sh
/tmp/lockbox --mode mask --bait /tmp/host-secret-bait -- /bin/sh -lc \
  'cat /tmp/host-secret-bait; ls -la ~/.ssh'
```

The bait was over-mounted and `~/.ssh` showed an empty tmpfs. But this approach is brittle: it depends on an exhaustive secret-path denylist. It is simpler operationally but easier to get wrong.

One prototype limitation: mounting `/proc` inside the deny root failed with `Operation not permitted`, so the prototype skips it. A production version should add a PID namespace and mount proc correctly, or intentionally omit proc if the agent can tolerate that.

**Network Namespace Findings**

The child gets a new netns with only loopback. Raw egress fails even when the program ignores proxy env vars:

```sh
/tmp/lockbox --mode mask --bait /tmp/host-secret-bait -- /bin/sh -lc '
python3 - <<PY
import socket
s=socket.socket()
s.settimeout(3)
try:
    s.connect(("1.1.1.1",443))
    print("CONNECTED")
except Exception as e:
    print(type(e).__name__, e)
PY
curl --noproxy "*" -I --connect-timeout 3 https://1.1.1.1
'
```

Observed:

```text
OSError [Errno 101] Network is unreachable
curl: (7) Failed to connect to 1.1.1.1 port 443
```

Unix socket proxy channel works across the netns:

```sh
rm -f /tmp/lockbox-proxy.sock /tmp/lockbox-proxy.out
( nc -lU /tmp/lockbox-proxy.sock > /tmp/lockbox-proxy.out & )

printf 'hello-through-proxy\n' |
  /tmp/lockbox --mode mask -- /bin/sh -lc 'nc -NU /tmp/lockbox-proxy.sock'

cat /tmp/lockbox-proxy.out
```

Observed:

```text
hello-through-proxy
```

Deny-root mode can also bind the proxy socket into `/proxy/proxy.sock`.

**Recommendation**

For a tool whose only job is credential protection, kernel-namespaces-direct is viable and smaller than Podman. Use deny-by-default filesystem construction, single UID/GID mapping, new netns with no route, and a Unix socket or preconnected fd to your proxy.

Be honest about setup friction: on Ubuntu 24.04 this is not a pure drop-in single binary unless you also install an AppArmor profile once as root. Without that, arbitrary binaries are not equivalent to Podman/bwrap under `apparmor_restrict_unprivileged_userns=1`.

Versus Podman, this gives up images, lifecycle management, exec/session plumbing, mature proc/dev/seccomp defaults, and rootless networking integrations. For 30 concurrent agent sessions, that is not inherently a blocker, but you would need to write your own session supervisor, cleanup, logging, proxy routing, and mount policy. If the product only needs “host tools, no secrets, no raw network,” direct namespaces are defensible. If you want image packaging or broad runtime hardening, keep Podman.