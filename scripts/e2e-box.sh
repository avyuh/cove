#!/usr/bin/env bash
set -euo pipefail

COVE_BIN="${COVE_BIN:-/usr/local/bin/cove}"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="$(mktemp -d)"
failures=0
created_bait=()

audit_path="${XDG_STATE_HOME:-$HOME/.local/state}/cove/audit.log"
state_sock="${XDG_STATE_HOME:-$HOME/.local/state}/cove/proxyd.sock"
state_dir="$(dirname "$state_sock")"
sessions_dir="$state_dir/sessions"
ca_pem="${COVE_CA_PEM:-$HOME/.config/cove/ca.pem}"
ca_key="${COVE_CA_KEY:-$HOME/.config/cove/ca-key.pem}"
host_root_bait="/tmp/cove_host_root_bait.$$"
runtime_fixture_top="$HOME/.cove-e2e-runtime-$$"
runtime_mount="$runtime_fixture_top/versions/node/v-test"
runtime_first_component="$(basename "$runtime_fixture_top")"
runtime_cfg_home="$WORK/runtime-cfg"
runtime_state_home="$WORK/runtime-state"

cleanup() {
  for p in "${created_bait[@]}"; do
    rm -rf "$p"
  done
  rm -f "$host_root_bait"
  rm -rf "$WORK"
}
trap cleanup EXIT

sq() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

plant_bait() {
  local path="$1"
  local body="$2"
  if [[ -e "$path" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$body" >"$path"
  created_bait+=("$path")
}

check() {
  local name="$1"
  shift
  set +e
  "$@" >"$WORK/$name.out" 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  /' "$WORK/$name.out"
    failures=$((failures + 1))
  fi
}

box_eval() {
  "$COVE_BIN" -- /bin/sh -lc "$1"
}

runtime_box_eval() {
  env XDG_CONFIG_HOME="$runtime_cfg_home" XDG_STATE_HOME="$runtime_state_home" "$COVE_BIN" -- /bin/sh -lc "$1"
}

expect_exit() {
  local want="$1"
  shift
  local opts="$-"
  set +e
  "$@" >"$WORK/exit.out" 2>&1
  local got=$?
  case "$opts" in
    *e*) set -e ;;
    *) set +e ;;
  esac
  if [[ $got -ne $want ]]; then
    echo "expected exit $want, got $got"
    sed 's/^/  /' "$WORK/exit.out"
    return 1
  fi
  return 0
}

wait_for_path() {
  local path="$1"
  local i
  for i in $(seq 1 100); do
    [[ -e "$path" ]] && return 0
    sleep 0.05
  done
  echo "timed out waiting for $path"
  return 1
}

wait_file_contains() {
  local path="$1"
  local pattern="$2"
  local i
  for i in $(seq 1 100); do
    if [[ -e "$path" ]] && grep -F "$pattern" "$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for $pattern in $path"
  [[ -e "$path" ]] && sed 's/^/  /' "$path"
  return 1
}

proxy_ping() {
  local sock="${1:-$state_sock}"
  python3 - "$sock" <<'PY'
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX)
s.settimeout(2)
s.connect(path)
s.sendall(b"PING\n")
data = s.recv(1024).decode("utf-8", "replace")
print(data.strip())
sys.exit(0 if data.startswith("PONG ") else 1)
PY
}

proxyd_pid_for_state() {
  local dir="$1"
  python3 - "$dir" <<'PY'
import os, sys
state = os.path.abspath(sys.argv[1])
lock = os.path.join(state, "proxyd.lock")
uid = os.getuid()
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    proc = os.path.join("/proc", name)
    try:
        with open(os.path.join(proc, "status"), "r", encoding="utf-8", errors="replace") as f:
            status = f.read().splitlines()
        uid_line = next((line for line in status if line.startswith("Uid:")), "")
        if not uid_line or int(uid_line.split()[1]) != uid:
            continue
        with open(os.path.join(proc, "cmdline"), "rb") as f:
            cmd = [part for part in f.read().split(b"\0") if part]
        if len(cmd) < 2 or cmd[1] != b"proxyd":
            continue
        fd_dir = os.path.join(proc, "fd")
        for fd in os.listdir(fd_dir):
            try:
                if os.readlink(os.path.join(fd_dir, fd)) == lock:
                    print(pid)
                    sys.exit(0)
            except OSError:
                pass
    except (OSError, ValueError, StopIteration):
        pass
sys.exit(1)
PY
}

wait_proxyd_down() {
  local dir="$1"
  local i
  for i in $(seq 1 100); do
    if ! proxyd_pid_for_state "$dir" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "proxyd still running for $dir"
  return 1
}

create_stale_unix_socket() {
  local path="$1"
  python3 - "$path" <<'PY'
import os, socket, sys
path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX)
s.bind(path)
s.close()
PY
}

seed_isolated_cove() {
  local cfg_home="$1"
  mkdir -p "$cfg_home/cove"
  cp "$ca_pem" "$cfg_home/cove/ca.pem"
  cp "$ca_key" "$cfg_home/cove/ca-key.pem"
}

latest_audit_has() {
  local host="$1"
  local policy="$2"
  local predicate="$3"
  python3 - "$audit_path" "$host" "$policy" "$predicate" <<'PY'
import json, sys
path, host, policy, predicate = sys.argv[1:5]
records = []
try:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("host") == host and rec.get("policy") == policy:
                records.append(rec)
except FileNotFoundError:
    print(f"audit log missing: {path}")
    sys.exit(1)
if not records:
    print(f"no audit record for host={host!r} policy={policy!r}")
    sys.exit(1)
rec = records[-1]
print(json.dumps(rec, sort_keys=True))
if predicate == "deny403":
    ok = rec.get("status") == 403
elif predicate == "allow_closed":
    ok = rec.get("bytes_up", 0) > 0 and rec.get("bytes_down", 0) > 0 and rec.get("dur_ms", 0) > 0
elif predicate == "deny400_structural":
    ok = rec.get("status") == 400 and isinstance(rec.get("session"), str) and len(rec["session"]) == 8 and "spoofed" not in json.dumps(rec)
else:
    ok = False
if not ok:
    print(f"predicate {predicate} failed")
    sys.exit(1)
PY
}

require_paths() {
  [[ -x "$COVE_BIN" ]] || { echo "missing executable $COVE_BIN"; return 1; }
  [[ -s "$ca_pem" ]] || { echo "missing CA cert $ca_pem"; return 1; }
  [[ -s "$ca_key" ]] || { echo "missing CA key $ca_key"; return 1; }
}

setup_bait() {
  plant_bait "$HOME/.ssh/cove_bait" "COVE_SSH_BAIT"
  plant_bait "$HOME/.aws/credentials" "COVE_AWS_BAIT"
  plant_bait "$HOME/.claude/cove_bait" "COVE_CLAUDE_BAIT"
  plant_bait "$HOME/.config/gh/hosts.yml" "COVE_GH_BAIT"
  plant_bait "$HOME/.mozilla/firefox/cove.default/cookies.sqlite" "COVE_COOKIE_BAIT"
  printf 'COVE_HOST_ROOT_BAIT\n' >"$host_root_bait"
}

setup_runtime_fixture() {
  mkdir -p "$runtime_mount/bin" "$runtime_mount/lib"
  printf '#!/bin/sh\necho COVE-FAKE-RUNTIME\n' >"$runtime_mount/bin/cove-fake-runtime"
  chmod 0755 "$runtime_mount/bin/cove-fake-runtime"
  created_bait+=("$runtime_fixture_top")
  seed_isolated_cove "$runtime_cfg_home"
  mkdir -p "$runtime_state_home"
  cat >"$runtime_cfg_home/cove/config.toml" <<EOF
[options]
tmp_size = "256m"
proxy_port = 8080
audit = true
cred_mount = []
runtime_mount = ["$runtime_mount"]
env_passthrough = []

allow = ["pypi.org"]
EOF
}

b1_secret_absence() {
  box_eval 'set -eu
for p in /root/.ssh/cove_bait /root/.aws/credentials /root/.claude/cove_bait /root/.config/gh/hosts.yml /root/.mozilla/firefox/cove.default/cookies.sqlite; do
  if cat "$p" >/tmp/cat.out 2>&1; then
    echo "PRESENT $p"
    exit 1
  fi
  grep -q "No such file" /tmp/cat.out || { cat /tmp/cat.out; exit 1; }
  echo "ABSENT $p"
done'
}

b2_ip_proxy_403() {
  box_eval 'out="$(curl -skv --max-time 8 https://1.1.1.1/ -o /dev/null 2>&1 || true)"; printf "%s\n" "$out"; echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"'
}

b2_raw_socket_enetunreach() {
  box_eval 'python3 - <<'"'"'PY'"'"'
import errno, socket, sys
s = socket.socket()
try:
    s.connect(("1.1.1.1", 443))
except OSError as e:
    print(f"errno={e.errno}")
    sys.exit(0 if e.errno == errno.ENETUNREACH else 1)
else:
    print("raw connect unexpectedly succeeded")
    sys.exit(1)
PY'
}

b2_no_resolver() {
  box_eval 'set +e; getent hosts example.com; rc=$?; set -e; echo "getent_rc=$rc"; test "$rc" -eq 2'
}

b2_evil_403_and_audit() {
  box_eval 'out="$(curl -skv --max-time 8 https://evil.example.com/ -o /dev/null 2>&1 || true)"; printf "%s\n" "$out"; echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"'
  latest_audit_has "evil.example.com" "deny" "deny403"
  "$COVE_BIN" log --deny-only --host evil.example.com | grep -F '"policy":"deny"' >/dev/null
}

b2_ip_literal_denied() {
  box_eval 'out="$(curl -skv --max-time 8 https://5.6.7.8/ -o /dev/null 2>&1 || true)"; printf "%s\n" "$out"; echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"'
  latest_audit_has "5.6.7.8" "deny" "deny403"
}

b3_privilege() {
  box_eval 'set -eu
field_value() {
  want="$1"
  file="$2"
  while read -r key val rest; do
    if [ "$key" = "$want:" ]; then
      printf "%s" "$val"
      return 0
    fi
  done <"$file"
  return 1
}
check_status() {
  f="$1"
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    v="$(field_value "$field" "$f")"
    test "$v" = "0000000000000000" || { echo "$f $field=$v"; exit 1; }
  done
  nnp="$(field_value NoNewPrivs "$f")"
  test "$nnp" = "1" || { echo "$f NoNewPrivs=$nnp"; exit 1; }
}
print_status() {
  label="$1"
  f="$2"
  printf "%s" "$label"
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    printf " %s=%s" "$field" "$(field_value "$field" "$f")"
  done
  printf " NoNewPrivs=%s\n" "$(field_value NoNewPrivs "$f")"
}
check_status /proc/self/status
check_status /proc/1/status
print_status agent /proc/self/status
print_status pid1 /proc/1/status
pids="$(find /proc -maxdepth 1 -type d -name "[0-9]*" -printf "%f\n" | wc -l)"
echo "proc_pid_count=$pids"
test "$pids" -le 25'
}

b4_pivot_root() {
  local home_q root_q
  home_q="$(sq "$HOME")"
  root_q="$(sq "$host_root_bait")"
  box_eval "set -eu
test ! -e /.oldroot
test \"\$(grep -c oldroot /proc/mounts)\" = \"0\"
test ! -e ${home_q}/.ssh/cove_bait
test ! -e ${root_q}
! grep -F \" ${home_q} \" /proc/mounts
echo pivot-root-ok"
}

b5_audit_unforgeable() {
  box_eval 'python3 - <<'"'"'PY'"'"'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect("/proxy/proxy.sock")
s.sendall(b"X-Cove-Session: spoofed\r\n\r\n")
data = s.recv(4096)
text = data.decode("utf-8", "replace")
print(text)
sys.exit(0 if "400 Bad Request" in text else 1)
PY'
  python3 - "$state_sock" <<'PY'
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX)
s.settimeout(2)
s.connect(path)
s.sendall(b"PING\n")
data = s.recv(1024).decode("utf-8", "replace")
print(data.strip())
sys.exit(0 if data.startswith("PONG ") else 1)
PY
  latest_audit_has "" "deny" "deny400_structural"
}

b6_ca_key_absent() {
  local snippet snippet_q
  snippet="$(awk 'NR == 2 {print; exit}' "$ca_key")"
  snippet_q="$(sq "$snippet")"
  box_eval "set -eu
set +e
grep -R -F ${snippet_q} /etc /root /run /proxy /tmp >/tmp/keygrep.out 2>/tmp/keygrep.err
rc=\$?
set -e
cat /tmp/keygrep.err || true
echo \"grep_rc=\$rc\"
test ! -s /tmp/keygrep.out
test -s /etc/ssl/certs/cove-ca.pem
test -s /etc/ssl/certs/cove-ca-bundle.pem
test \"\$(wc -c </etc/ssl/certs/cove-ca-bundle.pem)\" -gt \"\$(wc -c </etc/ssl/certs/cove-ca.pem)\"
line=\"\$(sed -n 2p /etc/ssl/certs/cove-ca.pem)\"
grep -F \"\$line\" /etc/ssl/certs/cove-ca-bundle.pem >/dev/null"
}

b7_allow_opaque() {
  box_eval 'python3 - <<'"'"'PY'"'"'
import socket, ssl, sys
s = socket.create_connection(("127.0.0.1", 8080), timeout=8)
s.sendall(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
print(resp.decode("utf-8", "replace").splitlines()[0] if resp else "no response")
if b"200 Connection Established" not in resp:
    sys.exit(1)
ctx = ssl.create_default_context()
tls = ctx.wrap_socket(s, server_hostname="pypi.org")
cert = tls.getpeercert()
issuer = " ".join("=".join(x) for rdn in cert.get("issuer", ()) for x in rdn)
print("issuer=" + issuer)
sys.exit(1 if "cove local CA" in issuer.lower() else 0)
PY'
}

rt_b1_secret_absence_home() {
  local home_q mount_q first_q
  home_q="$(sq "$HOME")"
  mount_q="$(sq "$runtime_mount")"
  first_q="$(sq "$runtime_first_component")"
  runtime_box_eval "set -eu
test -d ${mount_q}/bin
test \"\$(command -v cove-fake-runtime)\" = \"${runtime_mount}/bin/cove-fake-runtime\"
for p in ${home_q}/.ssh/cove_bait ${home_q}/.aws/credentials ${home_q}/.claude/cove_bait ${home_q}/.config/gh/hosts.yml; do
  test ! -e \"\$p\" || { echo \"PRESENT \$p\"; exit 1; }
done
entries=\"\$(find ${home_q} -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)\"
printf 'runtime_home_entries=%s\n' \"\$entries\"
test \"\$entries\" = ${first_q}
echo runtime-secret-absence-ok"
}

rt_b2_egress_fail_closed() {
  runtime_box_eval 'python3 - <<'"'"'PY'"'"'
import errno, socket, sys
s = socket.socket()
try:
    s.connect(("1.1.1.1", 443))
except OSError as e:
    print(f"errno={e.errno}")
    sys.exit(0 if e.errno == errno.ENETUNREACH else 1)
else:
    print("raw connect unexpectedly succeeded")
    sys.exit(1)
PY'
  runtime_box_eval 'out="$(curl -skv --max-time 8 https://evil.example.com/ -o /dev/null 2>&1 || true)"; printf "%s\n" "$out"; echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"'
}

rt_b7_allow_opaque() {
  runtime_box_eval 'python3 - <<'"'"'PY'"'"'
import socket, ssl, sys
s = socket.create_connection(("127.0.0.1", 8080), timeout=8)
s.sendall(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
print(resp.decode("utf-8", "replace").splitlines()[0] if resp else "no response")
if b"200 Connection Established" not in resp:
    sys.exit(1)
ctx = ssl.create_default_context()
tls = ctx.wrap_socket(s, server_hostname="pypi.org")
cert = tls.getpeercert()
issuer = " ".join("=".join(x) for rdn in cert.get("issuer", ()) for x in rdn)
print("issuer=" + issuer)
sys.exit(1 if "cove local CA" in issuer.lower() else 0)
PY'
}

rt_read_only_erofs() {
  local target_q
  target_q="$(sq "$runtime_mount/cove-write-test")"
  runtime_box_eval "python3 - ${target_q} <<'PY'
import errno, sys
try:
    with open(sys.argv[1], 'w', encoding='utf-8') as f:
        f.write('nope')
except OSError as e:
    print(f'errno={e.errno}')
    sys.exit(0 if e.errno == errno.EROFS else 1)
else:
    print('runtime mount write unexpectedly succeeded')
    sys.exit(1)
PY"
}

e_pypi_allow_audit() {
  box_eval 'code="$(curl -sS --max-time 20 -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/)"; echo "http_code=$code"; test "$code" = "200"'
  latest_audit_has "pypi.org" "allow" "allow_closed"
}

e_log_filters() {
  "$COVE_BIN" log --host pypi.org | grep -F '"host":"pypi.org"' >/dev/null
  "$COVE_BIN" log --deny-only >"$WORK/deny-only.log"
  grep -F '"policy":"deny"' "$WORK/deny-only.log" >/dev/null
  ! grep -F '"policy":"allow"' "$WORK/deny-only.log" >/dev/null
}

m8_log_filters_seeded() {
  local state="$WORK/m8-log-state"
  local audit="$state/cove/audit.log"
  rm -rf "$state"
  mkdir -p "$(dirname "$audit")"
  cat >"$audit" <<'JSONL'
{"ts":"2026-07-05T00:00:00Z","session":"aaa11111","policy":"allow","host":"pypi.org","port":443,"bytes_up":1,"bytes_down":2,"dur_ms":3}
{"ts":"2026-07-05T00:00:00Z","session":"bbb22222","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
{"ts":"2026-07-05T00:00:00Z","session":"aaa11111","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
{"ts":"2026-07-05T00:00:00Z","session":"ccc33333","policy":"allow","host":"evil.example.com","port":443,"bytes_up":4,"bytes_down":5,"dur_ms":6}
{"ts":
JSONL
  env XDG_STATE_HOME="$state" "$COVE_BIN" log --deny-only >"$WORK/m8-deny-only.log"
  env XDG_STATE_HOME="$state" "$COVE_BIN" log --session aaa11111 >"$WORK/m8-session.log"
  env XDG_STATE_HOME="$state" "$COVE_BIN" log --host evil.example.com >"$WORK/m8-host.log"
  env XDG_STATE_HOME="$state" "$COVE_BIN" log --deny-only --session aaa11111 --host evil.example.com >"$WORK/m8-composed.log"
  python3 - "$WORK/m8-deny-only.log" "$WORK/m8-session.log" "$WORK/m8-host.log" "$WORK/m8-composed.log" <<'PY'
import json, sys

def load(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    return records

deny, session, host, composed = map(load, sys.argv[1:5])
checks = [
    ("deny-only", len(deny) == 2 and all(r.get("policy") == "deny" for r in deny)),
    ("session", len(session) == 2 and all(r.get("session") == "aaa11111" for r in session)),
    ("host", len(host) == 3 and all(r.get("host") == "evil.example.com" for r in host)),
    ("composed", len(composed) == 1 and composed[0].get("policy") == "deny" and composed[0].get("session") == "aaa11111" and composed[0].get("host") == "evil.example.com"),
]
for name, ok in checks:
    print(f"{name}={ok}")
    if not ok:
        sys.exit(1)
PY
}

m8_log_follow_append_rotate() {
  local state="$WORK/m8-follow-state"
  local audit="$state/cove/audit.log"
  local out="$WORK/m8-follow.out"
  local err="$WORK/m8-follow.err"
  local pid rc
  rm -rf "$state"
  mkdir -p "$(dirname "$audit")"
  : >"$audit"
  env XDG_STATE_HOME="$state" "$COVE_BIN" log --follow --deny-only >"$out" 2>"$err" &
  pid=$!
  rc=0
  {
    sleep 0.2
    printf '%s\n' '{"ts":"2026-07-05T00:00:00Z","session":"aaa11111","policy":"allow","host":"pypi.org","port":443,"bytes_up":1,"bytes_down":2,"dur_ms":3}' >>"$audit"
    sleep 0.2
    ! grep -F 'pypi.org' "$out" >/dev/null 2>&1
    printf '%s\n' '{"ts":"2026-07-05T00:00:00Z","session":"bbb22222","policy":"deny","host":"follow-deny.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}' >>"$audit"
    wait_file_contains "$out" 'follow-deny.example.com'
    mv "$audit" "$audit.1"
    printf '%s\n' '{"ts":"2026-07-05T00:00:00Z","session":"ccc33333","policy":"deny","host":"follow-rotated.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}' >"$audit"
    wait_file_contains "$out" 'follow-rotated.example.com'
    : >"$audit"
    sleep 0.2
    printf '%s\n' '{"ts":"2026-07-05T00:00:00Z","session":"ddd44444","policy":"deny","host":"follow-truncated.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}' >>"$audit"
    wait_file_contains "$out" 'follow-truncated.example.com'
    test "$(grep -c 'follow-deny.example.com' "$out")" = "1"
  } || rc=$?
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  if [[ $rc -ne 0 ]]; then
    sed 's/^/follow-stdout: /' "$out" || true
    sed 's/^/follow-stderr: /' "$err" || true
    return "$rc"
  fi
  sed 's/^/follow: /' "$out"
}

m8_no_forbidden_positioning_phrase() {
  local needle bin
  needle="$(printf '%s %s' sec'ure' sand'box')"
  bin="$WORK/cove-strings-check"
  (cd "$REPO_ROOT" && "$GO_BIN" build -o "$bin" ./cmd/cove)
  if strings "$bin" | grep -i -F "$needle" >"$WORK/m8-binary-strings.out"; then
    sed 's/^/binary: /' "$WORK/m8-binary-strings.out"
    return 1
  fi
  (cd "$REPO_ROOT" && grep -R -I -n -i -F "$needle" README.md install.sh cmd internal docs/*.md --exclude='SPEC.md' >"$WORK/m8-source-strings.out") || true
  if [[ -s "$WORK/m8-source-strings.out" ]]; then
    sed 's/^/source: /' "$WORK/m8-source-strings.out"
    return 1
  fi
  echo "binary_strings_forbidden_phrase=0"
  echo "source_strings_forbidden_phrase=0"
}

e_claude_runtime_positive() {
  command -v claude >/dev/null || { echo "host claude missing from PATH"; return 1; }
  [[ -s "$HOME/.claude/.credentials.json" ]] || { echo "host Claude OAuth credentials missing"; return 1; }
  local start_size rc opts
  start_size="$(stat -c%s "$audit_path" 2>/dev/null || printf '0')"
  opts="$-"
  set +e
  timeout 180s "$COVE_BIN" -- claude -p "reply with exactly: COVE-OK" >"$WORK/claude-runtime.out" 2>"$WORK/claude-runtime.err"
  rc=$?
  case "$opts" in
    *e*) set -e ;;
    *) set +e ;;
  esac
  cat "$WORK/claude-runtime.out"
  if [[ $rc -ne 0 ]]; then
    echo "claude rc=$rc"
    sed 's/^/  /' "$WORK/claude-runtime.err"
    return 1
  fi
  grep -F "COVE-OK" "$WORK/claude-runtime.out" >/dev/null || { echo "missing COVE-OK"; return 1; }
  grep -F "cove: runtime " "$WORK/claude-runtime.err" >/dev/null || { echo "missing runtime mount note"; return 1; }
  python3 - "$audit_path" "$start_size" <<'PY'
import json, os, sys
path, start = sys.argv[1], int(sys.argv[2])
records = []
with open(path, "rb") as f:
    size = os.fstat(f.fileno()).st_size
    if start > size:
        print(f"audit rotated during claude test: start={start} size={size}")
        sys.exit(1)
    f.seek(start)
    for raw in f:
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if (
            rec.get("host") == "api.anthropic.com"
            and rec.get("policy") == "inject"
            and rec.get("method") == "POST"
            and str(rec.get("path", "")).startswith("/v1/messages")
            and rec.get("status") == 200
        ):
            records.append(rec)
if not records:
    print("missing claude POST /v1/messages status 200 audit record")
    sys.exit(1)
print(json.dumps(records[-1], sort_keys=True))
PY
}

g_exit_codes() {
  local bad_cfg
  bad_cfg="$(mktemp -d "$WORK/badcfg.XXXXXX")"
  mkdir -p "$bad_cfg/cove"
  printf '[[inject]\n' >"$bad_cfg/cove/config.toml"
  local setup_fail_cfg
  setup_fail_cfg="$(mktemp -d "$WORK/setupfail.XXXXXX")"
  mkdir -p "$setup_fail_cfg/cove"
  cp "$ca_pem" "$setup_fail_cfg/cove/ca.pem"
  printf '[options]\ntmp_size = "not-a-size"\nproxy_port = 8080\naudit = false\nallow = []\n' >"$setup_fail_cfg/cove/config.toml"
  expect_exit 66 "$COVE_BIN" --project "$WORK/no-such-project" -- /bin/true
  expect_exit 78 env XDG_CONFIG_HOME="$bad_cfg" "$COVE_BIN" -- /bin/true
  expect_exit 64 "$COVE_BIN" --bad-flag
  expect_exit 64 "$COVE_BIN"
  expect_exit 0 "$COVE_BIN" -- /bin/true
  echo "exit 0 -> 0"
  expect_exit 70 "$COVE_BIN" -- /bin/sh -c 'exit 70'
  echo "exit 70 -> 70"
  expect_exit 42 "$COVE_BIN" -- /bin/sh -c 'exit 42'
  echo "exit 42 -> 42"
  expect_exit 143 "$COVE_BIN" -- /bin/sh -c 'kill -TERM $$; sleep 1'
  echo "signal TERM -> 143"
  expect_exit 75 env XDG_CONFIG_HOME="$setup_fail_cfg" "$COVE_BIN" -- /bin/true
  echo "box setup failure -> 75"
  expect_exit 127 "$COVE_BIN" -- nonesuch-binary-cove-test
  echo "missing agent -> 127"
}

non_tty_pipe() {
  set +e
  "$COVE_BIN" -- /bin/sh -c 'echo hi' | cat >"$WORK/non-tty-pipe.out" 2>"$WORK/non-tty-pipe.err"
  local rc=${PIPESTATUS[0]}
  set -e
  test "$rc" -eq 0 || { echo "cove rc=$rc"; cat "$WORK/non-tty-pipe.err"; return 1; }
  grep -Fx hi "$WORK/non-tty-pipe.out" >/dev/null
}

m5_pty_signal() {
  python3 "$SCRIPT_DIR/e2e-pty.py"
}

m7_flock_singleton() {
  box_eval 'true'
  local before after rc
  before="$(proxyd_pid_for_state "$state_dir")"
  set +e
  timeout 2s "$COVE_BIN" proxyd >"$WORK/flock-second.out" 2>&1
  rc=$?
  set -e
  test "$rc" -eq 0 || { echo "second proxyd rc=$rc"; cat "$WORK/flock-second.out"; return 1; }
  after="$(proxyd_pid_for_state "$state_dir")"
  test "$before" = "$after" || { echo "proxyd pid changed: before=$before after=$after"; return 1; }
  proxy_ping "$state_sock" >/dev/null
  echo "flock_singleton_pid=$before second_rc=$rc"
}

m7_concurrent_sessions() {
  mkdir -p "$sessions_dir"
  box_eval 'true'
  local proxypid baseline start_size i fail fd_count sock_count
  proxypid="$(proxyd_pid_for_state "$state_dir")"
  baseline="$(find "/proc/$proxypid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  start_size="$(stat -c%s "$audit_path" 2>/dev/null || printf '0')"
  local pids=()
  for i in $(seq 1 20); do
    (
      "$COVE_BIN" -- /bin/sh -lc 'code="$(curl -sS --max-time 40 -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/)"; echo "http_code=$code"; test "$code" = "200"'
    ) >"$WORK/concurrency.$i.out" 2>&1 &
    pids+=("$!")
  done
  fail=0
  for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
      echo "session $((i + 1)) failed"
      sed 's/^/  /' "$WORK/concurrency.$((i + 1)).out"
      fail=1
    fi
  done
  test "$fail" -eq 0 || return 1
  for i in $(seq 1 20); do
    grep -F "http_code=200" "$WORK/concurrency.$i.out" >/dev/null || { echo "missing 200 for session $i"; cat "$WORK/concurrency.$i.out"; return 1; }
  done
  python3 - "$audit_path" "$start_size" 20 <<'PY'
import json, os, sys
path, start, want = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
records = []
with open(path, "rb") as f:
    size = os.fstat(f.fileno()).st_size
    if start > size:
        print(f"audit rotated during concurrency test: start={start} size={size}")
        sys.exit(1)
    f.seek(start)
    for raw in f:
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if rec.get("host") == "pypi.org" and rec.get("policy") == "allow":
            records.append(rec)
sessions = [rec.get("session", "") for rec in records]
distinct = sorted(set(sessions))
bad = [s for s in sessions if not isinstance(s, str) or len(s) != 8]
print(f"concurrency_audit_records={len(records)} distinct_sessions={len(distinct)}")
if len(records) < want or len(distinct) < want or bad:
    print("sessions=" + ",".join(sessions))
    sys.exit(1)
PY
  for i in $(seq 1 100); do
    fd_count="$(find "/proc/$proxypid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
    sock_count="$(find "$sessions_dir" -maxdepth 1 -name '*.sock' 2>/dev/null | wc -l)"
    if [[ "$sock_count" -eq 0 && "$fd_count" -le "$baseline" ]]; then
      echo "concurrency_sessions=20 fd_baseline=$baseline fd_after=$fd_count session_sockets=$sock_count"
      return 0
    fi
    sleep 0.1
  done
  echo "leak check failed: fd_baseline=$baseline fd_after=$fd_count session_sockets=$sock_count"
  find "$sessions_dir" -maxdepth 1 -name '*.sock' -print 2>/dev/null || true
  return 1
}

m7_one_session_parallel_requests() {
  box_eval 'set -eu
pids=""
for i in $(seq 1 20); do
  (code="$(curl -sS --max-time 40 -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/)"; echo "$i:$code"; test "$code" = "200") &
  pids="$pids $!"
done
fail=0
for pid in $pids; do
  wait "$pid" || fail=1
done
test "$fail" = "0"'
}

m7_fail_closed_proxy_death() {
  rm -f "$WORK/failclosed.ready" "$WORK/failclosed.go" "$WORK/failclosed.out"
  "$COVE_BIN" --project "$WORK" -- /bin/sh -lc 'set -eu
code="$(curl -sS --max-time 40 -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/)"
echo "before_code=$code" > /work/failclosed.out
test "$code" = "200"
touch /work/failclosed.ready
while [ ! -e /work/failclosed.go ]; do sleep 0.05; done
set +e
code="$(curl -sS --max-time 8 -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/ 2>>/work/failclosed.out)"
rc=$?
set -e
echo "after_rc=$rc after_code=$code" >> /work/failclosed.out
if [ "$rc" -eq 0 ] && [ "$code" = "200" ]; then
  exit 1
fi' >"$WORK/failclosed.launcher.out" 2>&1 &
  local launcher=$!
  wait_for_path "$WORK/failclosed.ready"
  local pid
  pid="$(proxyd_pid_for_state "$state_dir")"
  kill -9 "$pid"
  wait_proxyd_down "$state_dir"
  touch "$WORK/failclosed.go"
  if ! wait "$launcher"; then
    cat "$WORK/failclosed.launcher.out"
    cat "$WORK/failclosed.out" || true
    return 1
  fi
  grep -F "before_code=200" "$WORK/failclosed.out" >/dev/null
  grep -F "after_rc=" "$WORK/failclosed.out" >/dev/null
  ! grep -F "after_rc=0 after_code=200" "$WORK/failclosed.out" >/dev/null
  box_eval 'true'
  proxy_ping "$state_sock" >/dev/null
  sed 's/^/fail_closed_/' "$WORK/failclosed.out"
}

m7_kill9_sweep_reclaims() {
  box_eval 'true'
  mkdir -p "$sessions_dir"
  local stale_root stale_sock stale_base launcher i count pid sock_count
  stale_root="$(mktemp -d /tmp/cove-root.m7stale.XXXXXX)"
  created_bait+=("$stale_root")
  stale_sock="$sessions_dir/m7-stale-$$.sock"
  stale_base="$(basename "$stale_sock")"
  create_stale_unix_socket "$stale_sock"
  created_bait+=("$stale_sock")
  rm -f "$WORK/kill9.ready"
  "$COVE_BIN" --project "$WORK" -- /bin/sh -lc 'touch /work/kill9.ready; sleep 1' >"$WORK/kill9.launcher.out" 2>&1 &
  launcher=$!
  wait_for_path "$WORK/kill9.ready"
  count="$(find "$sessions_dir" -maxdepth 1 -name '*.sock' ! -name "$stale_base" 2>/dev/null | wc -l)"
  test "$count" -ge 1 || { echo "no live session socket observed"; return 1; }
  kill -9 "$launcher"
  set +e
  wait "$launcher" >/dev/null 2>&1
  set -e
  for i in $(seq 1 100); do
    count="$(find "$sessions_dir" -maxdepth 1 -name '*.sock' ! -name "$stale_base" 2>/dev/null | wc -l)"
    [[ "$count" -eq 0 ]] && break
    sleep 0.05
  done
  test "$count" -eq 0 || { echo "session socket survived launcher kill"; find "$sessions_dir" -maxdepth 1 -name '*.sock' -print; return 1; }
  sleep 2
  pid="$(proxyd_pid_for_state "$state_dir")"
  kill -9 "$pid"
  wait_proxyd_down "$state_dir"
  box_eval 'true'
  test ! -e "$stale_root" || { echo "stale root still exists: $stale_root"; return 1; }
  test ! -e "$stale_sock" || { echo "stale socket still exists: $stale_sock"; return 1; }
  for i in $(seq 1 100); do
    sock_count="$(find "$sessions_dir" -maxdepth 1 -name '*.sock' 2>/dev/null | wc -l)"
    [[ "$sock_count" -eq 0 ]] && break
    sleep 0.05
  done
  test "$sock_count" -eq 0 || { echo "session sockets leaked after sweep"; find "$sessions_dir" -maxdepth 1 -name '*.sock' -print; return 1; }
  echo "kill9_stale_root_reclaimed=$stale_root"
  echo "kill9_stale_socket_reclaimed=$stale_sock"
}

m7_sighup_reload() {
  local cfg_home="$WORK/hup-cfg" state_home="$WORK/hup-state" state="$WORK/hup-state/cove"
  rm -rf "$cfg_home" "$state_home"
  seed_isolated_cove "$cfg_home"
  cat >"$cfg_home/cove/config.toml" <<'EOF'
[options]
tmp_size = "256m"
proxy_port = 8080
audit = true
allow = []
EOF
  rm -f "$WORK/sighup.ready" "$WORK/sighup.go" "$WORK/sighup.out"
  env XDG_CONFIG_HOME="$cfg_home" XDG_STATE_HOME="$state_home" "$COVE_BIN" --project "$WORK" -- /bin/sh -lc 'set -eu
out="$(curl -skv --max-time 8 https://example.com/ -o /dev/null 2>&1 || true)"
printf "%s\n" "$out" > /work/sighup.out
echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"
touch /work/sighup.ready
while [ ! -e /work/sighup.go ]; do sleep 0.05; done
code="$(curl -sS --max-time 20 -o /dev/null -w "%{http_code}" https://example.com/)"
echo "after_code=$code" >> /work/sighup.out
test "$code" = "200"' >"$WORK/sighup.launcher.out" 2>&1 &
  local launcher=$!
  wait_for_path "$WORK/sighup.ready"
  cat >"$cfg_home/cove/config.toml" <<'EOF'
[options]
tmp_size = "256m"
proxy_port = 8080
audit = true
allow = ["example.com"]
EOF
  local pid
  pid="$(proxyd_pid_for_state "$state")"
  kill -HUP "$pid"
  touch "$WORK/sighup.go"
  if ! wait "$launcher"; then
    cat "$WORK/sighup.launcher.out"
    cat "$WORK/sighup.out" || true
    return 1
  fi
  grep -F "after_code=200" "$WORK/sighup.out" >/dev/null
  kill "$pid" >/dev/null 2>&1 || true
  wait_proxyd_down "$state" || true
  echo "sighup_reload_pid=$pid after_code=200"
}

m7_audit_rotation_ring() {
  local cfg_home="$WORK/rotation-cfg" state_home="$WORK/rotation-state" state="$WORK/rotation-state/cove"
  rm -rf "$cfg_home" "$state_home"
  seed_isolated_cove "$cfg_home"
  cat >"$cfg_home/cove/config.toml" <<'EOF'
[options]
tmp_size = "256m"
proxy_port = 8080
audit = true
allow = []
EOF
  env XDG_CONFIG_HOME="$cfg_home" XDG_STATE_HOME="$state_home" "$COVE_BIN" -- /bin/true
  local audit="$state/audit.log" i pid
  for i in $(seq 1 5); do
    printf 'old-%s\n' "$i" >"$audit.$i"
  done
  truncate -s $((64 * 1024 * 1024 + 1)) "$audit"
  env XDG_CONFIG_HOME="$cfg_home" XDG_STATE_HOME="$state_home" "$COVE_BIN" -- /bin/sh -lc 'out="$(curl -skv --max-time 8 https://rotation-denied.example.com/ -o /dev/null 2>&1 || true)"; printf "%s\n" "$out"; echo "$out" | grep -Eq "HTTP/1\.1 403|CONNECT tunnel failed, response 403"'
  for i in $(seq 1 5); do
    test -e "$audit.$i" || { echo "$audit.$i missing"; return 1; }
  done
  test ! -e "$audit.6" || { echo "$audit.6 should not exist"; return 1; }
  grep -F "old-4" "$audit.5" >/dev/null
  ! grep -F "old-5" "$audit.5" >/dev/null
  pid="$(proxyd_pid_for_state "$state")"
  kill "$pid" >/dev/null 2>&1 || true
  wait_proxyd_down "$state" || true
  echo "audit_rotation_ring=1..5 capped old5_dropped"
}

check prereq require_paths
setup_bait
setup_runtime_fixture

check B1-secret-absence b1_secret_absence
check B2-ip-proxy-403 b2_ip_proxy_403
check B2-raw-socket-ENETUNREACH b2_raw_socket_enetunreach
check B2-no-resolver b2_no_resolver
check B2-evil-403-audit b2_evil_403_and_audit
check B2-ip-literal-denied b2_ip_literal_denied
check B3-privilege b3_privilege
check B4-pivot-root b4_pivot_root
check B5-audit-unforgeable b5_audit_unforgeable
check B6-ca-key-absent b6_ca_key_absent
check B7-allow-opaque b7_allow_opaque
check RT-B1-secret-absence-home rt_b1_secret_absence_home
check RT-B2-egress-fail-closed rt_b2_egress_fail_closed
check RT-B7-allow-opaque rt_b7_allow_opaque
check RT-read-only-EROFS rt_read_only_erofs
check E-pypi-allow-audit e_pypi_allow_audit
check E-log-filters e_log_filters
check M8-log-filters-seeded m8_log_filters_seeded
check M8-log-follow-append-rotate m8_log_follow_append_rotate
check M8-no-forbidden-positioning-phrase m8_no_forbidden_positioning_phrase
check E-claude-runtime-positive e_claude_runtime_positive
check G-exit-codes g_exit_codes
check M5-non-tty-pipe non_tty_pipe
check M5-pty-signal-resize m5_pty_signal
check M7-flock-singleton m7_flock_singleton
check M7-concurrent-sessions m7_concurrent_sessions
check M7-one-session-parallel m7_one_session_parallel_requests
check M7-fail-closed-proxy-death m7_fail_closed_proxy_death
check M7-kill9-sweep-reclaims m7_kill9_sweep_reclaims
check M7-sighup-reload m7_sighup_reload
check M7-audit-rotation-ring m7_audit_rotation_ring

if [[ $failures -ne 0 ]]; then
  echo "FAILURES $failures"
  exit 1
fi
echo "ALL PASS"
