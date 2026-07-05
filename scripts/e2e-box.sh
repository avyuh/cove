#!/usr/bin/env bash
set -euo pipefail

COVE_BIN="${COVE_BIN:-/usr/local/bin/cove}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
failures=0
created_bait=()

audit_path="${XDG_STATE_HOME:-$HOME/.local/state}/cove/audit.log"
state_sock="${XDG_STATE_HOME:-$HOME/.local/state}/cove/proxyd.sock"
ca_pem="${COVE_CA_PEM:-$HOME/.config/cove/ca.pem}"
ca_key="${COVE_CA_KEY:-$HOME/.config/cove/ca-key.pem}"
host_root_bait="/tmp/cove_host_root_bait.$$"

cleanup() {
  for p in "${created_bait[@]}"; do
    rm -f "$p"
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

check prereq require_paths
setup_bait

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
check E-pypi-allow-audit e_pypi_allow_audit
check E-log-filters e_log_filters
check G-exit-codes g_exit_codes
check M5-non-tty-pipe non_tty_pipe
check M5-pty-signal-resize m5_pty_signal

if [[ $failures -ne 0 ]]; then
  echo "FAILURES $failures"
  exit 1
fi
echo "ALL PASS"
