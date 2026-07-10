#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture="$root/scripts/testdata/fake-release"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
  printf 'install_test: %s\n' "$*" >&2
  exit 1
}

assert_missing() {
  [[ ! -e "$1" && ! -L "$1" ]] || fail "unexpected partial install at $1"
}

make_bin() {
  local name=$1
  mkdir -p "$tmp/$name"
  cat >"$tmp/$name/curl" <<'EOF'
#!/bin/sh
set -eu
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2; continue ;;
    --write-out) shift 2; continue ;;
    --*) shift; continue ;;
    *) url=$1; shift; continue ;;
  esac
done
case "$url" in
  */releases/latest) printf '%s\n' 'https://github.com/avyuh/cove/releases/tag/v0.0.0'; exit 0 ;;
  *checksums.txt) source="$COVE_FAKE_RELEASE/checksums.txt" ;;
  *linux_amd64.tar.gz) source="$COVE_FAKE_RELEASE/cove_0.0.0_linux_amd64.tar.gz" ;;
  *linux_arm64.tar.gz) source="$COVE_FAKE_RELEASE/cove_0.0.0_linux_arm64.tar.gz" ;;
  *) exit 22 ;;
esac
cp "$source" "$out"
EOF
  chmod +x "$tmp/$name/curl"
}

run_install() {
  local name=$1
  local arch=$2
  local home="$tmp/$name/home"
  mkdir -p "$home"
  COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$fixture" HOME="$home" \
    PATH="$tmp/$name:/usr/bin:/bin" \
    "$tmp/$name/uname" -m >/dev/null 2>&1 || true
  COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$fixture" HOME="$home" \
    PATH="$tmp/$name:/usr/bin:/bin" COVE_TEST_ARCH="$arch" \
    /bin/sh "$root/install.sh"
}

make_bin normal
cat >"$tmp/normal/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf 'Linux\n' ;;
  -m) printf '%s\n' "${COVE_TEST_ARCH:-x86_64}" ;;
  *) exec /usr/bin/uname "$@" ;;
esac
EOF
chmod +x "$tmp/normal/uname"
run_install normal x86_64
[[ $("$tmp/normal/home/.local/bin/cove") == fake-amd64 ]] || fail "amd64 fixture was not installed"
[[ $(stat -c '%a' "$tmp/normal/home/.local/bin/cove") == 755 ]] || fail "installed mode is not 0755"
make_bin arm64
cp "$tmp/normal/uname" "$tmp/arm64/uname"
run_install arm64 aarch64
[[ $("$tmp/arm64/home/.local/bin/cove") == fake-arm64 ]] || fail "arm64 fixture was not installed"
mkdir -p "$tmp/latest/home"
COVE_FAKE_RELEASE="$fixture" HOME="$tmp/latest/home" PATH="$tmp/normal:/usr/bin:/bin" COVE_TEST_ARCH=x86_64 /bin/sh "$root/install.sh"
[[ $("$tmp/latest/home/.local/bin/cove") == fake-amd64 ]] || fail "latest redirect did not select the release"

grep -Eq 'podman|git clone|cove build' "$root/install.sh" && fail "installer contains retired install path"
! grep -q 'sudo cove setup\|prints which inject secrets are still unpopulated' "$root/README.md" || fail "README retains dishonest setup claim"

make_bin bad-checksum
cp -R "$fixture" "$tmp/bad-release"
sed -i 's/^./0/' "$tmp/bad-release/checksums.txt"
mkdir -p "$tmp/bad-checksum/home"
if COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$tmp/bad-release" HOME="$tmp/bad-checksum/home" PATH="$tmp/bad-checksum:/usr/bin:/bin" COVE_TEST_ARCH=x86_64 /bin/sh "$root/install.sh"; then
  fail "corrupt checksum was accepted"
fi
assert_missing "$tmp/bad-checksum/home/.local/bin/cove"

make_bin unsupported-os
cat >"$tmp/unsupported-os/uname" <<'EOF'
#!/bin/sh
case "$1" in -s) printf 'Darwin\n' ;; *) printf 'x86_64\n' ;; esac
EOF
chmod +x "$tmp/unsupported-os/uname"
if HOME="$tmp/unsupported-os/home" PATH="$tmp/unsupported-os:/usr/bin:/bin" /bin/sh "$root/install.sh"; then fail "unsupported OS was accepted"; fi
assert_missing "$tmp/unsupported-os/home/.local/bin/cove"

make_bin unsupported-arch
cat >"$tmp/unsupported-arch/uname" <<'EOF'
#!/bin/sh
case "$1" in -s) printf 'Linux\n' ;; *) printf 'riscv64\n' ;; esac
EOF
chmod +x "$tmp/unsupported-arch/uname"
if HOME="$tmp/unsupported-arch/home" PATH="$tmp/unsupported-arch:/usr/bin:/bin" /bin/sh "$root/install.sh"; then fail "unsupported architecture was accepted"; fi
assert_missing "$tmp/unsupported-arch/home/.local/bin/cove"

minimal_path="$tmp/minimal"
mkdir -p "$minimal_path"
ln -s /usr/bin/uname "$minimal_path/uname"
if HOME="$tmp/no-downloader-home" PATH="$minimal_path" /bin/sh "$root/install.sh"; then fail "missing downloader was accepted"; fi
assert_missing "$tmp/no-downloader-home/.local/bin/cove"

make_bin no-checksum
if COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$fixture" HOME="$tmp/no-checksum/home" PATH="$tmp/no-checksum:$minimal_path" /bin/sh "$root/install.sh"; then fail "missing checksum tool was accepted"; fi
assert_missing "$tmp/no-checksum/home/.local/bin/cove"

make_bin symlink
mkdir -p "$tmp/symlink/home/.local/bin" "$tmp/symlink/other"
ln -s "$tmp/symlink/other" "$tmp/symlink/home/.local/bin/cove"
if COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$fixture" HOME="$tmp/symlink/home" PATH="$tmp/symlink:/usr/bin:/bin" COVE_TEST_ARCH=x86_64 /bin/sh "$root/install.sh"; then fail "symlink destination was accepted"; fi
[[ -L "$tmp/symlink/home/.local/bin/cove" ]] || fail "symlink destination was modified"

make_bin unwritable
mkdir -p "$tmp/unwritable/home/bin"
chmod 500 "$tmp/unwritable/home/bin"
if COVE_VERSION=v0.0.0 COVE_FAKE_RELEASE="$fixture" HOME="$tmp/unwritable/home" COVE_INSTALL_DIR="$tmp/unwritable/home/bin" PATH="$tmp/unwritable:/usr/bin:/bin" COVE_TEST_ARCH=x86_64 /bin/sh "$root/install.sh"; then fail "unwritable directory was accepted"; fi
chmod 700 "$tmp/unwritable/home/bin"
assert_missing "$tmp/unwritable/home/bin/cove"

printf 'install_test: PASS\n'
