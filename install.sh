#!/usr/bin/env sh
# Install a released cove binary. This script intentionally has no build path.
set -eu

repo="https://github.com/avyuh/cove"

die() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) ;;
    *) die "cove releases support Linux only" ;;
esac

case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m) (expected x86_64 or aarch64)" ;;
esac

if command -v curl >/dev/null 2>&1; then
    downloader=curl
elif command -v wget >/dev/null 2>&1; then
    downloader=wget
else
    die "a TLS downloader (curl or wget) is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
    checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    checksum_tool=shasum
else
    die "a SHA-256 checksum tool (sha256sum or shasum) is required"
fi

download() {
    url=$1
    output=$2
    case "$downloader" in
        curl) curl --fail --location --silent --show-error --output "$output" "$url" ;;
        wget) wget --https-only --quiet --output-document="$output" "$url" ;;
    esac
}

if [ -n "${COVE_VERSION:-}" ]; then
    version=$COVE_VERSION
else
    case "$downloader" in
        curl)
            latest_url=$(curl --fail --location --silent --show-error --output /dev/null --write-out '%{url_effective}' "$repo/releases/latest")
            ;;
        wget)
            latest_url=$(wget --https-only --server-response --spider "$repo/releases/latest" 2>&1 | sed -n 's/^[[:space:]]*[Ll]ocation:[[:space:]]*//p' | tail -n 1)
            ;;
    esac
    version=$(printf '%s\n' "$latest_url" | sed -n 's|.*/tag/\(v[^/?#]*\).*|\1|p')
    [ -n "$version" ] || die "could not determine the latest cove release"
fi

case "$version" in
    v*) version_number=${version#v} ;;
    *) version_number=$version ;;
esac
[ -n "$version_number" ] || die "COVE_VERSION must not be empty"

archive="cove_${version_number}_linux_${arch}.tar.gz"
release="$repo/releases/download/$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

download "$release/$archive" "$work/$archive"
download "$release/checksums.txt" "$work/checksums.txt"

checksum_line=$(awk -v file="$archive" '
    $2 == file && NF == 2 && length($1) == 64 && $1 ~ /^[0123456789abcdefABCDEF]+$/ {
        count++; line = $0
    }
    END { if (count == 1) print line; else exit 1 }
' "$work/checksums.txt") || die "checksums.txt does not contain exactly one checksum for $archive"

(
    cd "$work"
    case "$checksum_tool" in
        sha256sum) printf '%s\n' "$checksum_line" | sha256sum --check --status - ;;
        shasum) printf '%s\n' "$checksum_line" | shasum -a 256 --check --status - ;;
    esac
) || die "checksum verification failed for $archive"

extract="$work/extract"
mkdir "$extract" || die "could not create extraction directory"
tar -xzf "$work/$archive" -C "$extract" || die "could not extract $archive"
binary="$extract/cove"
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] || die "release archive does not contain a regular executable cove binary"

install_dir=${COVE_INSTALL_DIR:-"$HOME/.local/bin"}
if [ -e "$install_dir" ] && [ ! -d "$install_dir" ]; then
    die "install directory is not a directory: $install_dir"
fi
mkdir -p "$install_dir" || die "install directory is not writable: $install_dir"
[ -d "$install_dir" ] && [ -w "$install_dir" ] || die "install directory is not writable: $install_dir"

destination="$install_dir/cove"
[ ! -L "$destination" ] || die "refusing to replace symlink destination: $destination"
temporary=$(mktemp "$install_dir/.cove.XXXXXX") || die "could not create temporary install file"
trap 'rm -rf "$work"; rm -f "$temporary"' EXIT HUP INT TERM
cp "$binary" "$temporary" || die "could not copy cove binary"
chmod 0755 "$temporary" || die "could not set executable mode"
[ ! -L "$destination" ] || die "refusing to replace symlink destination: $destination"
mv -f "$temporary" "$destination" || die "could not install cove"
trap 'rm -rf "$work"' EXIT HUP INT TERM

printf 'installed cove to %s\n' "$destination"
case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *)
        printf '%s is not in your PATH. Add this to your shell profile:\n' "$install_dir"
        printf '  export PATH="%s:$PATH"\n' "$install_dir"
        ;;
esac
printf 'next: cove setup\n'
