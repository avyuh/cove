#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/cove"
BIN_DIR="$HOME/.local/bin"
REPO_URL="https://github.com/avyuh/cove.git"

info()  { printf '\033[1;34m::\033[0m %s\n' "$*"; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Check dependencies
for cmd in git podman; do
  command -v "$cmd" >/dev/null 2>&1 || error "$cmd is required but not found. Please install it first."
done

# 2. Clone or update
if [ -d "$INSTALL_DIR/.git" ]; then
  info "Updating existing installation in $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only
else
  info "Cloning cove to $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# 3. Build image
info "Building cove container image"
"$INSTALL_DIR/cove" build

# 4. Symlink
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/cove" "$BIN_DIR/cove"
info "Linked $BIN_DIR/cove → $INSTALL_DIR/cove"

# 5. PATH check
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf '\n\033[1;33mwarning:\033[0m %s is not in your PATH.\n' "$BIN_DIR"
    printf 'Add this to your shell profile:\n\n  export PATH="%s:$PATH"\n\n' "$BIN_DIR"
    ;;
esac

# 6. Success
info "cove installed successfully. Run 'cove --help' to get started."
