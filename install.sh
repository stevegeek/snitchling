#!/bin/sh
# Installs snitchling for the current user: binary, icon and menu entry.
# Autostart is separate (see README) so the stock UI isn't replaced by accident.
set -eu
cd "$(dirname "$0")"
cargo build --release
install -Dm755 target/release/snitchling "$HOME/.local/bin/snitchling"
install -Dm644 assets/snitchling.svg "$HOME/.local/share/icons/hicolor/scalable/apps/snitchling.svg"
install -Dm644 assets/snitchling.png "$HOME/.local/share/icons/hicolor/256x256/apps/snitchling.png"
install -Dm644 packaging/snitchling.desktop "$HOME/.local/share/applications/snitchling.desktop"
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$HOME/.local/share/icons/hicolor" || true
command -v kbuildsycoca6 >/dev/null && kbuildsycoca6 >/dev/null 2>&1 || true
echo "installed: ~/.local/bin/snitchling (+ icon and menu entry)"
