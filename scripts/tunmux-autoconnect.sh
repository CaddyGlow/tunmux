#!/bin/bash
set -euo pipefail

BIN=/usr/local/bin/tunmux
PROFILE="$HOME/private/.wireguard/andi_split.conf"

# Already up? nothing to do. (status always exits 0, so match on output.)
if "$BIN" wgconf status 2>/dev/null | grep -q '^Connected:'; then
    exit 0
fi

exec "$BIN" --debug wgconf connect --file "$PROFILE"
