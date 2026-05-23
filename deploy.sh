#!/usr/bin/env bash
# Build, package, and deploy wirepf to a Debian server over SSH.
#
# Usage:
#   ./deploy.sh user@host           # ssh target
#   WIREPF_HOST=user@host ./deploy.sh
set -euo pipefail

HOST="${1:-${WIREPF_HOST:-}}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 <user@host>   (or set WIREPF_HOST)" >&2
    exit 2
fi

TARGET="x86_64-unknown-linux-musl"
PKG="wirepf-daemon"

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "==> Building release binary ($TARGET)"
cargo build -p "$PKG" --release --target "$TARGET"

echo "==> Packaging .deb"
cargo deb -p "$PKG" --no-build --target "$TARGET"

DEB=$(ls -t "target/$TARGET/debian/"wirepf_*.deb | head -1)
echo "==> Built: $DEB"

REMOTE="/tmp/$(basename "$DEB")"
echo "==> Uploading to $HOST:$REMOTE"
scp "$DEB" "$HOST:$REMOTE"

echo "==> Installing on $HOST"
ssh -t "$HOST" "sudo apt-get install -y --reinstall $REMOTE && rm -f $REMOTE && sudo systemctl status wirepf --no-pager -l"

cat <<EOF

==> Done.

Next steps on $HOST:
  sudo nano /etc/wirepf/config.json    # set auth_token
  sudo systemctl restart wirepf
  sudo journalctl -u wirepf -f         # tail logs

API:
  curl -s http://<host>:1204/health
  curl -s -H "Authorization: Bearer <token>" http://<host>:1204/interfaces
EOF
