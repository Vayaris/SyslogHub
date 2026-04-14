#!/bin/bash
# SyslogHub update script — pulls latest version from GitHub and restarts the service
set -e

REPO="https://github.com/Vayaris/SyslogHub"
INSTALL_DIR="/opt/syslog-server"
TMP=$(mktemp -d)

echo "==> Cloning latest version from $REPO..."
git clone --depth=1 "$REPO" "$TMP/repo"

echo "==> Updating application files..."
for dir in app static templates scripts; do
    rsync -a --delete "$TMP/repo/$dir/" "$INSTALL_DIR/$dir/"
done

# Make scripts executable
chmod +x "$INSTALL_DIR/scripts/"*.sh 2>/dev/null || true

echo "==> Updating Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"

echo "==> Restarting service..."
systemctl restart syslog-server

rm -rf "$TMP"
echo "==> Update complete."
