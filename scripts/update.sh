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
chmod +x "$INSTALL_DIR/scripts/"*.py 2>/dev/null || true

echo "==> Updating Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"

# Deploy alerts timer if missing (added in v1.7.0)
if [[ ! -f /etc/systemd/system/syslog-alerts.timer ]]; then
    echo "==> Installing syslog-alerts timer (v1.7.0)..."
    cat > /etc/systemd/system/syslog-alerts.service << 'ALERT_SVC'
[Unit]
Description=Syslog alerts check (no-log threshold)

[Service]
Type=oneshot
ExecStart=/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/alert_check.py
User=root
StandardOutput=journal
SyslogIdentifier=syslog-alerts
ALERT_SVC
    cat > /etc/systemd/system/syslog-alerts.timer << 'ALERT_TIMER'
[Unit]
Description=Syslog alerts check timer

[Timer]
OnCalendar=*:0/10
Persistent=true

[Install]
WantedBy=timers.target
ALERT_TIMER
    systemctl daemon-reload
    systemctl enable --now syslog-alerts.timer
fi

echo "==> Restarting service..."
systemctl restart syslog-server

rm -rf "$TMP"
echo "==> Update complete."
