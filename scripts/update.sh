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

# Patch nginx /api/logs/ block for SSE live tail (added in v1.8.0)
NGINX_CONF=/etc/nginx/sites-available/syslog-server.conf
if [[ -f "$NGINX_CONF" ]] && ! grep -q "proxy_read_timeout 960s" "$NGINX_CONF"; then
    echo "==> Patching nginx /api/logs/ for SSE live tail (v1.8.0)..."
    "$INSTALL_DIR/venv/bin/python3" - "$NGINX_CONF" <<'NGINX_PATCH'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text()
new_block = """    location /api/logs/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        # SSE /stream endpoints close server-side after 900s idle; allow a bit more here.
        proxy_read_timeout 960s;
        proxy_send_timeout 960s;
    }"""
patched = re.sub(r"location /api/logs/ \{[^}]*\}", new_block, src, count=1, flags=re.DOTALL)
if patched != src:
    p.write_text(patched)
NGINX_PATCH
    nginx -t && systemctl reload nginx
fi

echo "==> Restarting service..."
systemctl restart syslog-server

rm -rf "$TMP"
echo "==> Update complete."
