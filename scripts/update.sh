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

# Refresh GeoIP DB (db-ip.com Country Lite). Monthly — skipped if <35 days old. (v1.9.0)
echo "==> Refreshing GeoIP DB (db-ip.com)..."
"$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/scripts/download_dbip.py" || \
    echo "    (GeoIP download failed — country enrichment disabled until next run)"

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

# v1.10.0 — widen the login rate-limit location to cover TOTP + OIDC.
# Previous `location /api/auth/login` (prefix match) missed /login/totp and
# /oidc/login; attackers could bypass the 5r/min cap there.
NGINX_CONF=/etc/nginx/sites-available/syslog-server.conf
if [[ -f "$NGINX_CONF" ]] && grep -qE '^\s*location /api/auth/login \{' "$NGINX_CONF"; then
    echo "==> Patching nginx login rate-limit to regex (v1.10.0)..."
    "$INSTALL_DIR/venv/bin/python3" - "$NGINX_CONF" <<'NGINX_LOGIN_PATCH'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text()
new_block = """    location ~ ^/api/auth/(login|login/totp|oidc/login)$ {
        limit_req zone=login_zone burst=3 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }"""
patched = re.sub(r"    location /api/auth/login \{[^}]*\}", new_block, src, count=1, flags=re.DOTALL)
if patched != src:
    p.write_text(patched)
NGINX_LOGIN_PATCH
    nginx -t && systemctl reload nginx
fi

# Patch nginx /api/logs/ block for SSE live tail (added in v1.8.0)
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

# v1.10.0 — Harden filesystem permissions on DB + backups. The DB contains
# the bcrypt admin hash and (as of v1.10.0) encrypted integration secrets —
# previously it shipped 0644 so any local user could read it.
echo "==> Hardening permissions on DB + backups..."
chmod 0600 /opt/syslog-server/data/syslog-server.db 2>/dev/null || true
if [[ -d /opt/syslog-server/data/backups ]]; then
    chmod 0700 /opt/syslog-server/data/backups
    chmod 0600 /opt/syslog-server/data/backups/*.db 2>/dev/null || true
    chmod 0600 /opt/syslog-server/data/backups/*.db.enc 2>/dev/null || true
fi

# v1.10.0 — Seed the Fernet master key if missing. The app also creates
# one on demand at startup, but doing it here means the fresh key is part
# of the next backup cycle.
SECRETS_KEY=/opt/syslog-server/config/secrets.key
if [[ ! -f "$SECRETS_KEY" ]]; then
    umask 0377
    /opt/syslog-server/venv/bin/python3 -c \
        "from cryptography.fernet import Fernet; import sys; sys.stdout.buffer.write(Fernet.generate_key() + b'\n')" \
        > "$SECRETS_KEY"
    chmod 400 "$SECRETS_KEY"
    echo "    (generated new Fernet master key)"
fi

# v2.0.0 — nouveaux timers systemd (chain, dhcp-sweep, omada-sync)
echo "==> Installation des timers v2.0.0 (chain + dhcp_sweep + omada_sync)..."

cat > /etc/systemd/system/syslog-chain.service << 'CHAIN_SVC'
[Unit]
Description=SyslogHub — build daily integrity chain + TSA timestamp

[Service]
Type=oneshot
ExecStart=/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/chain_daily.py
User=root
StandardOutput=journal
SyslogIdentifier=syslog-chain
CHAIN_SVC

cat > /etc/systemd/system/syslog-chain.timer << 'CHAIN_TMR'
[Unit]
Description=SyslogHub — daily integrity chain timer

[Timer]
OnCalendar=*-*-* 00:05:00
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
CHAIN_TMR

cat > /etc/systemd/system/syslog-dhcp-sweep.service << 'DHCP_SVC'
[Unit]
Description=SyslogHub — nightly DHCP lease parsing

[Service]
Type=oneshot
ExecStart=/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/dhcp_sweep.py
User=root
StandardOutput=journal
SyslogIdentifier=syslog-dhcp-sweep
DHCP_SVC

cat > /etc/systemd/system/syslog-dhcp-sweep.timer << 'DHCP_TMR'
[Unit]
Description=SyslogHub — DHCP sweep timer

[Timer]
OnCalendar=*-*-* 00:30:00
Persistent=true
RandomizedDelaySec=90

[Install]
WantedBy=timers.target
DHCP_TMR

cat > /etc/systemd/system/syslog-omada-sync.service << 'OMSYNC_SVC'
[Unit]
Description=SyslogHub — Omada hotspot session sync

[Service]
Type=oneshot
ExecStart=/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/omada_sync.py
User=root
StandardOutput=journal
SyslogIdentifier=syslog-omada-sync
OMSYNC_SVC

cat > /etc/systemd/system/syslog-omada-sync.timer << 'OMSYNC_TMR'
[Unit]
Description=SyslogHub — Omada sync timer (every 5 min)

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
OMSYNC_TMR

systemctl daemon-reload
systemctl enable --now syslog-chain.timer syslog-dhcp-sweep.timer syslog-omada-sync.timer

# v2.0.0 — CA FreeTSA pour la vérification des TSR. Idempotent.
if [[ ! -f /opt/syslog-server/config/tsa/freetsa-ca.pem ]]; then
    mkdir -p /opt/syslog-server/config/tsa
    echo "==> Téléchargement de la CA FreeTSA..."
    curl -sS --max-time 15 -o /tmp/freetsa-ca.pem https://freetsa.org/files/cacert.pem || \
        echo "    (download échoué — activer TSA plus tard dans /compliance/chain)"
    if head -1 /tmp/freetsa-ca.pem 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
        mv /tmp/freetsa-ca.pem /opt/syslog-server/config/tsa/freetsa-ca.pem
        chmod 0644 /opt/syslog-server/config/tsa/freetsa-ca.pem
    fi
fi

# v2.0.0 — dossier branding (logos par space) + dossier réquisitions
mkdir -p /opt/syslog-server/data/branding /opt/syslog-server/data/requisitions
chmod 0750 /opt/syslog-server/data/requisitions

# v1.9.3 + v1.10.0 — systemd memory caps + sandbox hardening drop-in.
# Reapplied on every update so edits to the template reach existing installs.
mkdir -p /etc/systemd/system/syslog-server.service.d
cat > /etc/systemd/system/syslog-server.service.d/resources.conf << 'RESOURCES'
# Managed by SyslogHub update.sh — safety belt (v1.9.3) + sandbox (v1.10.0).
[Service]
MemoryHigh=512M
MemoryMax=768M
TasksMax=256

CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_KILL CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
PrivateDevices=yes
SystemCallArchitectures=native
UMask=0077
RESOURCES
systemctl daemon-reload

echo "==> Restarting service..."
systemctl restart syslog-server

rm -rf "$TMP"
echo "==> Update complete."
