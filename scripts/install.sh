#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Syslog Server — Install Script
# OS cible : Debian / Ubuntu (LXC Proxmox)
# Usage    : bash install.sh
# Idempotent : oui (peut être relancé sans risque)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

APP_DIR="/opt/syslog-server"
LOG_DIR="/var/log/syslog-server"
SSL_DIR="/etc/ssl/syslog-server"
VENV="$APP_DIR/venv"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Syslog Server — Installation"
echo "════════════════════════════════════════════════════════"
echo ""

# ── ÉTAPE 1 : Vérifications préalables ────────────────────────────────────────
info "Étape 1/15 : Vérifications préalables"
[[ $EUID -ne 0 ]] && error "Ce script doit être exécuté en tant que root."

if ! grep -qiE "debian|ubuntu" /etc/os-release 2>/dev/null; then
  warn "OS non reconnu comme Debian/Ubuntu — poursuite tout de même."
fi

PYTHON=$(command -v python3 || true)
[[ -z "$PYTHON" ]] && error "Python 3 introuvable."
PY_VERSION=$($PYTHON --version 2>&1)
success "Python: $PY_VERSION"

# ── ÉTAPE 2 : Packages système ────────────────────────────────────────────────
info "Étape 2/15 : Installation des packages système"
apt-get update -qq
apt-get install -y -qq nginx python3-pip python3-venv rsyslog logrotate openssl 2>&1 | tail -3
success "Packages installés"

# ── ÉTAPE 3 : Arborescence ────────────────────────────────────────────────────
info "Étape 3/15 : Création de l'arborescence"
mkdir -p "$APP_DIR"/{app/{routers,services},static/{css,js,img},templates,data,config,logs,scripts}
mkdir -p "$LOG_DIR"
mkdir -p "$SSL_DIR"
touch "$APP_DIR/logs/app.log"
success "Arborescence créée"

# ── ÉTAPE 4 : Virtualenv Python ───────────────────────────────────────────────
info "Étape 4/15 : Création du virtualenv Python"
if [[ ! -f "$VENV/bin/python3" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -q \
  "fastapi==0.115.12" \
  "uvicorn[standard]==0.34.2" \
  "sqlalchemy==2.0.40" \
  "jinja2==3.1.6" \
  "itsdangerous==2.2.0" \
  "bcrypt==4.3.0" \
  "python-multipart==0.0.20" \
  "aiofiles==24.1.0" \
  "python-dotenv==1.1.0"
success "Virtualenv prêt"

# ── ÉTAPE 5 : config/app.env ─────────────────────────────────────────────────
info "Étape 5/15 : Génération de la configuration"
ENV_FILE="$APP_DIR/config/app.env"
if [[ ! -f "$ENV_FILE" ]]; then
  SECRET_KEY=$("$VENV/bin/python3" -c "import secrets; print(secrets.token_hex(32))")
  cat > "$ENV_FILE" << EOF
LOG_ROOT=/var/log/syslog-server
DB_PATH=/opt/syslog-server/data/syslog-server.db
SECRET_KEY=${SECRET_KEY}
SESSION_MAX_AGE=86400
BIND_HOST=127.0.0.1
BIND_PORT=8000
EOF
  chmod 600 "$ENV_FILE"
  success "app.env généré"
else
  success "app.env existant conservé"
fi

# ── ÉTAPE 6 : Initialisation base SQLite ─────────────────────────────────────
info "Étape 6/15 : Initialisation de la base de données"
cd "$APP_DIR"
"$VENV/bin/python3" -c "
import sys
sys.path.insert(0, '$APP_DIR')
from app.database import init_db
init_db()
print('Base initialisée.')
"
success "Base SQLite prête"

# ── ÉTAPE 7 : Permissions répertoire logs ────────────────────────────────────
info "Étape 7/15 : Permissions"
chown -R syslog:adm "$LOG_DIR" 2>/dev/null || chown -R root:root "$LOG_DIR"
chmod 755 "$LOG_DIR"
chown -R root:root "$APP_DIR"
chmod 750 "$APP_DIR/data"
[[ -f "$APP_DIR/data/syslog-server.db" ]] && chmod 640 "$APP_DIR/data/syslog-server.db"
chmod 600 "$ENV_FILE"
success "Permissions appliquées"

# ── ÉTAPE 8 : Certificat TLS auto-signé ──────────────────────────────────────
info "Étape 8/15 : Génération du certificat TLS"
if [[ ! -f "$SSL_DIR/server.crt" ]]; then
  MACHINE_IP=$(hostname -I | awk '{print $1}')
  cat > /tmp/syslog-server-openssl.cnf << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C=FR
ST=Local
L=Local
O=SyslogServer
CN=syslog-server

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = syslog-server
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ${MACHINE_IP}
EOF
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$SSL_DIR/server.key" \
    -out "$SSL_DIR/server.crt" \
    -config /tmp/syslog-server-openssl.cnf 2>/dev/null
  chmod 600 "$SSL_DIR/server.key"
  rm -f /tmp/syslog-server-openssl.cnf
  success "Certificat auto-signé généré (10 ans, SAN: localhost, $MACHINE_IP)"
else
  success "Certificat existant conservé"
fi

# ── ÉTAPE 9 : Configuration nginx ─────────────────────────────────────────────
info "Étape 9/15 : Configuration nginx"
cat > /etc/nginx/sites-available/syslog-server.conf << 'NGINX'
# Syslog Server — nginx HTTPS reverse proxy

limit_req_zone $binary_remote_addr zone=login_zone:10m rate=5r/m;

server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    ssl_certificate     /etc/ssl/syslog-server/server.crt;
    ssl_certificate_key /etc/ssl/syslog-server/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    server_tokens off;
    client_max_body_size 1m;

    # Static files served directly par nginx
    location /static/ {
        alias /opt/syslog-server/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Rate-limiting sur le login
    location /api/auth/login {
        limit_req zone=login_zone burst=3 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Streaming (téléchargement + SSE live tail)
    location /api/logs/ {
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
    }

    # Toutes les autres requêtes
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINX

# Désactiver la config default
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/syslog-server.conf /etc/nginx/sites-enabled/

nginx -t 2>&1 | grep -v "^$"
systemctl enable nginx --quiet
systemctl restart nginx
success "nginx configuré et démarré"

# ── ÉTAPE 10 : Config rsyslog initiale ────────────────────────────────────────
info "Étape 10/15 : Configuration rsyslog initiale"
mkdir -p /var/log/syslog-server/514
chown syslog:adm /var/log/syslog-server/514 2>/dev/null || true

cat > /etc/rsyslog.d/99-syslog-server.conf << 'RSYSLOG'
# AUTO-GENERATED by syslog-server — DO NOT EDIT MANUALLY
# Ce fichier est regénéré automatiquement à chaque changement d'espace.

module(load="imudp")

template(name="tpl_514" type="list") {
    constant(value="/var/log/syslog-server/514/")
    property(name="fromhost-ip")
    constant(value=".log")
}
ruleset(name="rs_514") {
    action(
        type="omfile"
        dynaFile="tpl_514"
        dirCreateMode="0755"
        fileCreateMode="0640"
        fileOwner="syslog"
        fileGroup="adm"
    )
}
input(type="imudp" port="514" ruleset="rs_514")
RSYSLOG

rsyslogd -N1 -f /etc/rsyslog.d/99-syslog-server.conf 2>&1 | grep -v "^$" | head -5
systemctl restart rsyslog
success "rsyslog configuré (port 514 actif)"

# ── ÉTAPE 11 : Logrotate ──────────────────────────────────────────────────────
info "Étape 11/15 : Configuration logrotate"
cat > /etc/logrotate.d/syslog-server << 'LOGROTATE'
/var/log/syslog-server/*/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service 2>/dev/null || true
    endscript
}

/opt/syslog-server/logs/app.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
LOGROTATE
success "logrotate configuré"

# ── ÉTAPE 12 : Service systemd ────────────────────────────────────────────────
info "Étape 12/15 : Service systemd"
cat > /etc/systemd/system/syslog-server.service << 'SYSTEMD'
[Unit]
Description=Syslog Server Web Interface (FastAPI/Uvicorn)
After=network.target rsyslog.service
Wants=rsyslog.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/syslog-server
EnvironmentFile=/opt/syslog-server/config/app.env

ExecStart=/opt/syslog-server/venv/bin/uvicorn \
    app.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --no-access-log \
    --log-level warning

Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full

StandardOutput=journal
StandardError=journal
SyslogIdentifier=syslog-server

[Install]
WantedBy=multi-user.target
SYSTEMD

# Timer de rétention
cat > /etc/systemd/system/syslog-retention.service << 'RET_SVC'
[Unit]
Description=Syslog log retention cleanup

[Service]
Type=oneshot
ExecStart=/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/retention_cleanup.py
User=root
StandardOutput=journal
SyslogIdentifier=syslog-retention
RET_SVC

cat > /etc/systemd/system/syslog-retention.timer << 'RET_TIMER'
[Unit]
Description=Syslog retention cleanup timer

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
RET_TIMER

# Timer alertes no-log
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
systemctl enable syslog-server --quiet
systemctl enable syslog-retention.timer --quiet
systemctl enable syslog-alerts.timer --quiet
systemctl start syslog-server
systemctl start syslog-alerts.timer
success "Service systemd démarré"

# ── ÉTAPE 13 : Permissions finales ────────────────────────────────────────────
info "Étape 13/15 : Permissions finales"
chown -R root:root "$APP_DIR"
chmod 750 "$APP_DIR/data"
[[ -f "$APP_DIR/data/syslog-server.db" ]] && chmod 640 "$APP_DIR/data/syslog-server.db"
chmod 600 "$ENV_FILE"
chmod +x "$APP_DIR/scripts/install.sh"
chmod +x "$APP_DIR/scripts/retention_cleanup.py"
success "Permissions appliquées"

# ── ÉTAPE 14 : Health check ───────────────────────────────────────────────────
info "Étape 14/15 : Health check"
sleep 3

SYSLOG_OK=$(systemctl is-active syslog-server 2>/dev/null || echo "failed")
RSYSLOG_OK=$(systemctl is-active rsyslog 2>/dev/null || echo "failed")
NGINX_OK=$(systemctl is-active nginx 2>/dev/null || echo "failed")

[[ "$SYSLOG_OK"  == "active" ]] && success "syslog-server : actif"  || warn "syslog-server : $SYSLOG_OK"
[[ "$RSYSLOG_OK" == "active" ]] && success "rsyslog       : actif"  || warn "rsyslog       : $RSYSLOG_OK"
[[ "$NGINX_OK"   == "active" ]] && success "nginx         : actif"  || warn "nginx         : $NGINX_OK"

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost/ 2>/dev/null || echo "000")
[[ "$HTTP_CODE" =~ ^(200|302|301)$ ]] \
  && success "Interface web accessible (HTTP $HTTP_CODE)" \
  || warn "Interface web — code HTTP: $HTTP_CODE (vérifiez: journalctl -u syslog-server -n 30)"

# ── ÉTAPE 15 : Résumé ─────────────────────────────────────────────────────────
MACHINE_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Installation terminée !${NC}"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  URL         : https://${MACHINE_IP}/"
echo "  Utilisateur : admin"
echo -e "  Mot de passe: ${YELLOW}changeme${NC}  ← Changez-le immédiatement !"
echo ""
echo "  Logs app    : journalctl -u syslog-server -f"
echo "  Logs syslog : /var/log/syslog-server/514/<ip>.log"
echo ""
echo "  Test réception syslog :"
echo "    echo '<14>Test' | nc -u -w1 ${MACHINE_IP} 514"
echo "    logger -n ${MACHINE_IP} -P 514 -d 'Test message'"
echo ""
echo "════════════════════════════════════════════════════════"
