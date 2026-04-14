#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SyslogHub — Uninstall Script
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[ERR]${NC}  Exécuter en tant que root."; exit 1; }

echo ""
echo "════════════════════════════════════════════════════════"
echo "  SyslogHub — Désinstallation"
echo "════════════════════════════════════════════════════════"
echo ""

# Confirmation
read -rp "Supprimer SyslogHub et ses données ? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[yY]$ ]] || { echo "Annulé."; exit 0; }

read -rp "Supprimer également les fichiers de logs reçus ? [y/N] " DEL_LOGS

# Arrêt et désactivation des services
info "Arrêt des services"
systemctl stop syslog-server 2>/dev/null && success "syslog-server arrêté" || warn "syslog-server n'était pas actif"
systemctl disable syslog-server 2>/dev/null || true
systemctl stop syslog-retention.timer 2>/dev/null || true
systemctl disable syslog-retention.timer 2>/dev/null || true

# Suppression des unités systemd
rm -f /etc/systemd/system/syslog-server.service
rm -f /etc/systemd/system/syslog-retention.service
rm -f /etc/systemd/system/syslog-retention.timer
systemctl daemon-reload
success "Unités systemd supprimées"

# Suppression de la config nginx
rm -f /etc/nginx/sites-enabled/syslog-server.conf
rm -f /etc/nginx/sites-available/syslog-server.conf
# Réactiver la config par défaut si elle existait
[[ -f /etc/nginx/sites-available/default ]] && \
  ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true
systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
success "Configuration nginx supprimée"

# Suppression de la config rsyslog
rm -f /etc/rsyslog.d/99-syslog-server.conf
rm -f /etc/rsyslog.d/99-syslog-server.conf.bak
systemctl restart rsyslog 2>/dev/null || true
success "Configuration rsyslog supprimée"

# Suppression de logrotate
rm -f /etc/logrotate.d/syslog-server
success "Configuration logrotate supprimée"

# Suppression du certificat TLS
rm -rf /etc/ssl/syslog-server
success "Certificat TLS supprimé"

# Suppression de l'application
rm -rf /opt/syslog-server
success "Application supprimée (/opt/syslog-server)"

# Suppression des logs reçus
if [[ "$DEL_LOGS" =~ ^[yY]$ ]]; then
  rm -rf /var/log/syslog-server
  success "Logs syslog supprimés (/var/log/syslog-server)"
else
  warn "Logs conservés dans /var/log/syslog-server"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Désinstallation terminée.${NC}"
echo "════════════════════════════════════════════════════════"
echo ""
