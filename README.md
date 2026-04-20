# SyslogHub

Serveur SYSLOG centralisé avec interface web HTTPS — simple à déployer, facile à maintenir.

## Fonctionnalités

- Réception des logs syslog UDP (et TCP) sur plusieurs ports configurables
- Organisation par **espaces** (port + nom personnalisé, allowlist IP)
- Séparation automatique des logs par adresse IP source
- Interface web HTTPS moderne (dashboard, visualiseur, téléchargement ZIP, charts)
- Recherche texte dans les logs
- Configuration dynamique sans redémarrage manuel
- Rétention et rotation automatiques + backup quotidien de la base
- Authentification par login/mot de passe (rotation de session à chaque changement de MDP)
- **Intégration TP-Link Omada SDN par espace** (Northbound OpenAPI, supporte mode MSP multi-clients) : chaque espace peut pointer sur un contrôleur distinct pour enrichir les logs avec noms et modèles des équipements (bornes WiFi, switches, gateways)
- **Mode LAN** (par espace) : consolide toutes les sources dans un fichier `_all.log` supplémentaire et une vue combinée, tout en gardant la séparation par IP

## Stack

| Composant | Rôle |
|-----------|------|
| **rsyslog** | Réception UDP multi-ports |
| **FastAPI + Uvicorn** | API REST + interface web |
| **SQLite** | Stockage configuration |
| **Nginx** | Reverse proxy HTTPS |

## Prérequis

- Debian 11/12 ou Ubuntu 22.04/24.04
- Root ou sudo
- Ports 80, 443, 514 (UDP) accessibles

---

## Installation

### Méthode rapide (curl)

```bash
curl -fsSL https://raw.githubusercontent.com/Vayaris/SyslogHub/main/scripts/install.sh | bash
```

### Méthode manuelle

```bash
git clone https://github.com/Vayaris/SyslogHub.git
cd SyslogHub
bash scripts/install.sh
```

L'installeur effectue automatiquement :
1. Installation des dépendances système (nginx, python3, rsyslog, openssl…)
2. Création du virtualenv Python et installation des packages
3. Génération d'un certificat TLS auto-signé (10 ans)
4. Configuration nginx HTTPS avec rate-limiting sur le login
5. Configuration rsyslog (port 514 par défaut)
6. Initialisation de la base SQLite
7. Démarrage et activation des services systemd

**Durée estimée : 2–3 minutes**

### Après installation

Accéder à l'interface : `https://<IP_DU_SERVEUR>/`

| Identifiant | Valeur par défaut |
|-------------|-------------------|
| Utilisateur | `admin` |
| Mot de passe | `changeme` |

> **Changer le mot de passe immédiatement** dans **Paramètres → Sécurité**.
> Après validation, toutes les sessions en cours sont automatiquement invalidées et l'utilisateur est reconnecté.

### Mot de passe oublié ?

Si vous vous retrouvez verrouillé dehors, un script de secours remet les identifiants par défaut (`admin` / `changeme`) et invalide toutes les sessions :

```bash
sudo /opt/syslog-server/venv/bin/python /opt/syslog-server/scripts/reset_password.py
```

---

## Intégration Omada SDN (optionnelle, par espace)

Chaque espace SyslogHub peut être relié à un contrôleur **TP-Link Omada SDN** distinct via sa **Northbound OpenAPI**. Le mode (standalone ou MSP multi-clients), la liste des sites et des clients (si MSP) sont **découverts automatiquement** — rien d'autre à indiquer. Une fois configuré, les vues de logs enrichissent les équipements connus (bornes WiFi, switches, gateways) avec leur nom, leur modèle et leur statut.

### Pré-requis contrôleur

Dans votre contrôleur Omada, aller dans **Paramètres → OpenAPI** et créer une application de type **Client Credentials**. Noter :
- **Interface Access Address** (ex : `https://172.16.0.31:8043`)
- **Omada ID** (visible sur la page d'accueil du contrôleur)
- **Client ID** et **Client Secret** générés

### Configuration dans SyslogHub

Dans **Espaces → Modifier** (ou **Nouvel espace**), remplir la section **Intégration Omada** avec les 4 champs ci-dessus, enregistrer, puis cliquer sur **Tester la connexion**. Le message de succès indique le mode détecté (MSP ou standard), le nombre de sites/clients et la répartition des équipements par type. Répéter l'opération pour chaque espace à connecter à un contrôleur différent.

---

## Mode LAN (fichier combiné)

Quand un contrôleur envoie ses logs **en local** (LAN), chaque borne/switch apparaît avec son IP propre — l'UI sépare donc en de nombreux fichiers. Quand il passe par du **port-forwarding WAN**, tout arrive depuis une seule IP. Pour conserver les deux usages, activer le **Mode LAN** sur l'espace ajoute un fichier unifié `_all.log` qui consolide toutes les sources dans l'ordre d'arrivée (comportement syslog classique) sans supprimer les fichiers par-IP.

Dans le formulaire de l'espace, cocher **Contrôleur en LAN**. Un bouton **Vue combinée (toutes sources)** apparaît alors sur la page des logs de l'espace et donne accès au flux unifié, avec les mêmes contrôles (tail, filtre, auto-refresh) que le viewer par-IP.

---

## Configuration

### Ajouter un espace syslog

Dans l'interface web : **Espaces → Nouvel espace**

- Choisir un port UDP (ex: `30514`)
- Donner un nom (ex: `Firewall`)
- La config rsyslog est mise à jour automatiquement

### Configurer vos équipements

Pointer les équipements réseau (firewall, switch, serveurs) vers l'IP du serveur :

```
# Cisco IOS
logging host <IP_SERVEUR> transport udp port 514

# Fortinet
config log syslogd setting
  set status enable
  set server <IP_SERVEUR>
  set port 514
end

# Linux (rsyslog)
*.* @<IP_SERVEUR>:514

# Linux (syslog-ng)
destination d_remote { udp("<IP_SERVEUR>" port(514)); };
```

### Test de réception

```bash
# netcat
echo "<14>Test message" | nc -u -w1 <IP_SERVEUR> 514

# logger
logger -n <IP_SERVEUR> -P 514 -d "Test depuis $(hostname)"
```

---

## Structure des logs

```
/var/log/syslog-server/
├── 514/                    # Espace "Default" (port 514)
│   ├── 192.168.1.1.log     # Un fichier par IP source
│   └── 10.0.0.5.log
└── 30514/                  # Espace "Firewall" (port 30514, Mode LAN activé)
    ├── 192.168.1.254.log
    ├── 192.168.1.255.log
    └── _all.log            # Vue unifiée (Mode LAN uniquement)
```

---

## Gestion des services

```bash
# État
systemctl status syslog-server rsyslog nginx

# Logs de l'application
journalctl -u syslog-server -f

# Redémarrage
systemctl restart syslog-server

# Rétention manuelle (supprime les fichiers > retention_days)
/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/retention_cleanup.py

# Backup quotidien de la base
/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/backup_db.py

# Reset d'urgence des identifiants admin (admin / changeme)
/opt/syslog-server/venv/bin/python3 /opt/syslog-server/scripts/reset_password.py
```

---

## Mise à jour

Pour récupérer la dernière version depuis GitHub et redémarrer le service :

```bash
sudo bash /opt/syslog-server/scripts/update.sh
```

Le script :
1. Clone la dernière version du dépôt dans un dossier temporaire
2. Synchronise les dossiers `app/`, `static/`, `templates/` et `scripts/` (rsync avec `--delete`)
3. Met à jour les dépendances Python (`pip install -r requirements.txt`)
4. Redémarre `syslog-server` (la migration SQLite additive s'exécute au démarrage)

**Préservé** : la base SQLite (`data/syslog-server.db`), la configuration nginx, les certificats TLS, les logs reçus (`/var/log/syslog-server/`) et le virtualenv.

> Une sauvegarde automatique de la base est créée chaque nuit dans `data/backups/`. En cas de problème après une mise à jour, restaurer le dernier backup via `cp data/backups/syslog-server_YYYYMMDD_HHMMSS.db data/syslog-server.db` puis `systemctl restart syslog-server`.

---

## Désinstallation

```bash
bash /opt/syslog-server/scripts/uninstall.sh
```

Le script propose de conserver ou supprimer les fichiers de logs reçus.

---

## Sécurité

- HTTPS obligatoire (redirection automatique HTTP → HTTPS)
- Certificat auto-signé (remplaçable par un vrai certificat dans `/etc/ssl/syslog-server/`)
- Rate-limiting sur le login (5 req/min par IP)
- Cookie de session HttpOnly, Secure, SameSite=Strict
- Protection path traversal sur le visualiseur de logs
- Headers de sécurité nginx (HSTS, X-Frame-Options, CSP)

### Remplacer le certificat auto-signé

```bash
# Copier votre certificat
cp votre_cert.pem /etc/ssl/syslog-server/server.crt
cp votre_key.pem  /etc/ssl/syslog-server/server.key
chmod 600 /etc/ssl/syslog-server/server.key
systemctl reload nginx
```

---

## License

MIT
