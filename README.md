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
- **Intégration TP-Link Omada SDN par espace** (Northbound OpenAPI, supporte mode MSP multi-clients) : chaque espace peut pointer sur un contrôleur distinct. Les équipements (bornes WiFi, switches, gateways) sont enrichis dans les logs **et dans le tableau des sources** avec leur nom et leur modèle (rapprochement par IP, fallback AP MAC extraite des logs).
- **Mode LAN** (par espace) : consolide toutes les sources dans un fichier `_all.log` supplémentaire et une vue combinée, tout en gardant la séparation par IP
- **Téléchargement par plage de dates** : sur une source, choisir un intervalle et récupérer un seul `.log` concaténant toutes les archives (`.log.N.gz` décompressés à la volée)
- **Live tail (SSE)** : bouton *Live* dans le visualiseur — nouvelles lignes poussées en temps réel via Server-Sent Events, comme un `tail -f` dans le navigateur. Disponible sur les vues par-IP et sur la vue combinée (Mode LAN).
- **Bouton "Envoyer un log test"** : sur la page des sources d'un espace, envoie un syslog UDP depuis `127.0.0.1` avec un message personnalisable, pour vérifier que la réception est active et que la chaîne rsyslog → fichier fonctionne. Refuse l'envoi avec un message clair si l'espace a une allowlist incompatible.
- **Alertes "no-logs"** : notification email (SMTP Gmail / App Password) + webhook si un espace ne reçoit plus de logs depuis *X* heures (défaut 24h). Une alerte au passage DOWN, une alerte de retour (RECOVERY). Seuil, destinataire et webhook configurables par espace.

## Nouveautés v2.0.0 — Conformité LCEN/RGPD pour WiFi public

Release majeure. SyslogHub devient une solution clé en main pour les opérateurs soumis à la **conservation légale des données de connexion** (hôtels, bars, franchises, lieux publics) — alternative open-source aux appliances commerciales type Ucopia.

### Intégrité cryptographique des logs
- **Chaîne de hash SHA-256 journalière** par espace : chaque jour, un manifest JSON liste les fichiers de logs avec leur SHA-256 et pointe vers le manifest du jour précédent (`prev_sha256`). Modifier un seul byte casse la chaîne et est détectable.
- **Horodatage qualifié RFC 3161** : chaque manifest est soumis à une **Time-Stamp Authority** (défaut : FreeTSA, gratuit & public) qui retourne un token signé `.tsr` reconnu comme preuve légale. Valeur probante devant un tribunal.
- **Timer `syslog-chain.timer`** à 00:05 UTC. Script `verify_chain.py` pour audit indépendant.
- **Backfill rétroactif** au premier boot v2 (manifests construits pour les logs existants, sans TSA — marqué `skipped_backfill`).

### Workflow réquisition judiciaire
- Bouton **« Nouvelle réquisition »** dans `/compliance/requisitions` : formulaire (n°, OPJ, justification, espace, plage temporelle).
- **Bundle ZIP signé** généré automatiquement : logs bruts + manifests + `.tsr` + CSV corrélation + **PV.pdf** pré-rempli + `MANIFEST.json` + `README.txt` + `verify.sh` (vérification portable : bash + sha256sum + openssl).
- **Legal hold automatique** activé dès l'export : les logs couverts ne peuvent plus être purgés tant que la réquisition n'est pas clôturée.
- **SHA-256 du bundle** stocké en DB + commentaire ZIP + `signatures/bundle.sha256` interne.
- Audit trail complet : `requisition_create`, `requisition_export`, `requisition_download`, `requisition_close`.

### Gestion multi-utilisateurs + RBAC par espace
- Nouvelle table `users` : plusieurs comptes admin ou opérateur. Migration transparente de l'admin legacy.
- **Rôles par espace** (`owner` / `operator` / `readonly`) : un opérateur ne voit que les espaces auxquels il a explicitement accès. Admin global voit tout.
- Page `/users` pour la gestion (admin only).
- OIDC : utilisateur créé automatiquement au premier login SSO avec `role_global='operator'`.

### Rétention légale intelligente
- **Par espace** (plus de réglage global unique) : preset 180j / 365j (LCEN) / 1095j / personnalisé, avec avertissement RGPD art. 5-1-e.
- **Legal hold** : `scripts/retention_cleanup.py` refuse de supprimer les fichiers couverts par un hold actif. Audit log dédié (`retention_skip_hold`).
- Purge automatique quotidienne via le timer `syslog-retention.timer` existant.

### Corrélation identité ↔ IP ↔ temps
- **Parser DHCP** (`services/dhcp_parser.py`) : détecte les `DHCPACK` depuis les logs syslog entrants (ISC dhcpd, dnsmasq, Mikrotik RouterOS, pfSense, Cisco IOS, OpenWRT).
- **Sync Omada hotspot** (`services/omada_sync.py`) : pull toutes les 5 minutes des sessions clients (MAC, IP, identifiant email/SMS, AP, SSID, plage temporelle).
- **Endpoint `/api/correlation/who-was-on`** + page `/compliance/correlation` : « À 2026-04-23 14:35 UTC, IP 192.168.1.42 était attribuée à aa:bb:cc:dd:ee:ff, session hotspot ouverte par jean@example.com via AP Bar-AP-01 ».
- Flags `dhcp_parse_enabled` et `omada_sync_enabled` par espace.

### Conformité RGPD documentée
- **Registre de traitement art. 30 RGPD** : `GET /api/compliance/docs/register.pdf` — pré-rempli avec organisation, DPO, traitements par espace.
- **Mention d'information captive portal** : `GET /api/compliance/docs/notice/<space_id>.{pdf,md}` — document prêt à afficher ou intégrer.
- **Rapport annuel de conformité** : `GET /api/compliance/docs/annual-report.pdf?year=YYYY` — uptime, gaps, réquisitions, taux TSA.
- Page `/compliance/documents` (admin) pour configuration organisation + DPO et téléchargement.

### Alertes conformité
- Nouveaux déclencheurs dans `scripts/alert_check.py` : **chain_gap** (logs sans manifest), **tsa_failure** (manifests en échec après 3 tentatives), **legal_hold_long** (réquisition exportée depuis >90 jours sans clôture).
- Intégrés au timer existant `syslog-alerts.timer` (toutes les 10 min).

### Franchise / multi-établissement
- **Branding par espace** : upload logo (PNG/JPEG/GIF, max 256 KB, validation magic bytes) + couleur hex. Servi via `/branding/<space_id>.ext`.

### Migration v1.x → v2.0.0
- `update.sh` applique tout automatiquement : nouveaux timers, CA FreeTSA, nouvelles colonnes DB (idempotent `ALTER TABLE`), nouvelle table `users`.
- **TSA opt-in sur upgrade** (désactivée par défaut, l'admin active explicitement dans `/compliance/chain`).
- **Backfill chaîne en background** au 1er boot v2 : peut prendre plusieurs minutes sur une install chargée, non bloquant.
- Settings legacy `admin_*` conservés comme fallback — purgés en v2.2 après ramp-up.

### Hors scope v2.0.0 (roadmap v2.1)
- Service non-root (sysloghub user + sudoers restreint pour `systemctl restart rsyslog`)
- SQLCipher (alternative à Fernet field-level)
- WebAuthn en complément de TOTP
- Binding session IP/UA
- Upload SVG avec sanitizer strict
- Search full-text + parsing RFC5424 structuré

---

## Nouveautés v1.10.0 — Hardening sécurité

- **Mot de passe par défaut `changeme` bloqué** : tant qu'il n'est pas remplacé, toute requête authentifiée (sauf `/settings` et les endpoints nécessaires au changement) renvoie 403 `password_change_required` ou redirige vers `/settings?force_password=1`. Bannière rouge explicite dans Paramètres. Le flag est clearé automatiquement au premier changement.
- **Brute-force mitigé côté application** : lockout progressif *par username* (indépendant de l'IP) — 5 échecs en 15 min → 1 min, 10 en 1 h → 15 min, 20 en 24 h → 60 min. Un succès efface l'ardoise. Couvre `/api/auth/login`, `/api/auth/login/totp`. Nginx regex étendue à `login/totp` et `oidc/login` (auparavant seul `/login` exact était limité).
- **Anti-replay TOTP** : stockage du dernier counter consommé (`admin_totp_last_counter`), un même code 6-chiffres ne peut plus être rejoué dans sa fenêtre de 90 s. L'audit log distingue `replay` de `bad_code`.
- **OIDC `email_verified` exigé par défaut** : refus des utilisateurs dont l'IdP n'atteste pas la vérification de l'email (évite l'usurpation via un IdP laxiste). Toggle *Exiger `email_verified`* dans la carte OIDC pour les IdPs qui n'émettent pas ce claim.
- **Anti-SSRF** : nouvel `app/services/url_guard.py` qui valide les URLs Omada et OIDC avant toute requête sortante. Refuse les schemes exotiques (`file://`, `gopher://`), les IPs `169.254.169.254` / AWS-metadata / loopback / link-local / multicast / reserved. OIDC exige HTTPS + IP publique ; Omada accepte HTTP + IP privée (cas normal du contrôleur LAN).
- **Chiffrement des secrets en DB (Fernet)** : `smtp_password`, `oidc_client_secret`, et chaque `spaces.omada_client_secret` sont chiffrés au repos avec `cryptography.fernet`. Master key hors DB dans `/opt/syslog-server/config/secrets.key` (mode `0400 root:root`, auto-générée). Migration transparente au démarrage (rows legacy plaintext ré-encryptées automatiquement).
- **Backups chiffrés** : `scripts/backup_db.py` produit désormais des fichiers `.db.enc` chiffrés avec la même master key. Les anciennes copies `.db` en clair sont supprimées. Restauration via `scripts/restore_backup.py <file.db.enc>`.
- **Permissions filesystem durcies** : DB SQLite passe de `0644` à `0600 root:root`, répertoire de backups de `0755` à `0700`, chaque backup `0600`. `os.umask(0o077)` systématique dans le script de backup. `update.sh` migre les installations existantes automatiquement.
- **Sandbox systemd** : drop-in `resources.conf` étendu avec `CapabilityBoundingSet`, `RestrictAddressFamilies`, `ProtectHostname`, `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`, `LockPersonality`, `RestrictRealtime`, `RestrictNamespaces`, `RestrictSUIDSGID`, `PrivateDevices`, `SystemCallArchitectures=native`, `UMask=0077`. Score `systemd-analyze security` passe de **8.9 EXPOSED** à **4.4 OK**.

## Nouveautés v1.9.0

- **Audit log interne** : toutes les actions sensibles (login/logout, échecs, changement de mot de passe, CRUD espace, suppression de source, modifications de config, activation 2FA, login OIDC, révocation de session) sont tracées avec utilisateur, IP, user-agent et horodatage UTC. Consultable dans **Paramètres → Audit** avec filtres (action, utilisateur, période) et pagination. Rétention automatique de 180 jours.
- **Sessions actives + révocation** : la table des sessions en cours est consultable dans **Paramètres → Sessions actives** (IP, user-agent, date de création, dernière activité). Chaque session peut être révoquée individuellement (y compris la session courante, avec déconnexion immédiate) ou en bloc via *Révoquer toutes les autres*. Les sessions révoquées ou expirées sont purgées au démarrage.
- **SSO / OIDC** (Authentik, Keycloak, Google Workspace, etc.) : authentification via IdP externe avec découverte automatique (`.well-known/openid-configuration`), PKCE + state géré par Authlib. Une **allowlist** d'emails et de domaines glob (ex. `tristan@example.com, *@moncompany.com`) filtre l'accès — allowlist vide = tout le monde est refusé. Configuration complète dans **Paramètres → Authentification SSO**, bouton *Se connecter via SSO* sur la page de login (affiché automatiquement si OIDC activé).
- **TOTP 2FA sur le login local** : activation volontaire dans **Paramètres → Authentification à deux facteurs**. Flow d'enrôlement par QR code (pyotp + SVG inline), vérification à 6 chiffres puis activation. Au login, si 2FA activé, le mot de passe déclenche un `tx_id` signé court-TTL (2 min) et un deuxième écran demande le code. Désactivation re-authentifiée par le mot de passe admin.
- **GeoIP (pays) + rDNS** sur les IPs sources **en mode WAN uniquement** : enrichissement de la ligne source avec le code ISO 3166 (ex. `FR`, `US`) et le nom rDNS. Base db-ip.com Country Lite (gratuite, rafraîchissement mensuel par `install.sh` / `update.sh`). Les IPs privées, loopback, link-local, etc. sont court-circuitées. Cache rDNS 1h, timeout 0,5s, max 20 lookups par requête.
- **Alias "Contrôleur Omada"** : nouveau champ optionnel *IP locale du contrôleur* dans la config Omada d'un espace. Quand une source matche cette IP, elle apparaît comme **Contrôleur Omada** dans le tableau des sources (prioritaire sur le lookup d'équipement Omada normal). Particulièrement utile en Mode LAN où le contrôleur émet ses propres logs avec son IP interne.

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

## Alertes "no-logs"

SyslogHub peut envoyer une notification si un espace arrête de recevoir des logs pendant un délai configurable (défaut 24h). Un timer systemd (`syslog-alerts.timer`) vérifie tous les 10 min la fraîcheur du dernier log reçu sur chaque espace surveillé, et déclenche :
- **1 alerte DOWN** quand l'espace dépasse le seuil,
- **1 alerte RECOVERY** quand les logs reprennent.

### Configuration SMTP (globale)

Dans **Paramètres → Alertes** :
- Cocher *Activer le système d'alertes*
- Serveur SMTP : `smtp.gmail.com` — Port : `587`
- Utilisateur / From : adresse Gmail
- Mot de passe : **App Password** Gmail (16 caractères, 2FA requis sur le compte). Voir [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
- Destinataire par défaut : adresse qui reçoit les alertes si l'espace n'a pas de destinataire propre
- Bouton *Tester* pour vérifier la config

### Par espace

Dans **Espaces → Modifier**, bloc *Alertes "no-logs"* :
- *Surveiller cet espace* → active/désactive
- *Seuil (heures)* → défaut 24, max 720
- *Email destinataire* → optionnel, override du destinataire global
- *URL Webhook* → optionnel, POST JSON avec `{event, space, port, threshold_hours, last_log_at}`

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
