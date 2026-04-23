let auditPage = 1;

document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  await loadAlertsConfig();
  await loadStatus();
  await loadOidcConfig();
  await loadTotpStatus();
  await loadSessions();
  await loadAudit();
});

async function loadSettings() {
  try {
    const settings = await api('GET', '/settings');
    document.getElementById('retention-days').value = settings.retention_days;
    document.getElementById('admin-username').value = settings.admin_username;
    // v1.10.0 — show a blocking banner when the admin still runs the seeded
    // default password. The backend also 403s every non-settings API route.
    const banner = document.getElementById('password-must-change-banner');
    if (banner) {
      banner.style.display = settings.password_must_change ? 'block' : 'none';
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadStatus() {
  try {
    const status = await api('GET', '/settings/status');
    document.getElementById('status-content').innerHTML = `
      <div>
        <div class="status-row">
          <span class="status-label">rsyslog</span>
          <span class="badge ${status.rsyslog_active ? 'badge-success' : 'badge-danger'}">
            ${status.rsyslog_active ? 'Actif' : 'Inactif'}
          </span>
        </div>
        <div class="status-row">
          <span class="status-label">nginx</span>
          <span class="badge ${status.nginx_active ? 'badge-success' : 'badge-danger'}">
            ${status.nginx_active ? 'Actif' : 'Inactif'}
          </span>
        </div>
        <div class="status-row">
          <span class="status-label">Espaces actifs</span>
          <span class="status-value">${status.enabled_spaces} / ${status.total_spaces}</span>
        </div>
        <div class="status-row">
          <span class="status-label">Taille totale logs</span>
          <span class="status-value">${formatBytes(status.total_log_size_bytes)}</span>
        </div>
        <div class="status-row">
          <span class="status-label">Taille base de données</span>
          <span class="status-value">${formatBytes(status.db_size_bytes)}</span>
        </div>
      </div>
    `;
  } catch (err) {
    document.getElementById('status-content').innerHTML =
      `<div class="alert alert-danger" style="margin:16px">${err.message}</div>`;
  }
}

async function loadAlertsConfig() {
  try {
    const cfg = await api('GET', '/settings/alerts');
    document.getElementById('alerts-enabled').checked = !!cfg.enabled;
    document.getElementById('smtp-host').value = cfg.smtp_host || '';
    document.getElementById('smtp-port').value = cfg.smtp_port || '';
    document.getElementById('smtp-username').value = cfg.smtp_username || '';
    document.getElementById('smtp-from').value = cfg.smtp_from_email || '';
    document.getElementById('smtp-default-to').value = cfg.smtp_default_to || '';
    const pwdEl = document.getElementById('smtp-password');
    pwdEl.placeholder = cfg.smtp_password_set ? '•••••••• (configuré)' : '••••••••';
  } catch (err) {
    showToast(err.message, 'error');
  }
}

document.getElementById('alerts-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    enabled: document.getElementById('alerts-enabled').checked,
    smtp_host: document.getElementById('smtp-host').value.trim(),
    smtp_username: document.getElementById('smtp-username').value.trim(),
    smtp_from_email: document.getElementById('smtp-from').value.trim(),
    smtp_default_to: document.getElementById('smtp-default-to').value.trim(),
  };
  const portVal = document.getElementById('smtp-port').value.trim();
  if (portVal) body.smtp_port = parseInt(portVal, 10);
  const pwd = document.getElementById('smtp-password').value;
  if (pwd) body.smtp_password = pwd;
  try {
    await api('PUT', '/settings/alerts', body);
    document.getElementById('smtp-password').value = '';
    showToast('Configuration alertes enregistrée', 'success');
    await loadAlertsConfig();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

async function testAlerts() {
  const to = document.getElementById('smtp-default-to').value.trim();
  if (!to) {
    showToast('Renseignez un destinataire par défaut avant de tester', 'error');
    return;
  }
  try {
    await api('POST', '/settings/alerts/test', { to_email: to });
    showToast(`Email de test envoyé à ${to}`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

document.getElementById('general-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const retentionDays = parseInt(document.getElementById('retention-days').value, 10);
    if (!retentionDays || retentionDays < 1) throw new Error('Valeur invalide');
    await api('PUT', '/settings', { retention_days: retentionDays });
    showToast('Paramètres enregistrés', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
});

async function loadOidcConfig() {
  const badge = document.getElementById('oidc-status-badge');
  try {
    const cfg = await api('GET', '/settings/oidc');
    document.getElementById('oidc-enabled').checked = !!cfg.enabled;
    document.getElementById('oidc-discovery').value = cfg.discovery_url || '';
    document.getElementById('oidc-client-id').value = cfg.client_id || '';
    document.getElementById('oidc-allowlist').value = cfg.allowlist || '';
    document.getElementById('oidc-label').value = cfg.button_label || '';
    const reqVerified = document.getElementById('oidc-require-verified');
    if (reqVerified) reqVerified.checked = cfg.require_verified_email !== false;
    const secret = document.getElementById('oidc-client-secret');
    secret.placeholder = cfg.client_secret_set ? '•••••••• (configuré)' : '••••••••';
    if (cfg.enabled) {
      badge.textContent = 'Activé';
      badge.className = 'badge badge-success';
    } else {
      badge.textContent = 'Désactivé';
      badge.className = 'badge badge-warning';
    }
  } catch (err) {
    badge.textContent = '?';
  }
}

document.getElementById('oidc-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    enabled: document.getElementById('oidc-enabled').checked,
    discovery_url: document.getElementById('oidc-discovery').value.trim(),
    client_id: document.getElementById('oidc-client-id').value.trim(),
    allowlist: document.getElementById('oidc-allowlist').value.trim(),
    button_label: document.getElementById('oidc-label').value.trim(),
    require_verified_email: document.getElementById('oidc-require-verified').checked,
  };
  const secret = document.getElementById('oidc-client-secret').value;
  if (secret) body.client_secret = secret;
  try {
    await api('PUT', '/settings/oidc', body);
    document.getElementById('oidc-client-secret').value = '';
    showToast('Configuration OIDC enregistrée', 'success');
    await loadOidcConfig();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

async function loadTotpStatus() {
  const badge = document.getElementById('totp-status-badge');
  const activateBtn = document.getElementById('totp-activate-btn');
  const disableBtn = document.getElementById('totp-disable-btn');
  const setup = document.getElementById('totp-setup');
  try {
    const s = await api('GET', '/settings/totp');
    if (s.enabled) {
      badge.textContent = 'Activée';
      badge.className = 'badge badge-success';
      activateBtn.style.display = 'none';
      disableBtn.style.display = 'inline-flex';
      setup.style.display = 'none';
      setup.innerHTML = '';
    } else {
      badge.textContent = 'Désactivée';
      badge.className = 'badge badge-warning';
      activateBtn.style.display = 'inline-flex';
      disableBtn.style.display = 'none';
    }
  } catch (err) {
    badge.textContent = '?';
  }
}

async function startTotpSetup() {
  const setup = document.getElementById('totp-setup');
  try {
    const res = await api('POST', '/settings/totp/setup');
    setup.style.display = 'block';
    setup.innerHTML = `
      <div style="display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap;margin:16px 0;padding:16px;border:1px solid var(--color-border);border-radius:8px;background:var(--color-bg)">
        <div style="width:200px;height:200px;background:white;padding:6px;border-radius:6px">${res.svg}</div>
        <div style="flex:1;min-width:240px">
          <p>Scannez ce QR code avec votre application d'authentification, puis saisissez le code à 6 chiffres :</p>
          <p class="help-text mono" style="word-break:break-all;font-size:11px">${escapeHtml(res.uri)}</p>
          <div class="form-group" style="margin-top:12px">
            <label for="totp-code">Code de vérification</label>
            <input type="text" id="totp-code" inputmode="numeric" pattern="[0-9]*"
                   maxlength="6" placeholder="123456" autocomplete="one-time-code"
                   style="font-size:22px;letter-spacing:4px;text-align:center;max-width:180px">
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary" onclick="confirmTotp()">Confirmer</button>
            <button class="btn btn-secondary" onclick="cancelTotpSetup()">Annuler</button>
          </div>
        </div>
      </div>`;
    setTimeout(() => document.getElementById('totp-code')?.focus(), 100);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function cancelTotpSetup() {
  const setup = document.getElementById('totp-setup');
  setup.style.display = 'none';
  setup.innerHTML = '';
}

async function confirmTotp() {
  const code = document.getElementById('totp-code').value.trim();
  if (!/^\d{6}$/.test(code)) {
    showToast('Code à 6 chiffres requis', 'error');
    return;
  }
  try {
    await api('POST', '/settings/totp/activate', { code });
    showToast('2FA activée', 'success');
    cancelTotpSetup();
    await loadTotpStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function openTotpDisable() {
  const pwd = prompt('Pour désactiver la 2FA, confirmez votre mot de passe admin :');
  if (pwd === null) return;
  try {
    await api('DELETE', '/settings/totp', { password: pwd });
    showToast('2FA désactivée', 'success');
    await loadTotpStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadSessions() {
  const container = document.getElementById('sessions-content');
  try {
    const sessions = await api('GET', '/settings/sessions');
    if (!sessions.length) {
      container.innerHTML = '<div class="empty-state">Aucune session active</div>';
      return;
    }
    const rows = sessions.map(s => {
      const created = new Date(s.created_at).toLocaleString('fr-FR');
      const lastSeen = new Date(s.last_seen_at).toLocaleString('fr-FR');
      const ua = s.user_agent || '';
      const currentBadge = s.is_current
        ? '<span class="badge badge-success">Cette session</span>' : '';
      const revokeBtn = s.is_current
        ? `<button class="btn btn-danger btn-sm" onclick="revokeSession('${s.id}', true)">Se déconnecter</button>`
        : `<button class="btn btn-danger btn-sm" onclick="revokeSession('${s.id}', false)">Révoquer</button>`;
      return `
        <tr${s.is_current ? ' class="row-highlight"' : ''}>
          <td class="mono">${escapeHtml(s.ip || '—')}</td>
          <td class="col-ua" title="${escapeHtml(ua)}">${escapeHtml(ua || '—')}</td>
          <td class="mono">${created}</td>
          <td class="mono">${lastSeen}</td>
          <td class="col-actions">${currentBadge}${revokeBtn}</td>
        </tr>`;
    }).join('');
    container.innerHTML = `
      <div class="data-table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Navigateur</th>
              <th>Créée</th>
              <th>Dernière activité</th>
              <th style="text-align:right">Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    container.innerHTML = `<div class="alert alert-danger" style="margin:16px">${err.message}</div>`;
  }
}

async function revokeSession(id, isCurrent) {
  const msg = isCurrent
    ? 'Vous allez être déconnecté. Continuer ?'
    : 'Révoquer cette session ?';
  if (!confirm(msg)) return;
  try {
    await api('DELETE', `/settings/sessions/${id}`);
    if (isCurrent) {
      window.location = '/login';
      return;
    }
    showToast('Session révoquée', 'success');
    await loadSessions();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function revokeOtherSessions() {
  if (!confirm('Révoquer toutes les autres sessions ?')) return;
  try {
    const res = await api('DELETE', '/settings/sessions');
    showToast(`${res.revoked} session(s) révoquée(s)`, 'success');
    await loadSessions();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadAudit(page) {
  if (typeof page === 'number') auditPage = page;
  const action = document.getElementById('audit-action').value;
  const username = document.getElementById('audit-username').value.trim();
  const params = new URLSearchParams({ page: auditPage, per_page: 25 });
  if (action) params.set('action', action);
  if (username) params.set('username', username);

  const container = document.getElementById('audit-content');
  const pager = document.getElementById('audit-pagination');
  try {
    const res = await api('GET', `/settings/audit?${params.toString()}`);
    if (!res.items.length) {
      container.innerHTML = '<div class="empty-state">Aucune entrée</div>';
      pager.innerHTML = '';
      return;
    }
    const rows = res.items.map(e => {
      const ts = new Date(e.ts).toLocaleString('fr-FR');
      let details = '';
      if (e.details) {
        try {
          const obj = JSON.parse(e.details);
          details = Object.entries(obj)
            .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
            .join(' · ');
        } catch { details = e.details; }
      }
      return `
        <tr>
          <td class="mono">${ts}</td>
          <td><span class="badge badge-subtle">${escapeHtml(e.action)}</span></td>
          <td>${escapeHtml(e.username || '—')}</td>
          <td class="mono">${escapeHtml(e.ip || '—')}</td>
          <td class="col-details">${escapeHtml(details)}</td>
        </tr>`;
    }).join('');
    container.innerHTML = `
      <div class="data-table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Action</th>
              <th>Utilisateur</th>
              <th>IP</th>
              <th>Détails</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    pager.innerHTML = `
      <button class="btn btn-secondary btn-sm" ${res.page <= 1 ? 'disabled' : ''}
              onclick="loadAudit(${res.page - 1})">← Précédent</button>
      <span class="text-muted">Page ${res.page} / ${res.pages} — ${res.total} entrée(s)</span>
      <button class="btn btn-secondary btn-sm" ${res.page >= res.pages ? 'disabled' : ''}
              onclick="loadAudit(${res.page + 1})">Suivant →</button>`;
  } catch (err) {
    container.innerHTML = `<div class="alert alert-danger" style="margin:16px">${err.message}</div>`;
    pager.innerHTML = '';
  }
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

document.getElementById('security-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('admin-username').value.trim();
  const currentPwd = document.getElementById('current-password').value;
  const newPwd = document.getElementById('new-password').value;
  const confirmPwd = document.getElementById('confirm-password').value;

  if (newPwd && newPwd !== confirmPwd) {
    showToast('Les mots de passe ne correspondent pas', 'error');
    return;
  }

  const body = {};
  if (username) body.admin_username = username;
  if (newPwd) {
    body.current_password = currentPwd;
    body.new_password = newPwd;
  }

  if (!Object.keys(body).length) {
    showToast('Aucune modification', 'info');
    return;
  }

  try {
    await api('PUT', '/settings', body);
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
    if (body.new_password) {
      showToast('Mot de passe mis à jour — reconnexion dans 2 secondes…', 'success');
      setTimeout(async () => {
        await api('POST', '/auth/logout');
        window.location = '/login';
      }, 2000);
    } else {
      showToast('Sécurité mise à jour', 'success');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
});

