document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  await loadAlertsConfig();
  await loadStatus();
});

async function loadSettings() {
  try {
    const settings = await api('GET', '/settings');
    document.getElementById('retention-days').value = settings.retention_days;
    document.getElementById('admin-username').value = settings.admin_username;
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

