document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
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
    showToast('Sécurité mise à jour', 'success');
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
  } catch (err) {
    showToast(err.message, 'error');
  }
});
