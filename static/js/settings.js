document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  await loadStatus();
  await loadOmadaSettings();
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

// ── Omada integration ─────────────────────────────────────────────────────────

async function loadOmadaSettings() {
  try {
    const s = await api('GET', '/settings/omada');
    document.getElementById('omada-base-url').value = s.base_url || '';
    document.getElementById('omada-id').value = s.omada_id || '';
    document.getElementById('omada-client-id').value = s.client_id || '';
    document.getElementById('omada-site').value = s.site_name || 'Default';
    document.getElementById('omada-verify-ssl').checked = s.verify_ssl || false;

    const badge = document.getElementById('omada-status-badge');
    if (badge) {
      badge.textContent = s.configured ? 'Configuré' : 'Non configuré';
      badge.className = 'badge ' + (s.configured ? 'badge-success' : 'badge-warning');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

document.getElementById('omada-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const secret = document.getElementById('omada-client-secret').value;
  try {
    await api('PUT', '/settings/omada', {
      base_url: document.getElementById('omada-base-url').value.trim(),
      omada_id: document.getElementById('omada-id').value.trim(),
      client_id: document.getElementById('omada-client-id').value.trim(),
      client_secret: secret || null,
      site_name: document.getElementById('omada-site').value.trim() || 'Default',
      verify_ssl: document.getElementById('omada-verify-ssl').checked,
    });
    document.getElementById('omada-client-secret').value = '';
    showToast('Intégration Omada enregistrée', 'success');
    await loadOmadaSettings();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

async function testOmada() {
  const resultEl = document.getElementById('omada-test-result');
  resultEl.style.display = 'block';
  resultEl.className = 'alert alert-info';
  resultEl.textContent = 'Connexion en cours…';
  try {
    const res = await api('GET', '/settings/omada/test');
    resultEl.className = 'alert alert-success';
    const sample = res.sample.map(a => `${a.name || '?'} (${a.mac})${a.model ? ' — ' + a.model : ''}`).join(', ');
    resultEl.innerHTML = `<strong>✓ Connexion réussie</strong> — ${res.ap_count} AP(s) sur le site "<em>${escHtml(res.site_name)}</em>"` +
      (sample ? `<br><span style="font-size:12px">${escHtml(sample)}</span>` : '');
  } catch (err) {
    resultEl.className = 'alert alert-danger';
    resultEl.textContent = err.message;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
