document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
});

async function loadDashboard() {
  try {
    const [spaces, status] = await Promise.all([
      api('GET', '/spaces'),
      api('GET', '/settings/status'),
    ]);
    renderStats(status);
    renderSpaces(spaces);
  } catch (err) {
    document.getElementById('spaces-grid').innerHTML =
      `<div class="alert alert-danger">${err.message}</div>`;
  }
}

function renderStats(status) {
  document.getElementById('stat-enabled').textContent = status.enabled_spaces;
  document.getElementById('stat-total').textContent = status.total_spaces;
  document.getElementById('stat-size').textContent = formatBytes(status.total_log_size_bytes);

  const rsyslogEl = document.getElementById('stat-rsyslog');
  rsyslogEl.textContent = status.rsyslog_active ? 'Actif' : 'Inactif';
  rsyslogEl.className = 'badge ' + (status.rsyslog_active ? 'badge-success' : 'badge-danger');

  const nginxEl = document.getElementById('stat-nginx');
  nginxEl.textContent = status.nginx_active ? 'Actif' : 'Inactif';
  nginxEl.className = 'badge ' + (status.nginx_active ? 'badge-success' : 'badge-danger');
}

function renderSpaces(spaces) {
  const grid = document.getElementById('spaces-grid');
  if (!spaces.length) {
    grid.innerHTML = `
      <div style="grid-column:1/-1; text-align:center; padding:48px 0; color:var(--color-text-muted)">
        <p>Aucun espace configuré.</p>
        <a href="/spaces/new" class="btn btn-primary" style="margin-top:16px">Créer un espace</a>
      </div>`;
    return;
  }

  grid.innerHTML = spaces.map(s => `
    <div class="space-card" id="card-${s.id}">
      <div class="space-card-header">
        <div>
          <div class="space-card-title">${escHtml(s.name)}</div>
          <div class="space-card-port">UDP :${s.port}</div>
        </div>
        <label class="toggle" title="${s.enabled ? 'Désactiver' : 'Activer'}">
          <input type="checkbox" ${s.enabled ? 'checked' : ''}
                 onchange="toggleSpace(${s.id}, this.checked)">
          <span class="toggle-slider"></span>
        </label>
      </div>
      ${s.description ? `<p class="text-muted" style="margin-bottom:10px">${escHtml(s.description)}</p>` : ''}
      <div class="space-card-stats">
        <div class="space-stat">
          <span class="space-stat-label">Sources</span>
          <span class="space-stat-value">${s.stats?.source_count ?? 0}</span>
        </div>
        <div class="space-stat">
          <span class="space-stat-label">Taille</span>
          <span class="space-stat-value">${formatBytes(s.stats?.total_size_bytes ?? 0)}</span>
        </div>
        <div class="space-stat" style="grid-column:1/-1">
          <span class="space-stat-label">Dernière activité</span>
          <span class="space-stat-value" style="font-size:13px">${formatDate(s.stats?.last_seen)}</span>
        </div>
      </div>
      <div class="space-card-actions">
        <a href="/logs/${s.id}" class="btn btn-primary btn-sm" style="flex:1;justify-content:center">
          Voir les logs
        </a>
        <a href="/spaces/${s.id}/edit" class="btn btn-secondary btn-sm">Modifier</a>
      </div>
    </div>
  `).join('');
}

async function toggleSpace(id, enabled) {
  try {
    await api('PUT', `/spaces/${id}`, { enabled });
    showToast(enabled ? 'Espace activé' : 'Espace désactivé', 'success');
  } catch (err) {
    showToast(err.message, 'error');
    // Revert toggle
    const cb = document.querySelector(`#card-${id} input[type=checkbox]`);
    if (cb) cb.checked = !enabled;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
