// ── Spaces list page ─────────────────────────────────────────────────────────
let _deleteTarget = null;

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

if (document.getElementById('spaces-tbody')) {
  document.addEventListener('DOMContentLoaded', loadSpaces);
}

async function loadSpaces() {
  try {
    const spaces = await api('GET', '/spaces');
    const tbody = document.getElementById('spaces-tbody');
    if (!spaces.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:32px">
        Aucun espace. <a href="/spaces/new">En créer un</a>
      </td></tr>`;
      return;
    }
    tbody.innerHTML = spaces.map(s => `
      <tr>
        <td><strong>${escHtml(s.name)}</strong></td>
        <td>
          <span class="badge badge-port">${s.port}</span>
          ${s.tcp_enabled ? '<span class="badge badge-info" style="margin-left:4px">TCP</span>' : ''}
        </td>
        <td>
          ${s.description ? escHtml(s.description) : '<span class="text-muted">—</span>'}
          ${s.allowed_ip ? `<br><span class="badge badge-info" style="margin-top:4px">🔒 ${escHtml(s.allowed_ip)}</span>` : ''}
        </td>
        <td>${s.stats?.source_count ?? 0}</td>
        <td>${formatBytes(s.stats?.total_size_bytes ?? 0)}</td>
        <td>
          <label class="toggle">
            <input type="checkbox" ${s.enabled ? 'checked' : ''}
                   onchange="toggleEnabled(${s.id}, this.checked)">
            <span class="toggle-slider"></span>
          </label>
        </td>
        <td>
          <div style="display:flex;gap:6px">
            <a href="/logs/${s.id}" class="btn btn-secondary btn-sm">Logs</a>
            <a href="/spaces/${s.id}/edit" class="btn btn-secondary btn-sm">Modifier</a>
            <button class="btn btn-danger btn-sm" onclick="confirmDelete(${s.id}, '${escHtml(s.name)}', ${s.port})">
              Supprimer
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleEnabled(id, enabled) {
  try {
    await api('PUT', `/spaces/${id}`, { enabled });
    showToast(enabled ? 'Espace activé' : 'Espace désactivé', 'success');
  } catch (err) {
    showToast(err.message, 'error');
    loadSpaces();
  }
}

function confirmDelete(id, name, port) {
  _deleteTarget = { id, name, port };
  document.getElementById('modal-space-name').textContent = name;
  document.getElementById('modal-space-port').textContent = port;
  document.getElementById('modal-delete-logs').checked = false;
  document.getElementById('modal-delete').style.display = 'flex';
  document.getElementById('modal-confirm-btn').onclick = executeDelete;
}

function closeModal() {
  document.getElementById('modal-delete').style.display = 'none';
  _deleteTarget = null;
}

async function executeDelete() {
  if (!_deleteTarget) return;
  const { id } = _deleteTarget;
  const deleteLogs = document.getElementById('modal-delete-logs').checked;
  closeModal();
  try {
    await api('DELETE', `/spaces/${id}?delete_logs=${deleteLogs}`);
    showToast('Espace supprimé', 'success');
    loadSpaces();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Close modal on overlay click
document.addEventListener('click', (e) => {
  if (e.target.id === 'modal-delete') closeModal();
});

// ── Space edit/create form ────────────────────────────────────────────────────
if (document.getElementById('space-form')) {
  document.getElementById('space-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('submit-btn');
    const errEl = document.getElementById('form-error');
    btn.disabled = true;
    errEl.style.display = 'none';

    const name = document.getElementById('name').value.trim();
    const description = document.getElementById('description').value.trim() || null;

    const allowedIpEl = document.getElementById('allowed-ip');
    const allowed_ip = allowedIpEl ? (allowedIpEl.value.trim() || null) : null;

    const tcpEl = document.getElementById('tcp-enabled');
    const tcp_enabled = tcpEl ? tcpEl.checked : false;

    try {
      if (typeof MODE !== 'undefined' && MODE === 'edit') {
        await api('PUT', `/spaces/${SPACE_ID}`, { name, description, allowed_ip, tcp_enabled });
        showToast('Espace mis à jour', 'success');
        window.location = '/spaces';
      } else {
        const port = parseInt(document.getElementById('port').value, 10);
        if (!port || port < 1 || port > 65535) throw new Error('Port invalide (1-65535)');
        await api('POST', '/spaces', { name, port, description, allowed_ip, tcp_enabled });
        showToast('Espace créé', 'success');
        window.location = '/spaces';
      }
    } catch (err) {
      errEl.textContent = err.message;
      errEl.style.display = 'block';
      btn.disabled = false;
    }
  });
}
