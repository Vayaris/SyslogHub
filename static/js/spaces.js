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

    const lanEl = document.getElementById('lan-mode');
    const lan_mode = lanEl ? lanEl.checked : false;

    const omada = collectOmadaFields();
    const alerts = collectAlertFields();

    try {
      if (typeof MODE !== 'undefined' && MODE === 'edit') {
        await api('PUT', `/spaces/${SPACE_ID}`, {
          name, description, allowed_ip, tcp_enabled, lan_mode, ...omada, ...alerts,
        });
        showToast('Espace mis à jour', 'success');
        window.location = '/spaces';
      } else {
        const port = parseInt(document.getElementById('port').value, 10);
        if (!port || port < 1 || port > 65535) throw new Error('Port invalide (1-65535)');
        await api('POST', '/spaces', {
          name, port, description, allowed_ip, tcp_enabled, lan_mode, ...omada, ...alerts,
        });
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

// ── Alert fields on space edit form ──────────────────────────────────────────
function collectAlertFields() {
  const enabledEl = document.getElementById('alerts-enabled');
  if (!enabledEl) return {};
  const threshold = parseInt(document.getElementById('alert-threshold').value, 10);
  return {
    alerts_enabled: enabledEl.checked,
    alert_threshold_hours: (threshold && threshold > 0) ? threshold : 24,
    alert_email_to: document.getElementById('alert-email').value.trim() || null,
    alert_webhook_url: document.getElementById('alert-webhook').value.trim() || null,
  };
}

// ── Omada fields on space edit form ───────────────────────────────────────────
function collectOmadaFields() {
  const baseUrl = document.getElementById('omada-base-url');
  if (!baseUrl) return {};
  const secret = document.getElementById('omada-client-secret').value;
  const controllerEl = document.getElementById('omada-controller-ip');
  const fields = {
    omada_base_url:      baseUrl.value.trim() || null,
    omada_id:            document.getElementById('omada-id').value.trim() || null,
    omada_client_id:     document.getElementById('omada-client-id').value.trim() || null,
    omada_verify_ssl:    document.getElementById('omada-verify-ssl').checked,
    omada_controller_ip: controllerEl ? (controllerEl.value.trim() || null) : null,
  };
  // Empty secret on edit = keep current; on create, send null (optional)
  if (secret) fields.omada_client_secret = secret;
  return fields;
}

async function testOmadaForSpace() {
  if (typeof SPACE_ID === 'undefined' || SPACE_ID === null) return;
  const resultEl = document.getElementById('omada-test-result');
  resultEl.style.display = 'block';
  resultEl.className = 'alert alert-info';
  resultEl.textContent = 'Connexion en cours… (enregistrez d\'abord si vous venez de modifier les champs)';
  try {
    const res = await api('GET', `/spaces/${SPACE_ID}/omada/test`);
    resultEl.className = 'alert alert-success';

    const parts = [];
    parts.push(res.msp_mode ? 'Mode MSP' : 'Mode standard');
    parts.push(`${res.sites_total} site(s)`);
    if (res.msp_mode && res.customers_total != null) {
      parts.push(`${res.customers_total} client(s)`);
    }
    const typeCounts = Object.entries(res.device_count_by_type || {})
      .map(([t, n]) => `${n} ${t}`)
      .join(', ');
    parts.push(`${res.device_count} équipement(s)${typeCounts ? ' (' + typeCounts + ')' : ''}`);

    const sampleLines = (res.sample || []).map(d => {
      const bits = [];
      if (d.name) bits.push(d.name);
      bits.push(`${d.type || '?'}${d.model ? ' ' + d.model : ''}`);
      if (d.customer) bits.push(d.customer);
      if (d.site) bits.push(d.site);
      return `${bits.join(' — ')} (${d.mac})`;
    });

    let html = `<strong>✓ Connexion réussie</strong><br>${escHtml(parts.join(' · '))}`;
    if (sampleLines.length) {
      html += `<div style="font-size:12px;margin-top:6px">${sampleLines.map(escHtml).join('<br>')}</div>`;
    }
    resultEl.innerHTML = html;
  } catch (err) {
    resultEl.className = 'alert alert-danger';
    resultEl.textContent = err.message;
  }
}
