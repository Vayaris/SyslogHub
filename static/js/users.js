// v2.0.0 — /users page : gestion multi-utilisateurs + rôles par space

let _spacesCache = [];
let _currentUserForRoles = null;

async function ensureAdminOr403() {
  // Wait for base.html's me fetch to land
  for (let i = 0; i < 20; i++) {
    if (window.__ME) break;
    await new Promise(r => setTimeout(r, 50));
  }
  if (!window.__ME) {
    try {
      const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
      if (!res.ok) { window.location = '/login'; return false; }
      window.__ME = await res.json();
    } catch (e) { window.location = '/login'; return false; }
  }
  if (!window.__ME.is_admin) {
    document.getElementById('not-admin-banner').style.display = '';
    document.querySelector('.page-header .btn').style.display = 'none';
    document.getElementById('users-table').querySelector('tbody').innerHTML =
      '<tr><td colspan="8" class="text-muted">Accès refusé.</td></tr>';
    return false;
  }
  return true;
}

async function loadUsers() {
  try {
    const users = await api('GET', '/users');
    renderUsers(users || []);
  } catch (e) {
    showToast('Erreur chargement utilisateurs : ' + e.message, 'error');
  }
}

function renderUsers(users) {
  const tbody = document.querySelector('#users-table tbody');
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-muted">Aucun utilisateur.</td></tr>';
    return;
  }
  tbody.innerHTML = users.map(u => `
    <tr>
      <td><strong>${escapeHtml(u.username)}</strong></td>
      <td>${escapeHtml(u.email || '—')}</td>
      <td>${u.role_global === 'admin'
          ? '<span class="badge badge-warning">Admin</span>'
          : '<span class="badge">Opérateur</span>'}</td>
      <td>${u.totp_enabled ? '✓' : '—'}</td>
      <td>${u.oidc_subject
          ? '<span class="badge">SSO</span>'
          : (u.has_password ? '<span class="badge">Local</span>' : '<span class="badge">—</span>')}</td>
      <td>${u.last_login_at ? formatDate(u.last_login_at) : '—'}</td>
      <td>${u.disabled ? '<span class="badge badge-danger">Désactivé</span>' : '<span class="badge badge-ok">Actif</span>'}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn btn-sm" onclick="openRolesPanel(${u.id}, '${escapeAttr(u.username)}')">Espaces</button>
        <button class="btn btn-sm" onclick="openEditUserModal(${u.id})">Modifier</button>
        <button class="btn btn-sm btn-danger" onclick="deleteUser(${u.id}, '${escapeAttr(u.username)}')">Suppr.</button>
      </td>
    </tr>
  `).join('');
}

function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function escapeAttr(s) { return escapeHtml(s).replace(/'/g, "\\'"); }

// ── Modal create/edit ───────────────────────────────────────────────────────

function openCreateUserModal() {
  document.getElementById('user-modal-title').textContent = 'Nouvel utilisateur';
  document.getElementById('user-id').value = '';
  document.getElementById('user-username').value = '';
  document.getElementById('user-username').disabled = false;
  document.getElementById('user-email').value = '';
  document.getElementById('user-role').value = 'operator';
  document.getElementById('user-password').value = '';
  document.getElementById('user-password-hint').textContent = '(min. 8 caractères)';
  document.getElementById('user-disabled-group').style.display = 'none';
  document.getElementById('user-disabled').checked = false;
  document.getElementById('user-modal').style.display = 'flex';
}

async function openEditUserModal(userId) {
  const users = await api('GET', '/users');
  const u = (users || []).find(x => x.id === userId);
  if (!u) return;
  document.getElementById('user-modal-title').textContent = 'Modifier ' + u.username;
  document.getElementById('user-id').value = u.id;
  document.getElementById('user-username').value = u.username;
  document.getElementById('user-email').value = u.email || '';
  document.getElementById('user-role').value = u.role_global;
  document.getElementById('user-password').value = '';
  document.getElementById('user-password-hint').textContent = '(vide = conserver)';
  document.getElementById('user-disabled-group').style.display = '';
  document.getElementById('user-disabled').checked = !!u.disabled;
  document.getElementById('user-modal').style.display = 'flex';
}

function closeUserModal() {
  document.getElementById('user-modal').style.display = 'none';
}

async function submitUserForm(ev) {
  ev.preventDefault();
  const id = document.getElementById('user-id').value;
  const username = document.getElementById('user-username').value.trim();
  const email = document.getElementById('user-email').value.trim();
  const role = document.getElementById('user-role').value;
  const pw = document.getElementById('user-password').value;

  try {
    if (!id) {
      const body = { username, role_global: role };
      if (email) body.email = email;
      if (pw) body.password = pw;
      await api('POST', '/users', body);
      showToast('Utilisateur créé', 'success');
    } else {
      const body = { username, role_global: role };
      body.email = email || null;
      body.disabled = document.getElementById('user-disabled').checked;
      if (pw) body.new_password = pw;
      await api('PUT', '/users/' + id, body);
      showToast('Utilisateur mis à jour', 'success');
    }
    closeUserModal();
    await loadUsers();
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
  return false;
}

async function deleteUser(id, name) {
  if (!confirm(`Supprimer l'utilisateur "${name}" ? Ses rôles sur les espaces seront également supprimés.`)) return;
  try {
    await api('DELETE', '/users/' + id);
    showToast('Utilisateur supprimé', 'success');
    await loadUsers();
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

// ── Roles par space ─────────────────────────────────────────────────────────

async function openRolesPanel(userId, username) {
  _currentUserForRoles = { id: userId, username };
  document.getElementById('roles-card').style.display = '';
  document.getElementById('roles-card-title').textContent = `Rôles par espace — ${username}`;

  // Load spaces into the dropdown (once cached)
  if (!_spacesCache.length) {
    _spacesCache = await api('GET', '/spaces');
  }
  const sel = document.getElementById('roles-space-select');
  sel.innerHTML = _spacesCache.map(s =>
    `<option value="${s.id}">${escapeHtml(s.name)} (port ${s.port})</option>`
  ).join('');

  await reloadRoles();
}

function closeRolesPanel() {
  document.getElementById('roles-card').style.display = 'none';
  _currentUserForRoles = null;
}

async function reloadRoles() {
  if (!_currentUserForRoles) return;
  const rows = await api('GET', `/users/${_currentUserForRoles.id}/spaces`);
  const tbody = document.querySelector('#roles-table tbody');
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted">Aucun rôle attribué.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${escapeHtml(r.space_name || '—')}</td>
      <td><span class="badge">${escapeHtml(r.role)}</span></td>
      <td>${formatDate(r.granted_at)}</td>
      <td style="text-align:right">
        <button class="btn btn-sm btn-danger" onclick="removeSpaceRole(${r.space_id})">Retirer</button>
      </td>
    </tr>
  `).join('');
}

async function addSpaceRole() {
  if (!_currentUserForRoles) return;
  const spaceId = document.getElementById('roles-space-select').value;
  const role = document.getElementById('roles-role-select').value;
  try {
    await api('PUT', `/users/${_currentUserForRoles.id}/spaces/${spaceId}`, { role });
    showToast('Rôle attribué', 'success');
    await reloadRoles();
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

async function removeSpaceRole(spaceId) {
  if (!_currentUserForRoles) return;
  if (!confirm('Retirer ce rôle ?')) return;
  try {
    await api('DELETE', `/users/${_currentUserForRoles.id}/spaces/${spaceId}`);
    showToast('Rôle retiré', 'success');
    await reloadRoles();
  } catch (e) {
    showToast('Erreur : ' + e.message, 'error');
  }
}

// ── Boot ────────────────────────────────────────────────────────────────────

(async () => {
  if (!(await ensureAdminOr403())) return;
  await loadUsers();
})();
