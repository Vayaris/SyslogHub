function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Sources list (logs_space.html) ───────────────────────────────────────────
let _sourcesPage = 1;
let _sourcesFilter = '';
let _filterTimer = null;

if (document.getElementById('sources-tbody')) {
  document.addEventListener('DOMContentLoaded', () => {
    loadSources();

    document.getElementById('filter-ip').addEventListener('input', (e) => {
      clearTimeout(_filterTimer);
      _filterTimer = setTimeout(() => {
        _sourcesFilter = e.target.value.trim();
        _sourcesPage = 1;
        loadSources();
      }, 300);
    });
  });

  document.getElementById('search-btn').addEventListener('click', doSearch);
  document.getElementById('search-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doSearch();
  });
}

async function loadSources() {
  try {
    const params = new URLSearchParams({
      page: _sourcesPage,
      per_page: 50,
      filter_ip: _sourcesFilter,
    });
    const res = await api('GET', `/logs/${SPACE_ID}/sources?${params}`);
    const tbody = document.getElementById('sources-tbody');

    const countEl = document.getElementById('sources-count');
    if (countEl) countEl.textContent = res.total ? `${res.total} source(s)` : '';

    if (!res.items.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding:32px">
        ${_sourcesFilter ? 'Aucune source ne correspond au filtre.' : 'Aucun log reçu sur cet espace.'}
      </td></tr>`;
      document.getElementById('sources-pagination').style.display = 'none';
      return;
    }

    tbody.innerHTML = res.items.map(s => `
      <tr style="cursor:pointer" onclick="window.location='/logs/${SPACE_ID}/${escHtml(s.ip)}'">
        <td><strong>${escHtml(s.ip)}</strong></td>
        <td>${formatBytes(s.size_bytes)}</td>
        <td>${s.line_count.toLocaleString()}</td>
        <td>${formatDate(s.last_modified)}</td>
        <td>
          <div style="display:flex;gap:6px" onclick="event.stopPropagation()">
            <a href="/logs/${SPACE_ID}/${escHtml(s.ip)}" class="btn btn-secondary btn-sm">Voir</a>
            <button class="btn btn-danger btn-sm" onclick="confirmDeleteSource('${escHtml(s.ip)}')">Supprimer</button>
          </div>
        </td>
      </tr>
    `).join('');

    renderSourcesPagination(res.page, res.pages);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderSourcesPagination(page, pages) {
  const el = document.getElementById('sources-pagination');
  if (pages <= 1) { el.style.display = 'none'; return; }
  el.style.display = 'flex';
  el.innerHTML = `
    <button class="btn btn-secondary btn-sm" onclick="goSourcesPage(${page - 1})" ${page <= 1 ? 'disabled' : ''}>← Préc.</button>
    <span class="pagination-info">Page ${page} / ${pages}</span>
    <button class="btn btn-secondary btn-sm" onclick="goSourcesPage(${page + 1})" ${page >= pages ? 'disabled' : ''}>Suiv. →</button>
  `;
}

function goSourcesPage(p) {
  _sourcesPage = p;
  loadSources();
}

// ── Delete source IP ──────────────────────────────────────────────────────────
let _deleteSourceTarget = null;

function confirmDeleteSource(ip) {
  _deleteSourceTarget = ip;
  document.getElementById('modal-source-ip').textContent = ip;
  document.getElementById('modal-delete-source').style.display = 'flex';
  document.getElementById('modal-source-confirm').onclick = executeDeleteSource;
}

function closeSourceModal() {
  document.getElementById('modal-delete-source').style.display = 'none';
  _deleteSourceTarget = null;
}

async function executeDeleteSource() {
  if (!_deleteSourceTarget) return;
  const ip = _deleteSourceTarget;
  closeSourceModal();
  try {
    const res = await api('DELETE', `/logs/${SPACE_ID}/sources/${ip}`);
    showToast(`Source ${ip} supprimée (${res.deleted_files.length} fichier(s))`, 'success');
    loadSources();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Close modal on overlay click
if (document.getElementById('modal-delete-source')) {
  document.getElementById('modal-delete-source').addEventListener('click', (e) => {
    if (e.target.id === 'modal-delete-source') closeSourceModal();
  });
}

async function doSearch() {
  const q = document.getElementById('search-input').value.trim();
  if (q.length < 3) { showToast('Saisir au moins 3 caractères', 'info'); return; }

  document.getElementById('search-results').style.display = 'block';
  document.getElementById('search-content').innerHTML = '<div class="loading-placeholder">Recherche…</div>';

  try {
    const res = await api('GET', `/logs/search?space_id=${SPACE_ID}&q=${encodeURIComponent(q)}`);
    if (!res.results.length) {
      document.getElementById('search-content').innerHTML =
        '<div class="loading-placeholder">Aucun résultat.</div>';
      return;
    }
    document.getElementById('search-content').innerHTML = `
      <table class="table">
        <thead><tr><th>Source IP</th><th>Fichier</th><th>Ligne #</th><th>Contenu</th></tr></thead>
        <tbody>
          ${res.results.map(r => `
            <tr>
              <td>${escHtml(r.source_ip)}</td>
              <td>${escHtml(r.filename)}</td>
              <td>${r.line_number}</td>
              <td style="font-family:var(--font-mono);font-size:12px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                <a href="/logs/${r.space_id}/${r.source_ip}/view?filename=${encodeURIComponent(r.filename)}">
                  ${escHtml(r.line)}
                </a>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      ${res.truncated ? '<p class="text-muted" style="padding:10px 16px">Résultats tronqués — affinez votre recherche.</p>' : ''}
    `;
  } catch (err) {
    document.getElementById('search-content').innerHTML =
      `<div class="alert alert-danger" style="margin:16px">${err.message}</div>`;
  }
}

function clearSearch() {
  document.getElementById('search-results').style.display = 'none';
  document.getElementById('search-input').value = '';
}

// ── Files list (logs_files.html) ─────────────────────────────────────────────
if (document.getElementById('files-tbody')) {
  document.addEventListener('DOMContentLoaded', loadFiles);
}

async function loadFiles() {
  try {
    const files = await api('GET', `/logs/${SPACE_ID}/sources/${SOURCE_IP}/files`);
    const tbody = document.getElementById('files-tbody');
    if (!files.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding:32px">
        Aucun fichier trouvé.
      </td></tr>`;
      return;
    }
    tbody.innerHTML = files.map(f => `
      <tr>
        <td style="font-family:var(--font-mono);font-size:13px">${escHtml(f.filename)}</td>
        <td>${formatBytes(f.size_bytes)}</td>
        <td>${formatDate(f.last_modified)}</td>
        <td>${f.is_rotated
          ? '<span class="badge badge-warning">Archivé</span>'
          : '<span class="badge badge-success">Actif</span>'}</td>
        <td>
          <div style="display:flex;gap:6px">
            <a href="/logs/${SPACE_ID}/${SOURCE_IP}/view?filename=${encodeURIComponent(f.filename)}"
               class="btn btn-primary btn-sm">Voir</a>
            <a href="/api/logs/${SPACE_ID}/sources/${SOURCE_IP}/download?filename=${encodeURIComponent(f.filename)}"
               class="btn btn-secondary btn-sm">Télécharger</a>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── Log viewer (logs_viewer.html) ────────────────────────────────────────────
let _viewerState = { offset: 0, lines: 100, filter: '', autoRefresh: null };

if (document.getElementById('log-output')) {
  document.addEventListener('DOMContentLoaded', () => {
    _viewerState.lines = parseInt(document.getElementById('lines-select').value, 10);
    loadLogContent();

    document.getElementById('lines-select').addEventListener('change', (e) => {
      _viewerState.lines = parseInt(e.target.value, 10);
      _viewerState.offset = 0;
      loadLogContent();
    });

    let filterTimeout;
    document.getElementById('filter-input').addEventListener('input', (e) => {
      clearTimeout(filterTimeout);
      filterTimeout = setTimeout(() => {
        _viewerState.filter = e.target.value;
        _viewerState.offset = 0;
        loadLogContent();
      }, 350);
    });

    document.getElementById('prev-btn').addEventListener('click', () => {
      _viewerState.offset += _viewerState.lines;
      loadLogContent();
    });

    document.getElementById('next-btn').addEventListener('click', () => {
      _viewerState.offset = Math.max(0, _viewerState.offset - _viewerState.lines);
      loadLogContent();
    });

    document.getElementById('autorefresh-toggle').addEventListener('change', (e) => {
      if (e.target.checked) {
        _viewerState.autoRefresh = setInterval(() => {
          _viewerState.offset = 0;
          loadLogContent();
        }, 5000);
      } else {
        clearInterval(_viewerState.autoRefresh);
        _viewerState.autoRefresh = null;
      }
    });
  });
}

async function loadLogContent() {
  const output = document.getElementById('log-output');
  const params = new URLSearchParams({
    filename: FILENAME,
    lines: _viewerState.lines,
    offset: _viewerState.offset,
    filter: _viewerState.filter,
  });

  try {
    const res = await api('GET',
      `/logs/${SPACE_ID}/sources/${SOURCE_IP}/view?${params}`);

    if (!res.lines.length) {
      output.textContent = _viewerState.filter
        ? `Aucune ligne ne correspond au filtre "${_viewerState.filter}"`
        : 'Aucun contenu.';
    } else {
      output.textContent = res.lines.join('\n');
    }

    // Update navigation info
    document.getElementById('line-info').textContent =
      `${res.total_lines.toLocaleString()} lignes au total`;

    document.getElementById('prev-btn').disabled = !res.has_more;
    document.getElementById('next-btn').disabled = _viewerState.offset === 0;

    // Auto-scroll to bottom on fresh load
    if (_viewerState.offset === 0) {
      output.scrollTop = output.scrollHeight;
    }
  } catch (err) {
    output.textContent = `Erreur: ${err.message}`;
    showToast(err.message, 'error');
  }
}
