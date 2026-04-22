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

    tbody.innerHTML = res.items.map(s => {
      const main = s.device_name ? escHtml(s.device_name) : escHtml(s.ip);
      const subParts = [];
      if (s.device_name) subParts.push(escHtml(s.ip));
      if (s.device_model) subParts.push(escHtml(s.device_model));
      if (s.geoip_country) subParts.push(`<span class="badge-geo">${escHtml(s.geoip_country)}</span>`);
      if (s.rdns_name) subParts.push(escHtml(s.rdns_name));
      const sub = subParts.length
        ? `<div class="source-sub">${subParts.join(' · ')}</div>`
        : '';
      return `
      <tr style="cursor:pointer" onclick="window.location='/logs/${SPACE_ID}/${escHtml(s.ip)}'">
        <td>
          <div class="source-main">${main}</div>
          ${sub}
        </td>
        <td>${formatBytes(s.size_bytes)}</td>
        <td>${s.line_count.toLocaleString()}</td>
        <td>${formatDate(s.last_modified)}</td>
        <td>
          <div style="display:flex;gap:6px" onclick="event.stopPropagation()">
            <a href="/logs/${SPACE_ID}/${escHtml(s.ip)}" class="btn btn-secondary btn-sm">Voir</a>
            <button class="btn btn-danger btn-sm" onclick="confirmDeleteSource('${escHtml(s.ip)}')">Supprimer</button>
          </div>
        </td>
      </tr>`;
    }).join('');

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

// ── Test log ────────────────────────────────────────────────────────────────

function openTestLogModal() {
  const modal = document.getElementById('modal-test-log');
  if (!modal) return;
  modal.style.display = 'flex';
  const input = document.getElementById('test-log-message');
  if (input) { input.focus(); input.select(); }
  document.getElementById('test-log-send').onclick = sendTestLog;
}

function closeTestLogModal() {
  const modal = document.getElementById('modal-test-log');
  if (modal) modal.style.display = 'none';
}

async function sendTestLog() {
  const input = document.getElementById('test-log-message');
  const btn = document.getElementById('test-log-send');
  const message = (input.value || '').trim() || 'Test depuis SyslogHub';
  btn.disabled = true;
  try {
    await api('POST', `/logs/${SPACE_ID}/test`, { message });
    closeTestLogModal();
    showToast('Log de test envoyé — rafraîchissement des sources…', 'success');
    setTimeout(() => loadSources(), 600);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

if (document.getElementById('modal-test-log')) {
  document.getElementById('modal-test-log').addEventListener('click', (e) => {
    if (e.target.id === 'modal-test-log') closeTestLogModal();
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
      const rangeStart = document.getElementById('range-start');
      if (rangeStart) rangeStart.closest('.card-header').querySelector('div').style.display = 'none';
      return;
    }
    setupRangePicker(files);
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

function setupRangePicker(files) {
  const startEl = document.getElementById('range-start');
  const endEl = document.getElementById('range-end');
  const btn = document.getElementById('btn-download-range');
  if (!startEl || !endEl || !btn) return;

  const dates = files.map(f => f.last_modified.slice(0, 10)).sort();
  const minD = dates[0], maxD = dates[dates.length - 1];
  startEl.min = endEl.min = minD;
  startEl.max = endEl.max = maxD;
  if (!startEl.value) startEl.value = minD;
  if (!endEl.value) endEl.value = maxD;

  function refresh() {
    const s = startEl.value, e = endEl.value;
    const ok = s && e && s <= e;
    if (ok) {
      btn.href = `/api/logs/${SPACE_ID}/sources/${SOURCE_IP}/download-range?start=${s}&end=${e}`;
      btn.style.opacity = '';
      btn.style.pointerEvents = '';
    } else {
      btn.href = '#';
      btn.style.opacity = '.5';
      btn.style.pointerEvents = 'none';
    }
  }
  startEl.addEventListener('input', refresh);
  endEl.addEventListener('input', refresh);
  refresh();
}

// ── AP MAC view (logs_space.html) ─────────────────────────────────────────────
let _currentView = 'ip'; // 'ip' | 'ap'

function setView(view) {
  _currentView = view;
  const ipTable = document.getElementById('sources-table');
  const apTable = document.getElementById('ap-table');
  const filterIp = document.getElementById('filter-ip');
  const pagination = document.getElementById('sources-pagination');
  const btnIp = document.getElementById('btn-view-ip');
  const btnAp = document.getElementById('btn-view-ap');

  if (view === 'ap') {
    ipTable && (ipTable.style.display = 'none');
    apTable && (apTable.style.display = '');
    filterIp && (filterIp.style.display = 'none');
    pagination && (pagination.style.display = 'none');
    btnIp && btnIp.classList.remove('active');
    btnAp && btnAp.classList.add('active');
    loadAPView();
  } else {
    ipTable && (ipTable.style.display = '');
    apTable && (apTable.style.display = 'none');
    filterIp && (filterIp.style.display = '');
    btnIp && btnIp.classList.add('active');
    btnAp && btnAp.classList.remove('active');
    loadSources();
  }
}

async function loadAPView() {
  const tbody = document.getElementById('ap-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding:24px">Analyse des logs…</td></tr>`;
  try {
    const res = await api('GET', `/logs/${SPACE_ID}/ap-macs`);
    const devices = res.devices || [];
    if (!devices.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding:24px">
        Aucun équipement détecté dans les logs de cet espace.<br>
        <span style="font-size:12px">Le format attendu est <code>AP MAC=xx:xx:xx:xx:xx:xx</code></span>
      </td></tr>`;
      return;
    }
    tbody.innerHTML = devices.map(d => {
      const statusBadge = d.status != null
        ? `<span class="badge ${d.status === 1 ? 'badge-success' : 'badge-warning'}">${d.status === 1 ? 'Connecté' : 'Hors ligne'}</span>`
        : '<span class="text-muted">—</span>';
      const typeLabel = d.type
        ? `<span class="badge badge-info">${escHtml(String(d.type))}</span>`
        : '<span class="text-muted">—</span>';
      return `
        <tr>
          <td><code style="font-size:13px">${escHtml(d.mac)}</code></td>
          <td>${d.name ? escHtml(d.name) : '<span class="text-muted">—</span>'}</td>
          <td>${typeLabel}</td>
          <td>${d.model ? escHtml(d.model) : '<span class="text-muted">—</span>'}</td>
          <td>${statusBadge}</td>
          <td>
            <a href="/logs/${SPACE_ID}?ap_mac=${encodeURIComponent(d.mac)}" class="btn btn-secondary btn-sm">
              Voir logs
            </a>
          </td>
        </tr>`;
    }).join('');
    const countEl = document.getElementById('sources-count');
    if (countEl) countEl.textContent = `${res.count} équipement(s) détecté(s)`;
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── Log viewer (logs_viewer.html) ────────────────────────────────────────────
let _viewerState = { offset: 0, lines: 100, filter: '', apMac: '', autoRefresh: null };
let _apMacMap = {}; // mac → {name, model}

if (document.getElementById('log-output')) {
  document.addEventListener('DOMContentLoaded', () => {
    _viewerState.lines = parseInt(document.getElementById('lines-select').value, 10);

    // Populate AP MAC dropdown
    loadAPMacDropdown();

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

async function loadAPMacDropdown() {
  const sel = document.getElementById('ap-mac-select');
  if (!sel) return;
  if (typeof MERGED !== 'undefined' && MERGED) return;
  try {
    const res = await api('GET', `/logs/${SPACE_ID}/ap-macs`);
    const aps = (res.devices || []).filter(d => (d.type || '').toLowerCase() === 'ap');
    if (!aps.length) return;

    aps.forEach(ap => {
      _apMacMap[ap.mac] = ap;
      const opt = document.createElement('option');
      opt.value = ap.mac;
      opt.textContent = ap.name ? `${ap.mac}  (${ap.name})` : ap.mac;
      sel.appendChild(opt);
    });

    const bar = document.getElementById('ap-filter-bar');
    if (bar) bar.style.display = 'flex';
  } catch (_) { /* non-critical */ }
}

function applyAPFilter() {
  const mac = document.getElementById('ap-mac-select').value;
  _viewerState.apMac = mac;
  _viewerState.offset = 0;

  const badge = document.getElementById('ap-name-badge');
  if (badge) {
    const ap = _apMacMap[mac];
    if (mac && ap && ap.name) {
      badge.textContent = ap.name + (ap.model ? ` — ${ap.model}` : '');
      badge.style.display = '';
    } else {
      badge.style.display = 'none';
    }
  }

  loadLogContent();
}

// ── Live tail (SSE) ──────────────────────────────────────────────────────────
let _liveSource = null;

function toggleLive() {
  const btn = document.getElementById('live-toggle');
  const label = document.getElementById('live-label');
  const output = document.getElementById('log-output');
  if (!btn || !output) return;

  if (_liveSource) {
    _liveSource.close();
    _liveSource = null;
    btn.classList.remove('btn-live-active');
    if (label) label.textContent = 'Live';
    return;
  }

  // Stop auto-refresh if running — the two don't mix well.
  const ar = document.getElementById('autorefresh-toggle');
  if (ar && ar.checked) { ar.checked = false; ar.dispatchEvent(new Event('change')); }

  const isMerged = typeof MERGED !== 'undefined' && MERGED;
  const url = isMerged
    ? `/api/logs/${SPACE_ID}/merged/stream`
    : `/api/logs/${SPACE_ID}/sources/${SOURCE_IP}/stream?filename=${encodeURIComponent(FILENAME)}`;

  output.textContent = '[Live — en attente de nouvelles lignes…]';
  _liveSource = new EventSource(url);
  let first = true;
  _liveSource.onmessage = (e) => {
    if (first) { output.textContent = ''; first = false; }
    output.textContent += (output.textContent ? '\n' : '') + e.data;
    output.scrollTop = output.scrollHeight;
  };
  _liveSource.onerror = () => {
    showToast('Flux live interrompu', 'warning');
    if (_liveSource) { _liveSource.close(); _liveSource = null; }
    btn.classList.remove('btn-live-active');
    if (label) label.textContent = 'Live';
  };

  btn.classList.add('btn-live-active');
  if (label) label.textContent = 'Live • actif';
}

async function loadLogContent() {
  const output = document.getElementById('log-output');
  const isMerged = typeof MERGED !== 'undefined' && MERGED;
  const params = new URLSearchParams({
    lines: _viewerState.lines,
    offset: _viewerState.offset,
    filter: _viewerState.filter,
  });
  if (!isMerged) {
    params.set('filename', FILENAME);
    params.set('ap_mac', _viewerState.apMac || '');
  }
  const url = isMerged
    ? `/logs/${SPACE_ID}/merged/view?${params}`
    : `/logs/${SPACE_ID}/sources/${SOURCE_IP}/view?${params}`;

  try {
    const res = await api('GET', url);

    if (!res.lines.length) {
      const noFilter = !_viewerState.filter && !_viewerState.apMac;
      output.textContent = noFilter
        ? 'Aucun contenu.'
        : `Aucune ligne ne correspond au filtre${_viewerState.apMac ? ` AP MAC=${_viewerState.apMac}` : ''}${_viewerState.filter ? ` "${_viewerState.filter}"` : ''}.`;
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
