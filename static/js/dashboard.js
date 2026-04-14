document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  loadVolumeChart();
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

// ── Volume chart ──────────────────────────────────────────────────────────────

async function loadVolumeChart() {
  try {
    const data = await api('GET', '/settings/volume?days=7');
    renderVolumeChart(data);
  } catch (_) {
    // Non-critical — hide chart container on failure
    const c = document.getElementById('chart-container');
    if (c) c.style.display = 'none';
  }
}

function renderVolumeChart(data) {
  const canvas = document.getElementById('volume-chart');
  if (!canvas) return;

  const container = document.getElementById('chart-container');
  const W = container.clientWidth || 800;
  canvas.width = W;

  const ctx = canvas.getContext('2d');
  const H = canvas.height;
  const PAD = { top: 16, right: 20, bottom: 40, left: 56 };
  const chartW = W - PAD.left - PAD.right;
  const chartH = H - PAD.top - PAD.bottom;

  const maxBytes = Math.max(...data.map(d => d.bytes), 1);
  const totalBytes = data.reduce((s, d) => s + d.bytes, 0);

  // Update total label
  const totalEl = document.getElementById('chart-total');
  if (totalEl) totalEl.textContent = `Total : ${formatBytes(totalBytes)}`;

  // Colors from CSS variables (read from computed style)
  const style = getComputedStyle(document.documentElement);
  const colorPrimary = style.getPropertyValue('--color-primary').trim() || '#2563eb';
  const colorBorder  = style.getPropertyValue('--color-border').trim()  || '#e2e8f0';
  const colorMuted   = style.getPropertyValue('--color-text-muted').trim() || '#64748b';

  ctx.clearRect(0, 0, W, H);

  const barCount = data.length;
  const gap = 8;
  const barW = Math.max(4, (chartW - gap * (barCount - 1)) / barCount);

  // Y-axis grid lines
  ctx.strokeStyle = colorBorder;
  ctx.lineWidth = 1;
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const y = PAD.top + (chartH / gridLines) * i;
    ctx.beginPath();
    ctx.moveTo(PAD.left, y);
    ctx.lineTo(PAD.left + chartW, y);
    ctx.stroke();

    // Y label
    const val = maxBytes * (1 - i / gridLines);
    ctx.fillStyle = colorMuted;
    ctx.font = '10px ' + (style.getPropertyValue('--font').trim() || 'sans-serif');
    ctx.textAlign = 'right';
    ctx.fillText(formatBytes(val, 0), PAD.left - 6, y + 3);
  }

  // Bars + X labels
  data.forEach((d, i) => {
    const x = PAD.left + i * (barW + gap);
    const barH = d.bytes > 0 ? Math.max(2, (d.bytes / maxBytes) * chartH) : 0;
    const y = PAD.top + chartH - barH;

    ctx.fillStyle = colorPrimary;
    ctx.beginPath();
    ctx.roundRect(x, y, barW, barH, [3, 3, 0, 0]);
    ctx.fill();

    // X label: short date (day/month)
    const parts = d.date.split('-');
    const label = `${parts[2]}/${parts[1]}`;
    ctx.fillStyle = colorMuted;
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(label, x + barW / 2, H - PAD.bottom + 14);
  });

  // Tooltip on hover
  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    let hit = null;
    data.forEach((d, i) => {
      const x = PAD.left + i * (barW + gap);
      if (mx >= x && mx <= x + barW && my >= PAD.top && my <= PAD.top + chartH) {
        hit = { d, x, i };
      }
    });

    // Redraw to clear previous tooltip
    canvas.onmousemove._redrawBase && canvas.onmousemove._redrawBase();

    if (hit) {
      const tx = hit.x + barW / 2;
      const ty = PAD.top + 8;
      const label = `${hit.d.date}  ${formatBytes(hit.d.bytes)}`;
      ctx.font = 'bold 11px sans-serif';
      const tw = ctx.measureText(label).width + 16;
      const th = 22;
      const bx = Math.min(Math.max(tx - tw / 2, 4), W - tw - 4);

      ctx.fillStyle = 'rgba(15,23,42,0.85)';
      ctx.beginPath();
      ctx.roundRect(bx, ty, tw, th, 4);
      ctx.fill();

      ctx.fillStyle = '#fff';
      ctx.textAlign = 'left';
      ctx.fillText(label, bx + 8, ty + 15);
    }
  };

  // Store redraw function for tooltip clear
  const redraw = () => renderVolumeChart(data);
  canvas.onmousemove._redrawBase = redraw;
  canvas.onmouseleave = redraw;
}
