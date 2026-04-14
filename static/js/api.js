// Central API fetch wrapper
async function api(method, path, body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== null) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  if (res.status === 401) {
    window.location = '/login';
    return null;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Erreur inconnue' }));
    throw new Error(err.detail || 'Erreur serveur');
  }
  if (res.status === 204) return null;
  return res.json();
}

// Toast notifications
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity .3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Format bytes to human-readable
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Format ISO date to locale string
function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('fr-FR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch { return iso; }
}
