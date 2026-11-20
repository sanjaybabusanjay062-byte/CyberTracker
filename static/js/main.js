/* ================================================================
   CYBERTRACE AI — Global JavaScript Utilities
   ================================================================ */

// ── CSRF Token ──────────────────────────────────────────────────
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

// ── API Request Wrapper ─────────────────────────────────────────
async function apiRequest(url, method = 'GET', data = null, isFormData = false) {
  const options = {
    method,
    headers: {}
  };
  if (method !== 'GET') {
    options.headers['X-CSRFToken'] = getCsrfToken();
  }
  if (data && !isFormData) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(data);
  } else if (data && isFormData) {
    options.body = data; // FormData — no Content-Type header needed
  }
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      let errMsg = `HTTP ${response.status}`;
      try {
        const errData = await response.json();
        errMsg = errData.error || errMsg;
      } catch (_) {}
      throw new Error(errMsg);
    }
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('application/json')) {
      return await response.json();
    }
    return response;
  } catch (err) {
    console.error(`API Error [${method} ${url}]:`, err);
    throw err;
  }
}

// ── Toast Notifications ─────────────────────────────────────────
function showNotification(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span class="toast-msg">${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('hiding');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ── Loading Overlay ─────────────────────────────────────────────
function showLoading(text = 'Processing…') {
  // Try the base.html overlay first, then create a fallback
  let overlay = document.getElementById('loadingOverlay') || document.getElementById('loading-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'loading-overlay';
    overlay.className = 'loading-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(10,14,26,.8);display:flex;align-items:center;justify-content:center;z-index:2000;flex-direction:column;gap:1rem;';
    overlay.innerHTML = `<div class="cyber-spinner"></div><div id="loading-msg" style="font-size:.88rem;color:#8892a4;">Processing…</div>`;
    document.body.appendChild(overlay);
  }
  const msgEl = overlay.querySelector('#loading-msg, .loading-message, #loadingMessage');
  if (msgEl) msgEl.textContent = text;
  overlay.classList.add('active');
  overlay.style.display = 'flex';
}
function hideLoading() {
  const overlay = document.getElementById('loadingOverlay') || document.getElementById('loading-overlay');
  if (overlay) { overlay.classList.remove('active'); overlay.style.display = 'none'; }
}

// ── Utilities ───────────────────────────────────────────────────
function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-GB', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  } catch (_) { return ts; }
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let size = bytes;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return `${size.toFixed(1)} ${units[i]}`;
}

function getSeverityClass(severity) {
  const map = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info'
  };
  return map[severity] || 'badge-info';
}

function getStatusClass(status) {
  const map = {
    open: 'badge-open', active: 'badge-active', closed: 'badge-closed',
    archived: 'badge-info', new: 'badge-new', investigating: 'badge-investigating',
    resolved: 'badge-resolved', false_positive: 'badge-false_positive',
    stored: 'badge-low', analyzed: 'badge-success', deleted: 'badge-info'
  };
  return map[status] || 'badge-info';
}

function truncateHash(hash, len = 16) {
  return hash ? `${hash.substring(0, len)}…` : '—';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

function confirmDialog(message) {
  return new Promise(resolve => {
    // Simple browser confirm for now
    resolve(window.confirm(message));
  });
}

// ── Flash Messages Auto-Dismiss ─────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.flash-msg').forEach(el => {
    setTimeout(() => {
      el.style.transition = 'opacity .4s ease';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 450);
    }, 4000);
  });

  // Sidebar active state
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-item').forEach(link => {
    const href = link.getAttribute('href');
    if (href && (currentPath === href || (href !== '/' && currentPath.startsWith(href)))) {
      link.classList.add('active');
    }
  });
});
