/* CYBERTRACE AI — Log Analysis JavaScript */

let currentPage = 1;
let totalPages = 1;
let searchTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  loadLogStats();
  loadLogs(1);
  document.getElementById('search-input')?.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadLogs(1), 350);
  });
});

function buildFilterParams(page = 1) {
  const params = new URLSearchParams({ page, per_page: 50 });
  const vals = {
    case_id: 'filter-case-id',
    event_type: 'filter-event-type',
    severity: 'filter-severity',
    source_ip: 'filter-ip',
    username: 'filter-username',
    search: 'search-input',
    start_date: 'filter-start-date',
    end_date: 'filter-end-date'
  };
  for (const [key, elemId] of Object.entries(vals)) {
    const val = document.getElementById(elemId)?.value?.trim();
    if (val) params.set(key, val);
  }
  return params;
}

async function loadLogs(page = 1) {
  currentPage = page;
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="spinner" style="margin:0 auto;"></div></td></tr>`;

  try {
    const params = buildFilterParams(page);
    const data = await apiRequest('/api/logs/list?' + params.toString());
    totalPages = data.pages || 1;

    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="empty-icon">📋</div><div>No log records found</div><div style="font-size:.8rem;color:var(--text-muted);margin-top:.3rem;">Upload and analyze evidence files to populate logs</div></td></tr>`;
      renderPagination(0, 0, 0);
      return;
    }

    tbody.innerHTML = data.logs.map(r => `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem;white-space:nowrap;">${formatTimestamp(r.timestamp)}</td>
        <td><span class="code-text">${escapeHtml(r.source_ip || '—')}</span></td>
        <td>${escapeHtml(r.username || '—')}</td>
        <td><span class="badge ${getEventTypeClass(r.event_type)}">${formatEventType(r.event_type)}</span></td>
        <td title="${escapeHtml(r.event_description)}">${escapeHtml(r.event_description?.substring(0, 60) || '—')}${r.event_description?.length > 60 ? '…' : ''}</td>
        <td><span class="badge ${getSeverityClass(r.severity)}">${r.severity}</span></td>
        <td>${r.is_suspicious ? '<span style="color:var(--accent-red);">⚠️ Yes</span>' : '<span style="color:var(--text-muted);">—</span>'}</td>
        <td>
          <button class="btn btn-sm btn-ghost" onclick="toggleRaw(${r.id})" title="Toggle raw log">👁</button>
        </td>
      </tr>
      <tr id="raw-${r.id}" style="display:none;">
        <td colspan="8" style="padding:.5rem 1rem;background:var(--bg-secondary);">
          <code style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--accent-green);word-break:break-all;white-space:pre-wrap;">${escapeHtml(r.raw_log || 'No raw log available')}</code>
        </td>
      </tr>`).join('');

    renderPagination(data.page, data.pages, data.total);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:var(--accent-red);">Error: ${e.message}</td></tr>`;
  }
}

function toggleRaw(id) {
  const row = document.getElementById(`raw-${id}`);
  if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}

function renderPagination(page, pages, total) {
  const container = document.getElementById('pagination-container');
  if (!container) return;
  if (pages <= 1) { container.innerHTML = `<div class="pagination-info">${total} records</div>`; return; }

  let html = `<div class="pagination">`;
  html += `<button class="pagination-btn" onclick="loadLogs(${page - 1})" ${page <= 1 ? 'disabled' : ''}>‹ Prev</button>`;
  const start = Math.max(1, page - 2);
  const end = Math.min(pages, page + 2);
  if (start > 1) html += `<button class="pagination-btn" onclick="loadLogs(1)">1</button>${start > 2 ? '<span class="pagination-info">…</span>' : ''}`;
  for (let p = start; p <= end; p++) {
    html += `<button class="pagination-btn ${p === page ? 'active' : ''}" onclick="loadLogs(${p})">${p}</button>`;
  }
  if (end < pages) html += `${end < pages - 1 ? '<span class="pagination-info">…</span>' : ''}<button class="pagination-btn" onclick="loadLogs(${pages})">${pages}</button>`;
  html += `<button class="pagination-btn" onclick="loadLogs(${page + 1})" ${page >= pages ? 'disabled' : ''}>Next ›</button>`;
  html += `<span class="pagination-info">${total} total records</span></div>`;
  container.innerHTML = html;
}

async function loadLogStats() {
  try {
    const data = await apiRequest('/api/logs/stats');
    setStatVal('stat-total', data.total);
    setStatVal('stat-suspicious', data.suspicious);
    setStatVal('stat-failed', data.failed_logins);
    setStatVal('stat-critical', data.critical);
  } catch (e) { console.error('Stats error:', e); }
}

function setStatVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val || 0;
}

function getEventTypeClass(type) {
  const map = {
    login_success: 'badge-success', login_failure: 'badge-high',
    file_access: 'badge-low', process_exec: 'badge-medium',
    network_conn: 'badge-info', privilege_escalation: 'badge-critical',
    data_transfer: 'badge-medium', system_event: 'badge-info'
  };
  return map[type] || 'badge-info';
}

function formatEventType(type) {
  return (type || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

async function exportLogs() {
  const params = buildFilterParams(1);
  window.location.href = '/api/logs/export?' + params.toString();
}

function applyFilters() { loadLogs(1); loadLogStats(); }
function resetFilters() {
  ['filter-case-id', 'filter-event-type', 'filter-severity', 'filter-ip', 'filter-username',
   'search-input', 'filter-start-date', 'filter-end-date'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  loadLogs(1);
  loadLogStats();
}
