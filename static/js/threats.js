/* CYBERTRACE AI — Threat Detection JavaScript */

let currentPage = 1;
let threatChart = null;

document.addEventListener('DOMContentLoaded', () => {
  loadThreats(1);
  loadThreatStats();
});

async function loadThreats(page = 1) {
  currentPage = page;
  const tbody = document.getElementById('threats-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="spinner" style="margin:0 auto;"></div></td></tr>`;

  try {
    const params = new URLSearchParams({ page, per_page: 50 });
    const vals = { case_id: 'filter-case-id', severity: 'filter-severity', alert_type: 'filter-type', status: 'filter-status' };
    for (const [k, id] of Object.entries(vals)) {
      const v = document.getElementById(id)?.value;
      if (v) params.set(k, v);
    }

    const data = await apiRequest('/api/threats/list?' + params.toString());
    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="empty-icon">🛡️</div><div>No threat alerts found</div><div style="font-size:.8rem;color:var(--text-muted);margin-top:.3rem;">Run a threat scan on a case to detect suspicious activity</div></td></tr>`;
      return;
    }

    tbody.innerHTML = data.alerts.map(a => `
      <tr>
        <td><span class="code-text">${escapeHtml(a.alert_id)}</span></td>
        <td><span class="badge ${getSeverityClass(a.severity)}">${a.severity}</span></td>
        <td>${formatAlertType(a.alert_type)}</td>
        <td title="${escapeHtml(a.description)}">${escapeHtml(a.description?.substring(0, 65) || '—')}${a.description?.length > 65 ? '…' : ''}</td>
        <td><span class="code-text">${escapeHtml(a.source_ip || '—')}</span></td>
        <td>${escapeHtml(a.username || '—')}</td>
        <td style="font-size:.72rem;">${formatTimestamp(a.timestamp)}</td>
        <td>
          <select class="form-control" style="padding:.2rem .5rem;font-size:.75rem;width:140px;" onchange="updateStatus(${a.id}, this.value)">
            <option value="new" ${a.status === 'new' ? 'selected' : ''}>🔴 New</option>
            <option value="investigating" ${a.status === 'investigating' ? 'selected' : ''}>🟡 Investigating</option>
            <option value="resolved" ${a.status === 'resolved' ? 'selected' : ''}>🟢 Resolved</option>
            <option value="false_positive" ${a.status === 'false_positive' ? 'selected' : ''}>⚪ False Positive</option>
          </select>
        </td>
      </tr>`).join('');

    renderThreatPagination(data.page, data.pages, data.total);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:var(--accent-red);">Error: ${e.message}</td></tr>`;
  }
}

async function runScan() {
  const caseId = document.getElementById('scan-case-id')?.value;
  if (!caseId) { showNotification('Please select a case to scan', 'error'); return; }

  const btn = document.getElementById('scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = '🔍 Scanning…'; }
  showLoading('Running threat detection algorithms…');

  try {
    const data = await apiRequest(`/api/threats/scan/${caseId}`, 'POST');
    hideLoading();
    showNotification(`Scan complete: ${data.alerts_created} new alert(s) detected`, data.alerts_created > 0 ? 'warning' : 'success');
    loadThreats(1);
    loadThreatStats();
  } catch (e) {
    hideLoading();
    showNotification('Scan failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🔍 Run Threat Scan'; }
  }
}

async function updateStatus(alertId, status) {
  try {
    await apiRequest(`/api/threats/${alertId}/status`, 'PATCH', { status });
    showNotification(`Alert status updated to: ${status}`, 'success');
    loadThreatStats();
  } catch (e) {
    showNotification('Update failed: ' + e.message, 'error');
  }
}

async function loadThreatStats() {
  try {
    const data = await apiRequest('/api/threats/stats');
    setEl('stat-total', data.total);
    setEl('stat-investigating', data.investigating);

    const critical = data.by_severity?.critical || 0;
    const high = data.by_severity?.high || 0;
    setEl('stat-critical', critical + high);

    const ctx = document.getElementById('threat-type-chart');
    if (ctx && Object.keys(data.by_type || {}).length) {
      if (threatChart) threatChart.destroy();
      const labels = Object.keys(data.by_type).map(t => formatAlertType(t));
      const values = Object.values(data.by_type);
      const colors = ['#ff4757','#ffa502','#ffd32a','#00d4ff','#00ff88','#a855f7','#3b82f6'];
      threatChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{ data: values, backgroundColor: colors.slice(0, values.length), borderRadius: 4 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: { backgroundColor: '#162032', titleColor: '#e8f0fe', bodyColor: '#8892a4', borderColor: '#1e2d3d', borderWidth: 1 } },
          scales: {
            x: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { color: 'rgba(30,45,61,0.5)' } },
            y: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { color: 'rgba(30,45,61,0.5)' }, beginAtZero: true }
          }
        }
      });
    }
  } catch (e) { console.error('Stats error:', e); }
}

function renderThreatPagination(page, pages, total) {
  const container = document.getElementById('threat-pagination');
  if (!container) return;
  if (pages <= 1) { container.innerHTML = `<div class="pagination-info">${total} alerts</div>`; return; }
  let html = `<div class="pagination">`;
  html += `<button class="pagination-btn" onclick="loadThreats(${page - 1})" ${page <= 1 ? 'disabled' : ''}>‹</button>`;
  for (let p = Math.max(1, page - 2); p <= Math.min(pages, page + 2); p++) {
    html += `<button class="pagination-btn ${p === page ? 'active' : ''}" onclick="loadThreats(${p})">${p}</button>`;
  }
  html += `<button class="pagination-btn" onclick="loadThreats(${page + 1})" ${page >= pages ? 'disabled' : ''}>›</button>`;
  html += `<span class="pagination-info">${total} total</span></div>`;
  container.innerHTML = html;
}

function formatAlertType(type) {
  const labels = {
    brute_force: 'Brute Force', off_hours_access: 'Off-Hours Access',
    privilege_escalation: 'Privilege Escalation', data_exfiltration: 'Data Exfiltration',
    lateral_movement: 'Lateral Movement', suspicious_process: 'Suspicious Process',
    unusual_ip: 'Unusual IP'
  };
  return labels[type] || (type || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val || 0;
}

function applyFilters() { loadThreats(1); }
