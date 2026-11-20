/* CYBERTRACE AI — Automated Threat Detection & Triage JavaScript */

let allAlerts = [];
let currentPage = 1;
let totalPages = 1;

document.addEventListener('DOMContentLoaded', () => {
  loadCaseOptions();
  loadThreatStats();
  loadThreats(1);

  // Run Threat Scan
  const scanBtn = document.getElementById('runThreatScanBtn') || document.getElementById('scan-btn');
  if (scanBtn) {
    scanBtn.addEventListener('click', runThreatScan);
  }

  // Refresh
  const refreshBtn = document.getElementById('refreshThreatsBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadThreatStats();
      loadThreats(currentPage);
      showNotification('Threat telemetry updated', 'info');
    });
  }

  // Filters
  const filters = ['filterThreatCase', 'filterThreatType', 'filterThreatSeverity', 'filterThreatStatus'];
  filters.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => loadThreats(1));
  });

  // Search input debounced
  const searchInput = document.getElementById('threatSearchInput');
  if (searchInput) {
    let timer = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => filterThreatsLocally(), 250);
    });
  }
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const scanSel = document.getElementById('scanCaseSelector') || document.getElementById('scan-case-id');
    const filterSel = document.getElementById('filterThreatCase');

    if (data.cases) {
      data.cases.forEach(c => {
        const titleStr = `${c.case_id} — ${c.title.substring(0, 36)}`;
        if (scanSel) scanSel.add(new Option(titleStr, c.id));
        if (filterSel) filterSel.add(new Option(titleStr, c.id));
      });
    }
  } catch (e) {
    console.error('Threat case options error:', e);
  }
}

async function loadThreatStats() {
  try {
    const data = await apiRequest('/api/threats/stats');
    setEl('threatStatTotal', data.total ?? 0);
    setEl('threatStatInvestigating', data.investigating ?? 0);

    const critical = data.by_severity?.critical ?? 0;
    const high = data.by_severity?.high ?? 0;
    setEl('threatStatCritical', critical);
    setEl('threatStatHigh', high);
  } catch (e) {
    console.error('Threat stats load error:', e);
  }
}

function buildThreatParams(page = 1) {
  const p = new URLSearchParams({ page, per_page: 50 });
  const caseId = document.getElementById('filterThreatCase')?.value;
  const etype = document.getElementById('filterThreatType')?.value;
  const sev = document.getElementById('filterThreatSeverity')?.value;
  const status = document.getElementById('filterThreatStatus')?.value;

  if (caseId) p.set('case_id', caseId);
  if (etype) p.set('alert_type', etype);
  if (sev) p.set('severity', sev);
  if (status) p.set('status', status);

  return p;
}

async function loadThreats(page = 1) {
  currentPage = page;
  const tbody = document.getElementById('threatsTableBody') || document.getElementById('threats-tbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="9" class="table-empty-cell" style="text-align:center;padding:2rem;"><div class="inline-spinner"></div> Querying threat alert repository...</td></tr>`;

  try {
    const params = buildThreatParams(page);
    const data = await apiRequest('/api/threats/list?' + params.toString());
    allAlerts = data.alerts || [];
    totalPages = data.pages || 1;

    filterThreatsLocally();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" class="table-empty-cell" style="color:#ff4757;text-align:center;">Error loading threat detections: ${err.message}</td></tr>`;
  }
}

function filterThreatsLocally() {
  const tbody = document.getElementById('threatsTableBody') || document.getElementById('threats-tbody');
  if (!tbody) return;

  const q = document.getElementById('threatSearchInput')?.value?.toLowerCase()?.trim();
  let alerts = allAlerts;

  if (q) {
    alerts = alerts.filter(a => 
      (a.alert_type && a.alert_type.toLowerCase().includes(q)) ||
      (a.description && a.description.toLowerCase().includes(q)) ||
      (a.source_ip && a.source_ip.toLowerCase().includes(q)) ||
      (a.username && a.username.toLowerCase().includes(q)) ||
      (a.alert_id && a.alert_id.toLowerCase().includes(q))
    );
  }

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="table-empty-cell" style="text-align:center;padding:2.5rem;color:#8892a4;">
      <div style="font-size:2rem;margin-bottom:.5rem;">🛡️</div>
      <div>No threat alerts found matching current filters.</div>
      <div style="font-size:.78rem;margin-top:.3rem;color:#64748b;">Select an incident docket above and run a heuristic threat scan.</div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="code-text" style="color:#00d4ff;font-weight:600;">${escapeHtml(a.alert_id)}</span></td>
      <td>
        <span class="badge ${getCategoryBadgeClass(a.alert_type)}">${escapeHtml(a.alert_type)}</span>
      </td>
      <td>
        <span class="badge ${getSeverityBadgeClass(a.severity)}">${escapeHtml(a.severity?.toUpperCase() || 'MEDIUM')}</span>
      </td>
      <td>
        <div style="font-weight:500;color:#e8f0fe;font-size:.82rem;">${escapeHtml(a.description)}</div>
        ${a.case_ref ? `<div style="font-size:.72rem;color:#8892a4;">Case: ${escapeHtml(a.case_ref)}</div>` : ''}
      </td>
      <td>
        <span class="code-text" style="color:${a.severity === 'critical' ? '#ff4757' : '#00d4ff'};">${escapeHtml(a.source_ip || '—')}</span>
      </td>
      <td>
        <span style="font-weight:500;color:#e8f0fe;">${escapeHtml(a.username || '—')}</span>
      </td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem;white-space:nowrap;color:#8892a4;">
        ${formatTimestamp(a.timestamp || a.detected_at)}
      </td>
      <td>
        <span class="badge ${getStatusBadgeClass(a.status)}">${escapeHtml(formatStatus(a.status))}</span>
      </td>
      <td style="text-align:right;">
        <select class="form-select form-select-xs" style="width:130px;display:inline-block;font-size:.74rem;padding:.2rem .4rem;" onchange="updateAlertStatus(${a.id}, this.value)">
          <option value="new" ${a.status === 'new' ? 'selected' : ''}>🔴 New</option>
          <option value="investigating" ${a.status === 'investigating' ? 'selected' : ''}>🟡 In Triage</option>
          <option value="resolved" ${a.status === 'resolved' ? 'selected' : ''}>🟢 Resolved</option>
          <option value="false_positive" ${a.status === 'false_positive' ? 'selected' : ''}>⚪ False Pos</option>
        </select>
      </td>
    </tr>
  `).join('');
}

async function runThreatScan() {
  const caseId = (document.getElementById('scanCaseSelector') || document.getElementById('scan-case-id'))?.value;
  if (!caseId) {
    showNotification('Please select an incident docket to scan', 'warning');
    return;
  }

  const btn = document.getElementById('runThreatScanBtn') || document.getElementById('scan-btn');
  if (btn) btn.disabled = true;

  showLoading('Evaluating heuristic threat detection rules & MITRE ATT&CK vectors...');

  try {
    const res = await apiRequest(`/api/threats/scan/${caseId}`, 'POST');
    hideLoading();
    if (btn) btn.disabled = false;

    showNotification(`Scan complete! ${res.alerts_created || 0} new threat alert(s) detected.`, res.alerts_created > 0 ? 'warning' : 'success');
    loadThreatStats();
    loadThreats(1);
  } catch (err) {
    hideLoading();
    if (btn) btn.disabled = false;
    showNotification('Threat scan failed: ' + err.message, 'error');
  }
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    await apiRequest(`/api/threats/${alertId}/status`, 'PATCH', { status: newStatus });
    showNotification(`Alert status updated to: ${formatStatus(newStatus)}`, 'success');
    loadThreatStats();
    loadThreats(currentPage);
  } catch (err) {
    showNotification('Failed to update alert status: ' + err.message, 'error');
  }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? 0;
}

function getCategoryBadgeClass(cat) {
  const c = (cat || '').toLowerCase();
  if (c.includes('brute') || c.includes('fail')) return 'badge-critical';
  if (c.includes('exfil') || c.includes('lateral')) return 'badge-critical';
  if (c.includes('privilege') || c.includes('escal')) return 'badge-high';
  if (c.includes('unusual') || c.includes('hours')) return 'badge-warning';
  return 'badge-info';
}

function getSeverityBadgeClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-warning';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

function getStatusBadgeClass(st) {
  const s = (st || '').toLowerCase();
  if (s === 'new') return 'badge-critical';
  if (s === 'investigating') return 'badge-warning';
  if (s === 'resolved') return 'badge-success';
  return 'badge-info';
}

function formatStatus(st) {
  if (!st) return 'New';
  return st.replace(/_/g, ' ').toUpperCase();
}
