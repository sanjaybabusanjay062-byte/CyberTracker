/* CYBERTRACE AI — Forensic Log Analysis JavaScript */

let currentPage = 1;
let totalPages = 1;
let searchDebounceTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  loadCaseOptions();
  loadEvidenceParserOptions();
  loadLogStats();
  loadLogs(1);

  // Filter form submission
  const filterForm = document.getElementById('logFilterForm');
  if (filterForm) {
    filterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      loadLogs(1);
    });
  }

  // Reset filters
  const resetBtn = document.getElementById('resetFiltersBtn');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (filterForm) filterForm.reset();
      loadLogs(1);
    });
  }

  // Export CSV
  const exportBtn = document.getElementById('exportCsvBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const params = buildFilterQueryString();
      window.location.href = '/api/logs/export?' + params.toString();
      showNotification('Exporting filtered telemetry to CSV...', 'info');
    });
  }

  // Evidence Parser Trigger
  const parseBtn = document.getElementById('triggerParseBtn');
  if (parseBtn) {
    parseBtn.addEventListener('click', async () => {
      const evId = document.getElementById('triggerEvidenceSelect')?.value;
      if (!evId) {
        showNotification('Please select an ingested evidence file to parse', 'warning');
        return;
      }
      showLoading('Parsing raw evidence log file & indexing normalized events...');
      try {
        const res = await apiRequest(`/api/logs/parse/${evId}`, 'POST');
        hideLoading();
        showNotification(`Parsed and indexed ${res.records_parsed || 0} events!`, 'success');
        loadLogStats();
        loadLogs(1);
      } catch (err) {
        hideLoading();
        showNotification('Log parsing failed: ' + err.message, 'error');
      }
    });
  }

  // Debounced search input
  const searchInput = document.getElementById('logSearchQuery') || document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => loadLogs(1), 300);
    });
  }

  // Pagination navigation
  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  if (prevBtn) prevBtn.addEventListener('click', () => { if (currentPage > 1) loadLogs(currentPage - 1); });
  if (nextBtn) nextBtn.addEventListener('click', () => { if (currentPage < totalPages) loadLogs(currentPage + 1); });
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('logCaseFilter') || document.getElementById('filter-case-id');
    if (sel && data.cases) {
      data.cases.forEach(c => {
        sel.add(new Option(`${c.case_id} — ${c.title.substring(0, 36)}`, c.id));
      });
    }
  } catch (e) {
    console.error('Failed to load case options:', e);
  }
}

async function loadEvidenceParserOptions() {
  try {
    const data = await apiRequest('/api/evidence/list');
    const sel = document.getElementById('triggerEvidenceSelect');
    if (sel && data.evidence) {
      data.evidence.forEach(e => {
        sel.add(new Option(`${e.evidence_id} (${e.original_filename})`, e.id));
      });
    }
  } catch (e) {
    console.error('Failed to load evidence parser options:', e);
  }
}

async function loadLogStats() {
  try {
    const data = await apiRequest('/api/logs/stats');
    setStatText('logStatTotal', data.total);
    setStatText('logStatSuspicious', data.suspicious);
    setStatText('logStatFailedLogins', data.failed_logins);
    setStatText('logStatCritical', data.critical);
  } catch (e) {
    console.error('Failed to load log stats:', e);
  }
}

function setStatText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? 0;
}

function buildFilterQueryString(page = 1) {
  const params = new URLSearchParams({ page, per_page: 50 });

  const caseId = (document.getElementById('logCaseFilter') || document.getElementById('filter-case-id'))?.value;
  const eventType = (document.getElementById('logEventTypeFilter') || document.getElementById('filter-event-type'))?.value;
  const severity = (document.getElementById('logSeverityFilter') || document.getElementById('filter-severity'))?.value;
  const ip = (document.getElementById('logIpFilter') || document.getElementById('filter-ip'))?.value?.trim();
  const user = (document.getElementById('logUserFilter') || document.getElementById('filter-username'))?.value?.trim();
  const search = (document.getElementById('logSearchQuery') || document.getElementById('search-input'))?.value?.trim();
  const dateRange = (document.getElementById('logDateRange'))?.value;

  if (caseId) params.set('case_id', caseId);
  if (eventType) params.set('event_type', eventType);
  if (severity) params.set('severity', severity);
  if (ip) params.set('source_ip', ip);
  if (user) params.set('username', user);
  if (search) params.set('search', search);

  if (dateRange === '24h') {
    const d = new Date(Date.now() - 24 * 3600 * 1000);
    params.set('start_date', d.toISOString());
  } else if (dateRange === '7d') {
    const d = new Date(Date.now() - 7 * 24 * 3600 * 1000);
    params.set('start_date', d.toISOString());
  } else if (dateRange === '30d') {
    const d = new Date(Date.now() - 30 * 24 * 3600 * 1000);
    params.set('start_date', d.toISOString());
  }

  return params;
}

async function loadLogs(page = 1) {
  currentPage = page;
  const tbody = document.getElementById('logsTableBody') || document.getElementById('logs-tbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="7" class="table-empty-cell" style="text-align:center;padding:2rem;"><div class="inline-spinner"></div> Querying forensic log index...</td></tr>`;

  try {
    const params = buildFilterQueryString(page);
    const data = await apiRequest('/api/logs/list?' + params.toString());
    totalPages = data.pages || 1;

    // Update pagination displays
    updatePaginationUI(data.page, data.pages, data.total);

    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="table-empty-cell" style="text-align:center;padding:2.5rem;color:#8892a4;">
        <div style="font-size:2rem;margin-bottom:.5rem;">📋</div>
        <div>No forensic events matched your query.</div>
      </td></tr>`;
      return;
    }

    tbody.innerHTML = data.logs.map(r => `
      <tr class="${r.is_suspicious ? 'table-row-suspicious' : ''}">
        <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem;white-space:nowrap;color:#8892a4;">
          ${formatTimestamp(r.timestamp)}
        </td>
        <td>
          <span class="code-text" style="color:#00d4ff;">${escapeHtml(r.source_ip || '—')}</span>
        </td>
        <td>
          <span style="font-weight:500;color:#e8f0fe;">${escapeHtml(r.username || '—')}</span>
        </td>
        <td>
          <span class="badge ${getEventTypeBadgeClass(r.event_type)}">${escapeHtml(formatEventType(r.event_type))}</span>
          ${r.is_suspicious ? '<span class="badge badge-critical" style="margin-left:.25rem;">FLAG</span>' : ''}
        </td>
        <td>
          <div style="color:#e8f0fe;font-size:.82rem;">${escapeHtml(r.event_description || '—')}</div>
          ${r.threat_category ? `<div style="font-size:.72rem;color:#ffa502;">ATT&CK: ${escapeHtml(r.threat_category)}</div>` : ''}
        </td>
        <td>
          <span class="badge ${getSeverityBadgeClass(r.severity)}">${escapeHtml(r.severity?.toUpperCase() || 'INFO')}</span>
        </td>
        <td style="text-align:center;">
          <button class="btn btn-xs btn-secondary" onclick="toggleRawModal(${r.id})" title="Inspect Raw Log Payload">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
          </button>
        </td>
      </tr>
      <tr id="raw-row-${r.id}" style="display:none;background:#0d1117;">
        <td colspan="7" style="padding:.6rem 1rem;border-left:3px solid #00d4ff;">
          <div style="font-size:.72rem;color:#8892a4;margin-bottom:.3rem;">RAW EVENT TELEMETRY // ID: ${r.id}</div>
          <pre style="margin:0;font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#00ff88;word-break:break-all;white-space:pre-wrap;">${escapeHtml(r.raw_log || r.event_description || 'No raw payload stored')}</pre>
        </td>
      </tr>
    `).join('');

  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-empty-cell" style="color:#ff4757;text-align:center;">Error querying log stream: ${e.message}</td></tr>`;
  }
}

function toggleRawModal(id) {
  const row = document.getElementById(`raw-row-${id}`);
  if (row) {
    row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
  }
}

function updatePaginationUI(page, pages, total) {
  const countDisplay = document.getElementById('tableRecordCountDisplay');
  if (countDisplay) countDisplay.textContent = `Displaying ${total} indexed forensic records`;

  const pageInfo = document.getElementById('pageInfoText');
  if (pageInfo) pageInfo.textContent = `Page ${page} of ${pages || 1}`;

  const totalEvents = document.getElementById('totalEventsCount');
  if (totalEvents) totalEvents.textContent = `${total} Events Indexed`;

  const currPagePill = document.getElementById('currentPageNum');
  if (currPagePill) currPagePill.textContent = page;

  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  if (prevBtn) prevBtn.disabled = page <= 1;
  if (nextBtn) nextBtn.disabled = page >= pages;
}

function getSeverityBadgeClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

function getEventTypeBadgeClass(etype) {
  const t = (etype || '').toLowerCase();
  if (t.includes('fail') || t.includes('block')) return 'badge-critical';
  if (t.includes('priv') || t.includes('escal')) return 'badge-high';
  if (t.includes('success') || t.includes('allow')) return 'badge-success';
  if (t.includes('c2') || t.includes('exfil')) return 'badge-critical';
  return 'badge-info';
}

function formatEventType(etype) {
  if (!etype) return 'Generic Event';
  return etype.replace(/_/g, ' ').toUpperCase();
}
