/* CYBERTRACE AI — Reports JavaScript */

document.addEventListener('DOMContentLoaded', () => {
  loadReports();
});

async function generateReport() {
  const caseId = document.getElementById('report-case-id')?.value;
  const reportType = document.getElementById('report-type')?.value;
  if (!caseId) { showNotification('Please select a case', 'error'); return; }

  const btn = document.getElementById('generate-btn');
  if (btn) { btn.disabled = true; }
  document.getElementById('generate-btn-text').textContent = '⏳ Generating…';
  showLoading('Generating forensic PDF report…');

  try {
    const data = await apiRequest('/api/reports/generate', 'POST', { case_id: caseId, report_type: reportType });
    hideLoading();
    if (btn) btn.disabled = false;
    document.getElementById('generate-btn-text').textContent = '🔄 Generate PDF Report';

    // Show success modal
    document.getElementById('success-report-name').textContent = data.filename;
    document.getElementById('download-btn').onclick = () => { window.location.href = data.download_url; };
    document.getElementById('report-success-modal').style.display = 'flex';
    showNotification('Report generated successfully!', 'success');
    loadReports();
  } catch (e) {
    hideLoading();
    if (btn) btn.disabled = false;
    document.getElementById('generate-btn-text').textContent = '🔄 Generate PDF Report';
    showNotification('Report generation failed: ' + e.message, 'error');
  }
}

async function loadReports() {
  const tbody = document.getElementById('reports-tbody');
  if (!tbody) return;

  try {
    const data = await apiRequest('/api/reports/list');
    if (!data.reports || data.reports.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">
        <div class="empty-icon">📄</div>
        <div>No reports generated yet</div>
        <div style="font-size:.8rem;margin-top:.3rem;color:var(--text-muted)">Select a case and generate your first report</div>
      </td></tr>`;
      return;
    }

    tbody.innerHTML = data.reports.map(r => `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.75rem;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(r.filename)}">
          📄 ${escapeHtml(r.filename)}
        </td>
        <td style="font-size:.75rem;">${formatTimestamp(r.created_at)}</td>
        <td>${formatFileSize(r.file_size)}</td>
        <td>
          <div style="display:flex;gap:.4rem;">
            <a href="${escapeHtml(r.download_url)}" class="btn btn-sm btn-primary" download>⬇ Download</a>
            <button class="btn btn-sm btn-danger" onclick="deleteReport('${escapeHtml(r.filename)}')">🗑️</button>
          </div>
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state" style="color:var(--accent-red);">Error: ${e.message}</td></tr>`;
  }
}

async function deleteReport(filename) {
  const confirmed = await confirmDialog(`Delete report "${filename}"? This cannot be undone.`);
  if (!confirmed) return;
  try {
    await apiRequest(`/api/reports/delete/${encodeURIComponent(filename)}`, 'DELETE');
    showNotification('Report deleted', 'info');
    loadReports();
  } catch (e) {
    showNotification('Delete failed: ' + e.message, 'error');
  }
}
