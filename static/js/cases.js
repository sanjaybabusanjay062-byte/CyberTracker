/* CYBERTRACE AI — Case Management JavaScript */

let selectedCaseId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadCases();
});

async function loadCases() {
  const tbody = document.getElementById('cases-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><div class="spinner" style="margin:0 auto;"></div></td></tr>`;

  try {
    const params = new URLSearchParams({ page: 1, per_page: 50 });
    const st = document.getElementById('filter-status')?.value;
    const pr = document.getElementById('filter-priority')?.value;
    if (st) params.set('status', st);
    if (pr) params.set('priority', pr);

    const data = await apiRequest('/api/cases/list?' + params.toString());
    if (!data.cases || data.cases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><div class="empty-icon">📁</div><div>No cases found</div><div style="font-size:.8rem;color:var(--text-muted);margin-top:.3rem;">Create your first investigation case</div></td></tr>`;
      return;
    }

    tbody.innerHTML = data.cases.map(c => `
      <tr style="cursor:pointer;" onclick="viewCase(${c.id})">
        <td><span class="code-text">${escapeHtml(c.case_id)}</span></td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(c.title)}">${escapeHtml(c.title)}</td>
        <td>${escapeHtml(c.investigator_name || '—')}</td>
        <td><span class="badge ${getStatusClass(c.status)}">${c.status}</span></td>
        <td><span class="badge ${getPriorityClass(c.priority)}">${c.priority}</span></td>
        <td>${c.evidence_count || 0}</td>
        <td>${c.alerts_count || 0}</td>
        <td style="font-size:.72rem;">${formatTimestamp(c.created_at)}</td>
        <td onclick="event.stopPropagation()">
          <div style="display:flex;gap:.4rem;">
            <button class="btn btn-sm btn-ghost" onclick="viewCase(${c.id})" title="View details">🔍</button>
            <button class="btn btn-sm btn-danger" onclick="archiveCase(${c.id})" title="Archive">🗄️</button>
          </div>
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state" style="color:var(--accent-red);">Error: ${e.message}</td></tr>`;
  }
}

async function viewCase(id) {
  selectedCaseId = id;
  const panel = document.getElementById('case-detail-panel');
  if (!panel) return;
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  document.getElementById('detail-meta').innerHTML = '<span style="color:var(--text-muted)">Loading…</span>';
  document.getElementById('detail-evidence').innerHTML = '';
  document.getElementById('notes-list').innerHTML = '';

  try {
    const c = await apiRequest(`/api/cases/${id}`);
    document.getElementById('detail-case-id').textContent = `${c.case_id} — ${c.title}`;
    document.getElementById('detail-status-select').value = c.status;

    document.getElementById('detail-meta').innerHTML = `
      <span class="meta-label">Case ID</span><span class="meta-value code-text">${escapeHtml(c.case_id)}</span>
      <span class="meta-label">Status</span><span class="meta-value"><span class="badge ${getStatusClass(c.status)}">${c.status}</span></span>
      <span class="meta-label">Priority</span><span class="meta-value"><span class="badge ${getPriorityClass(c.priority)}">${c.priority}</span></span>
      <span class="meta-label">Investigator</span><span class="meta-value">${escapeHtml(c.investigator_name || '—')}</span>
      <span class="meta-label">Created</span><span class="meta-value">${formatTimestamp(c.created_at)}</span>
      <span class="meta-label">Updated</span><span class="meta-value">${formatTimestamp(c.updated_at)}</span>
      <span class="meta-label">Description</span><span class="meta-value">${escapeHtml(c.description || '—')}</span>`;

    // Evidence list
    const evDiv = document.getElementById('detail-evidence');
    if (c.evidence && c.evidence.length > 0) {
      evDiv.innerHTML = c.evidence.map(ev => `
        <div style="display:flex;align-items:center;gap:.6rem;padding:.5rem;background:var(--bg-secondary);border-radius:6px;margin-bottom:.4rem;font-size:.8rem;">
          <span>📄</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(ev.original_filename)}</span>
          <span class="badge ${getStatusClass(ev.status)}">${ev.status}</span>
        </div>`).join('');
    } else {
      evDiv.innerHTML = `<div style="color:var(--text-muted);font-size:.82rem;">No evidence files uploaded</div>`;
    }

    loadNotes(id);
  } catch (e) {
    document.getElementById('detail-meta').innerHTML = `<span style="color:var(--accent-red);">Error: ${e.message}</span>`;
  }
}

async function loadNotes(caseId) {
  try {
    const data = await apiRequest(`/api/cases/${caseId}/notes`);
    const container = document.getElementById('notes-list');
    if (!data.notes || data.notes.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted);font-size:.82rem;text-align:center;padding:1rem;">No notes yet</div>`;
      return;
    }
    container.innerHTML = data.notes.map(n => `
      <div style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;padding:.6rem .9rem;margin-bottom:.5rem;">
        <div style="display:flex;justify-content:space-between;margin-bottom:.25rem;">
          <span style="font-size:.72rem;color:var(--accent-cyan);">${n.note_type?.replace(/_/g, ' ').toUpperCase() || 'NOTE'}</span>
          <span style="font-size:.72rem;color:var(--text-muted);">${formatTimestamp(n.timestamp)}</span>
        </div>
        <div style="font-size:.82rem;color:var(--text-secondary);">${escapeHtml(n.content)}</div>
        <div style="font-size:.72rem;color:var(--text-muted);margin-top:.2rem;">— ${escapeHtml(n.author_name || 'Unknown')}</div>
      </div>`).join('');
  } catch (e) { console.error('Notes error:', e); }
}

async function addNote() {
  if (!selectedCaseId) return;
  const content = document.getElementById('new-note-content')?.value.trim();
  const noteType = document.getElementById('note-type')?.value;
  if (!content) { showNotification('Note content is required', 'error'); return; }
  try {
    await apiRequest(`/api/cases/${selectedCaseId}/notes`, 'POST', { content, note_type: noteType });
    document.getElementById('new-note-content').value = '';
    loadNotes(selectedCaseId);
    showNotification('Note added', 'success');
  } catch (e) {
    showNotification('Failed to add note: ' + e.message, 'error');
  }
}

async function updateCaseStatus() {
  if (!selectedCaseId) return;
  const status = document.getElementById('detail-status-select')?.value;
  try {
    await apiRequest(`/api/cases/${selectedCaseId}`, 'PATCH', { status });
    showNotification(`Case status updated to: ${status}`, 'success');
    loadCases();
  } catch (e) {
    showNotification('Update failed: ' + e.message, 'error');
  }
}

async function archiveCase(id) {
  const confirmed = await confirmDialog('Archive this case? It will be hidden from active investigations.');
  if (!confirmed) return;
  try {
    await apiRequest(`/api/cases/${id}`, 'DELETE');
    showNotification('Case archived', 'info');
    loadCases();
    if (selectedCaseId === id) closeCaseDetail();
  } catch (e) {
    showNotification('Archive failed: ' + e.message, 'error');
  }
}

function closeCaseDetail() {
  document.getElementById('case-detail-panel').style.display = 'none';
  selectedCaseId = null;
}

function openNewCaseModal() { document.getElementById('new-case-modal').style.display = 'flex'; }
function closeNewCaseModal() { document.getElementById('new-case-modal').style.display = 'none'; }

async function createCase() {
  const title = document.getElementById('new-case-title')?.value.trim();
  if (!title) { showNotification('Case title is required', 'error'); return; }
  try {
    showLoading('Creating case…');
    await apiRequest('/api/cases', 'POST', {
      title,
      description: document.getElementById('new-case-desc')?.value || '',
      priority: document.getElementById('new-case-priority')?.value || 'medium'
    });
    hideLoading();
    showNotification('Case created!', 'success');
    closeNewCaseModal();
    document.getElementById('new-case-title').value = '';
    document.getElementById('new-case-desc').value = '';
    loadCases();
  } catch (e) {
    hideLoading();
    showNotification('Failed: ' + e.message, 'error');
  }
}

function getPriorityClass(priority) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
  return map[priority] || 'badge-info';
}
