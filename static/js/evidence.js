/* CYBERTRACE AI — Evidence Management JavaScript */

let currentPage = 1;
let evidenceData = [];

document.addEventListener('DOMContentLoaded', () => {
  loadCaseOptions();
  loadEvidence();
  initDropzone();
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('upload-case-id');
    const filterSel = document.getElementById('filter-case-id');
    if (sel && data.cases) {
      data.cases.forEach(c => {
        const opt = new Option(`${c.case_id} — ${c.title.substring(0, 40)}`, c.id);
        sel.add(opt.cloneNode(true));
        if (filterSel) filterSel.add(opt);
      });
    }
  } catch (e) { console.error('Case load error:', e); }
}

async function loadEvidence() {
  const tbody = document.getElementById('evidence-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><div class="spinner" style="margin:0 auto;"></div></td></tr>`;
  try {
    const params = new URLSearchParams();
    const caseId = document.getElementById('filter-case-id')?.value;
    const ft = document.getElementById('filter-type')?.value;
    const st = document.getElementById('filter-status')?.value;
    if (caseId) params.set('case_id', caseId);
    if (ft) params.set('file_type', ft);
    if (st) params.set('status', st);

    const data = await apiRequest('/api/evidence/list?' + params.toString());
    evidenceData = data.evidence || [];

    if (evidenceData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-state"><div class="empty-icon">🗂️</div><div>No evidence files uploaded yet</div><div style="font-size:.8rem;color:var(--text-muted);margin-top:.3rem;">Upload log files to begin analysis</div></td></tr>`;
      return;
    }
    tbody.innerHTML = evidenceData.map(ev => `
      <tr>
        <td><span class="code-text">${escapeHtml(ev.evidence_id)}</span></td>
        <td title="${escapeHtml(ev.original_filename)}">${escapeHtml(ev.original_filename.substring(0, 32))}${ev.original_filename.length > 32 ? '…' : ''}</td>
        <td>${escapeHtml(ev.case_reference || '—')}</td>
        <td><span class="hash-text" title="${escapeHtml(ev.sha256_hash)}">${truncateHash(ev.sha256_hash, 20)}</span></td>
        <td>${formatFileSize(ev.file_size)}</td>
        <td style="font-size:.75rem;">${formatTimestamp(ev.uploaded_at)}</td>
        <td><span class="badge ${getStatusClass(ev.status)}">${ev.status}</span></td>
        <td>
          ${ev.integrity_verified
            ? `<span class="integrity-ok" title="Integrity verified">✅ Verified</span>`
            : `<span class="integrity-fail" title="Integrity check failed">⛔ Modified</span>`}
        </td>
        <td>
          <div style="display:flex;gap:.4rem;flex-wrap:wrap;">
            <button class="btn btn-sm btn-ghost" onclick="showDetails(${ev.id})" title="View details">🔍</button>
            <button class="btn btn-sm btn-ghost" onclick="verifyIntegrity(${ev.id})" title="Verify SHA-256">🔐</button>
            <button class="btn btn-sm btn-ghost" onclick="analyzeEvidence(${ev.id})" title="Parse logs">⚙️</button>
            <button class="btn btn-sm btn-danger" onclick="deleteEvidence(${ev.id})" title="Delete">🗑️</button>
          </div>
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state" style="color:var(--accent-red);">Error loading evidence: ${e.message}</td></tr>`;
  }
}

function initDropzone() {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('file-input');
  if (!zone || !input) return;

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) handleFileSelect(input.files[0]);
  });
}

function handleFileSelect(file) {
  const info = document.getElementById('file-info');
  if (info) {
    info.innerHTML = `<div class="upload-file-info"><span>📄</span><span><strong>${escapeHtml(file.name)}</strong> — ${formatFileSize(file.size)}</span></div>`;
  }
}

async function uploadEvidence() {
  const input = document.getElementById('file-input');
  const caseId = document.getElementById('upload-case-id')?.value;
  const description = document.getElementById('upload-desc')?.value || '';

  if (!input?.files[0]) { showNotification('Please select a file', 'error'); return; }
  if (!caseId) { showNotification('Please select a case', 'error'); return; }

  const formData = new FormData();
  formData.append('file', input.files[0]);
  formData.append('case_id', caseId);
  formData.append('description', description);

  const btn = document.getElementById('upload-btn');
  const progress = document.getElementById('upload-progress');
  if (btn) { btn.disabled = true; btn.textContent = 'Uploading…'; }
  if (progress) { progress.style.display = 'block'; setProgress(30); }

  try {
    if (progress) setProgress(60);
    const data = await apiRequest('/api/evidence/upload', 'POST', formData, true);
    if (progress) setProgress(100);
    showNotification(`Evidence ${data.evidence.evidence_id} uploaded successfully!`, 'success');
    input.value = '';
    document.getElementById('file-info').innerHTML = '';
    loadEvidence();
  } catch (e) {
    showNotification('Upload failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⬆ Upload Evidence'; }
    setTimeout(() => { if (progress) { progress.style.display = 'none'; setProgress(0); } }, 1500);
  }
}

function setProgress(pct) {
  const bar = document.getElementById('progress-fill');
  if (bar) bar.style.width = pct + '%';
}

async function verifyIntegrity(id) {
  try {
    showLoading('Verifying file integrity…');
    const data = await apiRequest(`/api/evidence/${id}/verify`, 'POST');
    hideLoading();
    if (data.integrity) {
      showNotification('✅ Integrity verified — SHA-256 hash matches!', 'success');
    } else {
      showNotification('⛔ INTEGRITY VIOLATION — file has been modified!', 'error');
    }
    loadEvidence();
  } catch (e) {
    hideLoading();
    showNotification('Integrity check failed: ' + e.message, 'error');
  }
}

async function analyzeEvidence(id) {
  try {
    showLoading('Parsing log records…');
    const data = await apiRequest(`/api/evidence/${id}/analyze`, 'POST');
    hideLoading();
    showNotification(`Analysis complete: ${data.records_parsed} log records parsed`, 'success');
    loadEvidence();
  } catch (e) {
    hideLoading();
    showNotification('Analysis failed: ' + e.message, 'error');
  }
}

async function deleteEvidence(id) {
  const confirmed = await confirmDialog('Remove this evidence file from the case? This action cannot be undone.');
  if (!confirmed) return;
  try {
    await apiRequest(`/api/evidence/${id}`, 'DELETE');
    showNotification('Evidence removed', 'info');
    loadEvidence();
  } catch (e) {
    showNotification('Delete failed: ' + e.message, 'error');
  }
}

async function showDetails(id) {
  try {
    const ev = await apiRequest(`/api/evidence/${id}`);
    const modal = document.getElementById('detail-modal');
    document.getElementById('detail-content').innerHTML = `
      <div class="meta-grid">
        <span class="meta-label">Evidence ID</span><span class="meta-value code-text">${escapeHtml(ev.evidence_id)}</span>
        <span class="meta-label">Filename</span><span class="meta-value">${escapeHtml(ev.original_filename)}</span>
        <span class="meta-label">Case</span><span class="meta-value">${escapeHtml(ev.case_reference || '—')}</span>
        <span class="meta-label">File Type</span><span class="meta-value">${escapeHtml(ev.file_type)}</span>
        <span class="meta-label">File Size</span><span class="meta-value">${formatFileSize(ev.file_size)}</span>
        <span class="meta-label">Uploaded By</span><span class="meta-value">${escapeHtml(ev.uploader_name)}</span>
        <span class="meta-label">Uploaded At</span><span class="meta-value">${formatTimestamp(ev.uploaded_at)}</span>
        <span class="meta-label">Status</span><span class="meta-value"><span class="badge ${getStatusClass(ev.status)}">${ev.status}</span></span>
        <span class="meta-label">Parsed Logs</span><span class="meta-value">${ev.parsed_logs_count} records</span>
        <span class="meta-label">Integrity</span><span class="meta-value">${ev.integrity_verified ? '<span class="integrity-ok">✅ Verified</span>' : '<span class="integrity-fail">⛔ Modified</span>'}</span>
        <span class="meta-label">Last Check</span><span class="meta-value">${formatTimestamp(ev.integrity_check_at)}</span>
        <span class="meta-label">Description</span><span class="meta-value">${escapeHtml(ev.description || '—')}</span>
      </div>
      <div style="margin-top:1.25rem;">
        <div class="meta-label" style="margin-bottom:.4rem;">SHA-256 Hash</div>
        <div class="hash-text" style="background:var(--bg-secondary);padding:.6rem .9rem;border-radius:6px;border:1px solid var(--border-color);">${escapeHtml(ev.sha256_hash)}</div>
      </div>`;
    modal.style.display = 'flex';
  } catch (e) {
    showNotification('Failed to load evidence details', 'error');
  }
}

function closeDetailModal() { document.getElementById('detail-modal').style.display = 'none'; }
