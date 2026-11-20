/* CYBERTRACE AI — Evidence Management JavaScript */

let evidenceData = [];
let selectedUploadFile = null;

document.addEventListener('DOMContentLoaded', () => {
  loadCaseOptions();
  loadEvidence();
  initDropzone();
  initFilters();

  const refreshBtn = document.getElementById('refreshEvidenceBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadEvidence();
      showNotification('Evidence vault reloaded', 'info');
    });
  }
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('evidenceCaseSelector') || document.getElementById('upload-case-id');
    const filterSel = document.getElementById('filterCase') || document.getElementById('filter-case-id');

    if (data.cases) {
      data.cases.forEach(c => {
        const titleText = `${c.case_id} — ${c.title.substring(0, 36)}`;
        if (sel) {
          const opt = new Option(titleText, c.id);
          sel.add(opt);
        }
        if (filterSel) {
          const filterOpt = new Option(titleText, c.id);
          filterSel.add(filterOpt);
        }
      });
    }
  } catch (e) {
    console.error('Case options error:', e);
  }
}

async function loadEvidence() {
  const tbody = document.getElementById('evidenceTableBody') || document.getElementById('evidence-tbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="8" class="table-empty-cell" style="text-align:center;padding:2rem;"><div class="inline-spinner"></div> Loading evidence repository...</td></tr>`;

  try {
    const params = new URLSearchParams();
    const caseId = (document.getElementById('filterCase') || document.getElementById('filter-case-id'))?.value;
    const ft = (document.getElementById('filterType') || document.getElementById('filter-type'))?.value;
    const st = (document.getElementById('filterStatus') || document.getElementById('filter-status'))?.value;
    const query = document.getElementById('evidenceSearchInput')?.value?.toLowerCase()?.trim();

    if (caseId) params.set('case_id', caseId);
    if (ft) params.set('file_type', ft);
    if (st && st !== 'verified' && st !== 'modified') params.set('status', st);

    const data = await apiRequest('/api/evidence/list?' + params.toString());
    evidenceData = data.evidence || [];

    // Filter in-memory by status / search query if requested
    let filtered = evidenceData;
    if (st === 'verified') filtered = filtered.filter(e => e.integrity_verified);
    if (st === 'modified') filtered = filtered.filter(e => !e.integrity_verified);
    if (query) {
      filtered = filtered.filter(e => 
        (e.original_filename && e.original_filename.toLowerCase().includes(query)) ||
        (e.sha256_hash && e.sha256_hash.toLowerCase().includes(query)) ||
        (e.evidence_id && e.evidence_id.toLowerCase().includes(query))
      );
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="table-empty-cell" style="text-align:center;padding:2.5rem;color:#8892a4;">
        <div style="font-size:2rem;margin-bottom:.5rem;">🗂️</div>
        <div>No forensic artifacts found for current query.</div>
      </td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(ev => `
      <tr>
        <td><span class="code-text" style="color:#00d4ff;font-weight:600;">${escapeHtml(ev.evidence_id)}</span></td>
        <td>
          <div style="font-weight:500;color:#e8f0fe;" title="${escapeHtml(ev.original_filename)}">
            ${escapeHtml(ev.original_filename)}
          </div>
          <div style="font-size:.74rem;color:#8892a4;">${escapeHtml(ev.description || 'Raw Forensic Ingestion')}</div>
        </td>
        <td><span class="code-text">${escapeHtml(ev.case_reference || '—')}</span></td>
        <td>
          <span class="hash-text" title="${escapeHtml(ev.sha256_hash)}" style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#00ff88;cursor:pointer;" onclick="navigator.clipboard.writeText('${escapeHtml(ev.sha256_hash)}'); showNotification('Hash copied to clipboard!', 'success');">
            ${truncateHash(ev.sha256_hash, 18)}
          </span>
        </td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.76rem;">${formatFileSize(ev.file_size)}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#8892a4;">${formatTimestamp(ev.uploaded_at)}</td>
        <td>
          ${ev.integrity_verified
            ? `<span class="badge badge-success" id="badge-integrity-${ev.id}" title="SHA-256 match confirmed">✓ Verified</span>`
            : `<span class="badge badge-critical" id="badge-integrity-${ev.id}" title="Integrity violation!">⚠ Modified</span>`}
        </td>
        <td class="text-right">
          <div style="display:inline-flex;gap:.35rem;justify-content:flex-end;">
            <button class="btn btn-xs btn-secondary" onclick="verifyIntegrity(${ev.id})" title="Verify SHA-256 Hash">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              <span>Verify</span>
            </button>
            <button class="btn btn-xs btn-secondary" onclick="analyzeEvidence(${ev.id})" title="Parse and Normalize Logs">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
              <span>Parse</span>
            </button>
            <button class="btn btn-xs btn-danger" onclick="deleteEvidence(${ev.id})" title="Archive/Delete artifact">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty-cell" style="color:#ff4757;text-align:center;">Error loading evidence: ${e.message}</td></tr>`;
  }
}

function initFilters() {
  const inputs = ['filterCase', 'filterType', 'filterStatus', 'filter-case-id', 'filter-type', 'filter-status'];
  inputs.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => loadEvidence());
  });

  const searchInput = document.getElementById('evidenceSearchInput');
  if (searchInput) {
    let timer = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => loadEvidence(), 250);
    });
  }
}

function initDropzone() {
  const zone = document.getElementById('evidenceDropzone') || document.getElementById('upload-zone');
  const input = document.getElementById('evidenceFileInput') || document.getElementById('file-input');
  const prompt = document.getElementById('dropzonePrompt');
  const preview = document.getElementById('filePreviewCard');
  const removeBtn = document.getElementById('removeSelectedFileBtn');
  const form = document.getElementById('evidenceUploadForm');

  if (!zone || !input) return;

  zone.addEventListener('click', (e) => {
    if (e.target !== removeBtn && !removeBtn?.contains(e.target)) {
      input.click();
    }
  });

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });

  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      selectedUploadFile = e.dataTransfer.files[0];
      showFilePreview(selectedUploadFile);
    }
  });

  input.addEventListener('change', () => {
    if (input.files && input.files[0]) {
      selectedUploadFile = input.files[0];
      showFilePreview(selectedUploadFile);
    }
  });

  if (removeBtn) {
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      selectedUploadFile = null;
      input.value = '';
      if (preview) preview.style.display = 'none';
      if (prompt) prompt.style.display = 'flex';
    });
  }

  function showFilePreview(file) {
    if (prompt) prompt.style.display = 'none';
    if (preview) {
      preview.style.display = 'flex';
      const nameEl = document.getElementById('previewFileName');
      const sizeEl = document.getElementById('previewFileSize');
      if (nameEl) nameEl.textContent = file.name;
      if (sizeEl) sizeEl.textContent = formatFileSize(file.size);
    }
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const caseId = (document.getElementById('evidenceCaseSelector') || document.getElementById('upload-case-id'))?.value;
      const file = selectedUploadFile || input.files[0];
      const desc = (document.getElementById('evidenceDescription'))?.value || '';

      if (!file) {
        showNotification('Please select or drop a forensic evidence file', 'error');
        return;
      }
      if (!caseId) {
        showNotification('Please select an incident case', 'error');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);
      formData.append('case_id', caseId);
      formData.append('description', desc);

      const progressWrapper = document.getElementById('uploadProgressWrapper');
      const progressBar = document.getElementById('uploadProgressBar');
      const progressText = document.getElementById('uploadProgressText');
      const progressPercent = document.getElementById('uploadProgressPercent');

      if (progressWrapper) progressWrapper.style.display = 'block';
      if (progressBar) progressBar.style.width = '30%';
      if (progressText) progressText.textContent = 'Computing SHA-256 hash & writing to enclave...';
      if (progressPercent) progressPercent.textContent = '30%';

      try {
        showLoading('Ingesting evidence artifact and computing SHA-256…');
        const res = await apiRequest('/api/evidence/upload', 'POST', formData, true);
        hideLoading();

        if (progressBar) progressBar.style.width = '100%';
        if (progressPercent) progressPercent.textContent = '100%';
        if (progressText) progressText.textContent = 'Hash verified: ' + truncateHash(res.evidence?.sha256_hash, 16);

        showNotification(`Artifact ingested! SHA-256: ${truncateHash(res.evidence?.sha256_hash, 16)}`, 'success');

        // Reset dropzone
        selectedUploadFile = null;
        input.value = '';
        if (preview) preview.style.display = 'none';
        if (prompt) prompt.style.display = 'flex';
        form.reset();
        setTimeout(() => {
          if (progressWrapper) progressWrapper.style.display = 'none';
        }, 2000);

        loadEvidence();
      } catch (err) {
        hideLoading();
        if (progressWrapper) progressWrapper.style.display = 'none';
        showNotification('Upload failed: ' + err.message, 'error');
      }
    });
  }
}

async function verifyIntegrity(evidenceId) {
  showLoading('Recalculating SHA-256 cryptographic digest against disk artifact…');
  try {
    const res = await apiRequest(`/api/evidence/${evidenceId}/verify`, 'POST');
    hideLoading();

    const badge = document.getElementById(`badge-integrity-${evidenceId}`);
    if (res.integrity) {
      if (badge) {
        badge.className = 'badge badge-success';
        badge.textContent = '✓ Verified';
      }
      showNotification(`INTEGRITY VERIFIED! Stored and disk SHA-256 hashes match: ${truncateHash(res.current_hash, 16)}`, 'success');
    } else {
      if (badge) {
        badge.className = 'badge badge-critical';
        badge.textContent = '⚠ Modified';
      }
      showNotification(`WARNING: Cryptographic integrity failure! File hash modified!`, 'error');
    }
  } catch (err) {
    hideLoading();
    showNotification('Integrity verification failed: ' + err.message, 'error');
  }
}

async function analyzeEvidence(evidenceId) {
  showLoading('Parsing forensic log stream & extracting normalized telemetry…');
  try {
    const res = await apiRequest(`/api/evidence/${evidenceId}/analyze`, 'POST');
    hideLoading();
    showNotification(`Forensic Parser: Successfully extracted ${res.records_parsed || 0} events!`, 'success');
    loadEvidence();
  } catch (err) {
    hideLoading();
    showNotification('Parsing failed: ' + err.message, 'error');
  }
}

async function deleteEvidence(evidenceId) {
  const confirmed = await confirmDialog('Remove this evidence artifact from active investigation? Forensic audit records will be preserved.');
  if (!confirmed) return;

  try {
    showLoading('Archiving artifact record…');
    await apiRequest(`/api/evidence/${evidenceId}`, 'DELETE');
    hideLoading();
    showNotification('Artifact marked as deleted in chain of custody', 'info');
    loadEvidence();
  } catch (err) {
    hideLoading();
    showNotification('Delete failed: ' + err.message, 'error');
  }
}
