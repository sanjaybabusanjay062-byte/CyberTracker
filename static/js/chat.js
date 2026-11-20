/* CYBERTRACE AI — AI Forensic Investigation Assistant JavaScript */

let sessionId = generateSessionId();
let isProcessing = false;
let currentCaseId = null;

function generateSessionId() {
  return 'CT-SESS-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
}

document.addEventListener('DOMContentLoaded', () => {
  const sessionEl = document.getElementById('chatSessionId');
  if (sessionEl) sessionEl.textContent = sessionId;

  loadCaseOptions();
  loadContextMetrics();
  initChatForm();
  initPromptChips();

  const clearBtn = document.getElementById('clearChatBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      const area = document.getElementById('chatMessagesArea') || document.getElementById('chat-messages');
      if (area) {
        area.innerHTML = `
          <div class="chat-message assistant-msg">
            <div class="msg-avatar"><span>AI</span></div>
            <div class="msg-content-wrapper">
              <div class="msg-sender-name">CYBERTRACE AI Forensics</div>
              <div class="msg-bubble">
                <p>Investigation session reset. Telemetry indexes and cryptographic hashes are ready. What evidence would you like to examine?</p>
              </div>
              <div class="msg-timestamp">Session Cleared</div>
            </div>
          </div>
        `;
      }
      try {
        await apiRequest(`/api/chat/history/${sessionId}`, 'DELETE');
      } catch (_) {}
      sessionId = generateSessionId();
      if (sessionEl) sessionEl.textContent = sessionId;
      showNotification('Chat conversation cleared', 'info');
    });
  }
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('chatCaseSelect') || document.getElementById('case-selector');
    if (!sel || !data.cases) return;

    data.cases.forEach(c => {
      sel.add(new Option(`${c.case_id} — ${c.title.substring(0, 32)}`, c.id));
    });

    sel.addEventListener('change', () => {
      currentCaseId = sel.value || null;
      const label = document.getElementById('groundingCaseLabel');
      if (label) {
        label.textContent = currentCaseId ? sel.options[sel.selectedIndex].text : 'All Active Cases';
      }
      loadContextMetrics();
      showNotification(`Forensic grounding updated to: ${label ? label.textContent : 'All Cases'}`, 'info');
    });
  } catch (e) {
    console.error('Failed to load case options for AI:', e);
  }
}

async function loadContextMetrics() {
  try {
    const url = '/api/chat/context' + (currentCaseId ? `?case_id=${currentCaseId}` : '');
    const data = await apiRequest(url);

    const evEl = document.getElementById('ctxEvidenceCount');
    const logEl = document.getElementById('ctxLogCount');
    const threatEl = document.getElementById('ctxThreatCount');

    if (evEl) evEl.textContent = data.evidence_count ?? '--';
    if (logEl) logEl.textContent = data.log_count ?? '--';
    if (threatEl) threatEl.textContent = data.threat_count ?? '--';
  } catch (e) {
    console.warn('Context metrics load error:', e);
  }
}

function initChatForm() {
  const form = document.getElementById('chatForm');
  const input = document.getElementById('chatInput') || document.getElementById('chat-input');

  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        submitQuery();
      }
      // Auto-resize textarea
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 140) + 'px';
    });
  }

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      submitQuery();
    });
  }
}

function initPromptChips() {
  document.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const q = chip.dataset.query || chip.querySelector('.chip-text')?.textContent?.trim() || chip.textContent?.trim();
      if (q) {
        const input = document.getElementById('chatInput') || document.getElementById('chat-input');
        if (input) input.value = q;
        submitQuery();
      }
    });
  });
}

async function submitQuery() {
  if (isProcessing) return;
  const input = document.getElementById('chatInput') || document.getElementById('chat-input');
  const question = input?.value?.trim();
  if (!question) return;

  isProcessing = true;
  input.value = '';
  input.style.height = 'auto';

  // Append User message
  appendUserMessage(question);
  showTyping(true);

  try {
    const data = await apiRequest('/api/chat/query', 'POST', {
      question,
      case_id: currentCaseId,
      session_id: sessionId
    });

    showTyping(false);
    appendAssistantMessage(data);
  } catch (err) {
    showTyping(false);
    appendAssistantMessage({
      answer: `### Telemetry Query Notice\n\nUnable to process query at this moment: ${err.message}. Please check that evidence is indexed or try rephrasing your inquiry.`,
      supporting_records: [],
      confidence: 0,
      disclaimer: 'Analysis based on available evidence only.'
    });
  } finally {
    isProcessing = false;
  }
}

function appendUserMessage(text) {
  const area = document.getElementById('chatMessagesArea') || document.getElementById('chat-messages');
  if (!area) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = 'chat-message user-msg';
  const nowStr = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

  msgDiv.innerHTML = `
    <div class="msg-avatar user-avatar">
      <span>YOU</span>
    </div>
    <div class="msg-content-wrapper">
      <div class="msg-sender-name">Investigator Query</div>
      <div class="msg-bubble user-bubble">
        <p>${escapeHtml(text)}</p>
      </div>
      <div class="msg-timestamp">${nowStr}</div>
    </div>
  `;

  area.appendChild(msgDiv);
  scrollToBottom();
}

function appendAssistantMessage(data) {
  const area = document.getElementById('chatMessagesArea') || document.getElementById('chat-messages');
  if (!area) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = 'chat-message assistant-msg';
  const nowStr = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

  // Format markdown in answer
  const formattedAnswer = renderMarkdownAnswer(data.answer || 'No response returned.');

  // Supporting evidence records cards
  let supportingHtml = '';
  const records = data.supporting_records || [];
  if (records.length > 0) {
    supportingHtml = `
      <div class="supporting-evidence-box">
        <div class="supporting-header">
          <span class="supp-icon">🛡️</span>
          <span>Supporting Evidence Logs (${records.length} Records Verified)</span>
        </div>
        <div class="supporting-records-list">
          ${records.slice(0, 6).map(r => `
            <div class="supp-record-item">
              <span class="supp-time">${escapeHtml(formatTimestamp(r.timestamp))}</span>
              <span class="supp-type badge ${getSeverityClass(r.severity || 'info')}">${escapeHtml(r.event_type || 'event')}</span>
              <span class="supp-ip code-text">${escapeHtml(r.source_ip || 'Local')}</span>
              <span class="supp-user">${escapeHtml(r.username || 'system')}</span>
              <span class="supp-desc">${escapeHtml(r.event_description || r.description || '')}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  msgDiv.innerHTML = `
    <div class="msg-avatar">
      <span>AI</span>
    </div>
    <div class="msg-content-wrapper">
      <div class="msg-sender-name">
        <span>CYBERTRACE AI Forensics</span>
        <span class="confidence-tag">Confidence: ${Math.round((data.confidence || 0.95) * 100)}%</span>
      </div>
      <div class="msg-bubble">
        <div class="ai-formatted-text">${formattedAnswer}</div>
        ${supportingHtml}
        <div class="grounding-disclaimer-note">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          <span>${escapeHtml(data.disclaimer || 'Deterministic grounding active. 0% hallucination tolerance.')}</span>
        </div>
      </div>
      <div class="msg-timestamp">${nowStr}</div>
    </div>
  `;

  area.appendChild(msgDiv);
  scrollToBottom();
}

function showTyping(show) {
  const indicator = document.getElementById('typingIndicator') || document.getElementById('typing-indicator');
  if (indicator) {
    indicator.style.display = show ? 'flex' : 'none';
  }
  if (show) scrollToBottom();
}

function scrollToBottom() {
  const area = document.getElementById('chatMessagesArea') || document.getElementById('chat-messages');
  if (area) {
    setTimeout(() => {
      area.scrollTop = area.scrollHeight;
    }, 50);
  }
}

function renderMarkdownAnswer(text) {
  if (!text) return '';
  // Basic markdown parser
  let html = escapeHtml(text);

  // Headers
  html = html.replace(/^### (.*$)/gim, '<h4 class="ai-heading">$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3 class="ai-heading">$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h2 class="ai-heading">$1</h2>');

  // Bold
  html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
  // Italic
  html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');
  // Inline code
  html = html.replace(/`(.*?)`/gim, '<code class="inline-code">$1</code>');

  // Bullet items
  html = html.replace(/^\- (.*$)/gim, '<li class="ai-bullet">$1</li>');
  html = html.replace(/(<li.*<\/li>)/gim, '<ul class="ai-list">$1</ul>');

  // Line breaks to paragraphs
  html = html.split('\n\n').map(p => {
    if (p.startsWith('<h') || p.startsWith('<ul')) return p;
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  }).join('');

  return html;
}
