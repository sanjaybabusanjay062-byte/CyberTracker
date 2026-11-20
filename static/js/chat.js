/* CYBERTRACE AI — AI Chat Assistant JavaScript */

let sessionId = generateSessionId();
let isProcessing = false;
let currentCaseId = null;
const SUGGESTIONS = [
  'Who logged into the server between 2–4 AM?',
  'Show me all failed login attempts',
  'Which IP addresses appear most suspicious?',
  'Give me a summary of all threats detected',
  'Was there any brute force attack detected?',
  'What files were accessed by admin users?',
  'Show timeline of events for the past 24 hours',
  'List all privilege escalation events',
];

function generateSessionId() {
  return 'sess-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 9);
}

document.addEventListener('DOMContentLoaded', () => {
  renderSuggestions();
  loadCaseSelect();

  // Enter to send (Shift+Enter for newline)
  const input = document.getElementById('chat-input');
  if (input) {
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
      // Auto-resize textarea
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 120) + 'px';
    });
  }
});

function renderSuggestions() {
  const container = document.getElementById('suggestions-list');
  if (!container) return;
  container.innerHTML = SUGGESTIONS.map(s =>
    `<button class="suggestion-chip" onclick="useSuggestion(this.textContent)">${escapeHtml(s)}</button>`
  ).join('');
}

function useSuggestion(text) {
  const input = document.getElementById('chat-input');
  if (input) { input.value = text; input.focus(); }
}

async function loadCaseSelect() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=50');
    const sel = document.getElementById('case-selector');
    if (!sel || !data.cases) return;
    data.cases.forEach(c => {
      sel.add(new Option(`${c.case_id} — ${c.title.substring(0, 35)}`, c.id));
    });
  } catch (e) { console.warn('Case load:', e); }
}

function onCaseChange() {
  const sel = document.getElementById('case-selector');
  currentCaseId = sel?.value || null;
  const badge = document.getElementById('case-badge');
  if (badge) {
    badge.textContent = currentCaseId
      ? sel.options[sel.selectedIndex].text
      : 'All Cases';
  }
}

async function sendMessage() {
  if (isProcessing) return;
  const input = document.getElementById('chat-input');
  const question = input?.value?.trim();
  if (!question) return;

  isProcessing = true;
  input.value = '';
  input.style.height = 'auto';

  appendMessage('user', question);
  showTyping();

  try {
    const data = await apiRequest('/api/chat/query', 'POST', {
      question,
      case_id: currentCaseId,
      session_id: sessionId
    });
    removeTyping();
    appendAssistantMessage(data);
    updateSessionInfo();
  } catch (e) {
    removeTyping();
    appendMessage('assistant', `⚠️ Error processing query: ${e.message}. Please try again.`);
  } finally {
    isProcessing = false;
    scrollToBottom();
  }
}

function appendMessage(role, content) {
  const container = document.getElementById('chat-messages');
  if (!container) return;

  // Remove welcome screen if present
  const welcome = document.getElementById('chat-welcome');
  if (welcome) welcome.remove();

  const avatarContent = role === 'user' ? '👤' : '🤖';
  const timeStr = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

  const div = document.createElement('div');
  div.className = `chat-message ${role}`;
  div.innerHTML = `
    <div class="msg-avatar ${role}">${avatarContent}</div>
    <div>
      <div class="msg-bubble">${escapeHtml(content)}</div>
      <div class="msg-time">${timeStr}</div>
    </div>`;
  container.appendChild(div);
  scrollToBottom();
}

function appendAssistantMessage(data) {
  const container = document.getElementById('chat-messages');
  if (!container) return;

  const timeStr = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.className = 'chat-message assistant';

  const hasRecords = data.supporting_records && data.supporting_records.length > 0;
  const recordsHtml = hasRecords ? `
    <details class="supporting-records">
      <summary>📊 ${data.supporting_records.length} supporting record${data.supporting_records.length !== 1 ? 's' : ''}</summary>
      <table class="supporting-table" style="margin-top:.5rem;">
        <thead><tr><th>Time</th><th>IP</th><th>User</th><th>Event</th><th>Severity</th></tr></thead>
        <tbody>
          ${data.supporting_records.slice(0, 15).map(r => `
            <tr>
              <td>${formatTimestamp(r.timestamp)?.split(' ').slice(-1)[0] || '—'}</td>
              <td>${escapeHtml(r.source_ip || '—')}</td>
              <td>${escapeHtml(r.username || '—')}</td>
              <td>${escapeHtml(r.event_type || '—')}</td>
              <td><span class="badge ${getSeverityClass(r.severity)}">${r.severity}</span></td>
            </tr>`).join('')}
          ${data.supporting_records.length > 15 ? `<tr><td colspan="5" style="color:var(--text-muted);text-align:center;">…and ${data.supporting_records.length - 15} more</td></tr>` : ''}
        </tbody>
      </table>
    </details>` : '';

  div.innerHTML = `
    <div class="msg-avatar assistant">🤖</div>
    <div style="max-width:85%;">
      <div class="msg-bubble" style="border-radius:12px 12px 12px 3px;">
        <div style="white-space:pre-wrap;">${escapeHtml(data.answer)}</div>
        ${recordsHtml}
        <div style="margin-top:.6rem;padding-top:.6rem;border-top:1px solid rgba(255,255,255,.08);font-size:.72rem;color:var(--text-muted);">
          ⚠️ ${escapeHtml(data.disclaimer || 'Analysis based on available evidence only.')}
        </div>
      </div>
      <div class="msg-time">
        ${timeStr}
        ${data.confidence ? `<span style="margin-left:.5rem;color:var(--accent-cyan);">Confidence: ${data.confidence}</span>` : ''}
      </div>
    </div>`;
  container.appendChild(div);
}

function showTyping() {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.id = 'typing-indicator';
  div.className = 'chat-message assistant';
  div.innerHTML = `
    <div class="msg-avatar assistant">🤖</div>
    <div class="msg-bubble" style="padding:.7rem 1rem;border-radius:12px 12px 12px 3px;">
      <div class="typing-indicator">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <span style="font-size:.75rem;color:var(--text-muted);margin-left:.4rem;">Analyzing evidence…</span>
      </div>
    </div>`;
  container.appendChild(div);
  scrollToBottom();
}

function removeTyping() {
  document.getElementById('typing-indicator')?.remove();
}

function scrollToBottom() {
  const container = document.getElementById('chat-messages');
  if (container) container.scrollTop = container.scrollHeight;
}

async function clearConversation() {
  if (!(await confirmDialog('Clear this conversation? The session history will be deleted.'))) return;
  try {
    await apiRequest(`/api/chat/history/${sessionId}`, 'DELETE');
    sessionId = generateSessionId();
    const container = document.getElementById('chat-messages');
    if (container) {
      container.innerHTML = `<div id="chat-welcome" style="text-align:center;padding:3rem 1rem;color:var(--text-muted);">
        <div style="font-size:2.5rem;margin-bottom:1rem;">🤖</div>
        <div style="font-size:1rem;font-weight:600;color:var(--text-secondary);margin-bottom:.5rem;">CYBERTRACE AI Assistant</div>
        <div style="font-size:.82rem;">Ask me anything about the evidence and investigation</div>
      </div>`;
    }
    updateSessionInfo();
    showNotification('Conversation cleared', 'info');
  } catch (e) {
    showNotification('Failed to clear conversation', 'error');
  }
}

function updateSessionInfo() {
  const el = document.getElementById('session-id-display');
  if (el) el.textContent = sessionId;
}
