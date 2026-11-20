/* CYBERTRACE AI — Incident Timeline JavaScript */

let allEvents = [];
let filteredEvents = [];

document.addEventListener('DOMContentLoaded', () => {
  loadTimeline();
});

function buildParams() {
  const p = new URLSearchParams({ limit: 300 });
  const vals = {
    case_id: 'filter-case-id',
    severity: 'filter-severity',
    event_type: 'filter-event-type',
    start_date: 'filter-start',
    end_date: 'filter-end'
  };
  for (const [key, id] of Object.entries(vals)) {
    const val = document.getElementById(id)?.value;
    if (val) p.set(key, val);
  }
  return p;
}

async function loadTimeline() {
  const container = document.getElementById('timeline-container');
  const countEl = document.getElementById('event-count');
  if (!container) return;
  container.innerHTML = `<div style="text-align:center;padding:3rem;"><div class="spinner" style="margin:0 auto;"></div><div style="color:var(--text-muted);margin-top:1rem;">Loading events…</div></div>`;

  try {
    const data = await apiRequest('/api/timeline/events?' + buildParams().toString());
    allEvents = data.events || [];
    filteredEvents = allEvents;
    if (countEl) countEl.textContent = allEvents.length;
    renderTimeline(allEvents);
  } catch (e) {
    container.innerHTML = `<div style="text-align:center;padding:2rem;color:var(--accent-red);">Error loading timeline: ${e.message}</div>`;
  }
}

function renderTimeline(events) {
  const container = document.getElementById('timeline-container');
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = `<div style="text-align:center;padding:3rem;color:var(--text-muted);">
      <div style="font-size:2.5rem;margin-bottom:1rem;">🕐</div>
      <div>No events found for the selected filters</div>
      <div style="font-size:.8rem;margin-top:.3rem;">Try uploading and analyzing evidence files</div>
    </div>`;
    return;
  }

  // Group events by date
  const groups = {};
  events.forEach(ev => {
    const date = ev.timestamp ? ev.timestamp.split('T')[0] : 'Unknown Date';
    if (!groups[date]) groups[date] = [];
    groups[date].push(ev);
  });

  let html = '<div class="timeline-track">';
  for (const [date, dayEvents] of Object.entries(groups)) {
    const displayDate = formatDate(date);
    html += `<div style="margin:1.5rem 0 1rem;display:flex;align-items:center;gap:.75rem;">
      <div style="font-size:.78rem;font-weight:600;color:var(--accent-cyan);letter-spacing:.05em;text-transform:uppercase;">${displayDate}</div>
      <div style="flex:1;height:1px;background:var(--border-color);"></div>
      <span class="badge badge-info" style="font-size:.68rem;">${dayEvents.length} events</span>
    </div>`;

    dayEvents.forEach(ev => {
      html += `<div class="timeline-item">
        <div class="timeline-dot ${ev.severity || 'info'}"></div>
        <div class="timeline-card">
          <div class="timeline-time">${formatTimestamp(ev.timestamp)}</div>
          <div class="timeline-event-type">
            <span class="badge ${getSeverityClass(ev.severity)}">${ev.severity || 'info'}</span>
            <span style="margin-left:.5rem;font-size:.82rem;font-weight:500;color:var(--text-primary);">
              ${formatEventType(ev.event_type)}
            </span>
            ${ev.is_suspicious ? '<span style="color:var(--accent-red);margin-left:.4rem;font-size:.8rem;">⚠️ Suspicious</span>' : ''}
          </div>
          <div class="timeline-desc">${escapeHtml(ev.event_description || 'No description')}</div>
          <div class="timeline-meta">
            ${ev.source_ip ? `<span>🌐 ${escapeHtml(ev.source_ip)}</span>` : ''}
            ${ev.username ? `<span>👤 ${escapeHtml(ev.username)}</span>` : ''}
            ${ev.destination_ip ? `<span>→ ${escapeHtml(ev.destination_ip)}</span>` : ''}
            ${ev.threat_category ? `<span style="color:var(--accent-orange);">🏷️ ${escapeHtml(ev.threat_category)}</span>` : ''}
          </div>
        </div>
      </div>`;
    });
  }
  html += '</div>';
  container.innerHTML = html;
}

function formatDate(dateStr) {
  if (!dateStr || dateStr === 'Unknown Date') return 'Unknown Date';
  try {
    const d = new Date(dateStr + 'T00:00:00');
    return d.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  } catch (_) { return dateStr; }
}

function formatEventType(type) {
  return (type || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function applyFilters() { loadTimeline(); }

function filterBySeverity(severity) {
  const sel = document.getElementById('filter-severity');
  if (sel) sel.value = severity;
  loadTimeline();
}
