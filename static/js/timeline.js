/* CYBERTRACE AI — Incident Timeline JavaScript */

let allTimelineEvents = [];
let timelineZoomLevel = 1;

document.addEventListener('DOMContentLoaded', () => {
  loadCaseOptions();
  loadTimeline();

  // Form submission
  const form = document.getElementById('timelineFilterForm');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      loadTimeline();
    });
  }

  // Filters change
  const selects = ['timelineCaseSelect', 'timelineSeveritySelect', 'timelineEventTypeSelect', 'timelineDateRange'];
  selects.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => loadTimeline());
  });

  // Search input debounced
  const searchInput = document.getElementById('timelineSearchInput');
  if (searchInput) {
    let timer = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => filterTimelineLocally(), 200);
    });
  }

  // Export Timeline
  const exportBtn = document.getElementById('exportTimelineBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const params = buildTimelineParams();
      window.location.href = '/api/timeline/export?' + params.toString();
      showNotification('Exporting incident sequence timeline...', 'info');
    });
  }

  // Zoom controls
  const zoomIn = document.getElementById('zoomInTimelineBtn');
  const zoomOut = document.getElementById('zoomOutTimelineBtn');
  if (zoomIn) {
    zoomIn.addEventListener('click', () => {
      timelineZoomLevel = Math.min(1.4, timelineZoomLevel + 0.15);
      applyZoom();
    });
  }
  if (zoomOut) {
    zoomOut.addEventListener('click', () => {
      timelineZoomLevel = Math.max(0.75, timelineZoomLevel - 0.15);
      applyZoom();
    });
  }
});

function applyZoom() {
  const container = document.getElementById('verticalTimeline') || document.getElementById('timeline-container');
  if (container) {
    container.style.transform = `scale(${timelineZoomLevel})`;
    container.style.transformOrigin = 'top left';
  }
}

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('timelineCaseSelect') || document.getElementById('filter-case-id');
    if (sel && data.cases) {
      data.cases.forEach(c => {
        sel.add(new Option(`${c.case_id} — ${c.title.substring(0, 36)}`, c.id));
      });
    }
  } catch (e) {
    console.error('Timeline cases load error:', e);
  }
}

function buildTimelineParams() {
  const p = new URLSearchParams({ limit: 400 });
  const caseId = (document.getElementById('timelineCaseSelect') || document.getElementById('filter-case-id'))?.value;
  const sev = (document.getElementById('timelineSeveritySelect') || document.getElementById('filter-severity'))?.value;
  const etype = (document.getElementById('timelineEventTypeSelect') || document.getElementById('filter-event-type'))?.value;
  const range = (document.getElementById('timelineDateRange'))?.value;

  if (caseId) p.set('case_id', caseId);
  if (sev) p.set('severity', sev);
  if (etype) p.set('event_type', etype);

  if (range === '24h') {
    p.set('start_date', new Date(Date.now() - 24 * 3600 * 1000).toISOString());
  } else if (range === '7d') {
    p.set('start_date', new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString());
  }

  return p;
}

async function loadTimeline() {
  const container = document.getElementById('verticalTimeline') || document.getElementById('timeline-container');
  const loading = document.getElementById('timelineLoading');
  const empty = document.getElementById('timelineEmpty');
  const statsBadge = document.getElementById('timelineStatsBadge');

  if (loading) loading.style.display = 'flex';
  if (empty) empty.style.display = 'none';
  if (container) container.innerHTML = '';

  try {
    const params = buildTimelineParams();
    const data = await apiRequest('/api/timeline/events?' + params.toString());
    allTimelineEvents = data.events || [];

    if (loading) loading.style.display = 'none';

    if (statsBadge) {
      statsBadge.textContent = `${allTimelineEvents.length} Sequential Events Reconstructed`;
    }

    filterTimelineLocally();
  } catch (err) {
    if (loading) loading.style.display = 'none';
    if (container) {
      container.innerHTML = `<div style="text-align:center;padding:2rem;color:#ff4757;">Failed to reconstruct timeline: ${err.message}</div>`;
    }
  }
}

function filterTimelineLocally() {
  const q = document.getElementById('timelineSearchInput')?.value?.toLowerCase()?.trim();
  let events = allTimelineEvents;

  if (q) {
    events = events.filter(e => 
      (e.event_description && e.event_description.toLowerCase().includes(q)) ||
      (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
      (e.username && e.username.toLowerCase().includes(q)) ||
      (e.event_type && e.event_type.toLowerCase().includes(q))
    );
  }

  renderTimeline(events);
}

function renderTimeline(events) {
  const container = document.getElementById('verticalTimeline') || document.getElementById('timeline-container');
  const empty = document.getElementById('timelineEmpty');

  if (!container) return;

  if (!events || events.length === 0) {
    if (empty) empty.style.display = 'block';
    container.innerHTML = '';
    return;
  }

  if (empty) empty.style.display = 'none';

  // Group by calendar day
  const groups = {};
  events.forEach(ev => {
    const day = ev.timestamp ? ev.timestamp.split('T')[0] : 'Unknown Date';
    if (!groups[day]) groups[day] = [];
    groups[day].push(ev);
  });

  let html = '';
  for (const [dayStr, dayEvents] of Object.entries(groups)) {
    const dateFormatted = formatDayHeader(dayStr);
    html += `
      <div class="timeline-day-separator">
        <span class="day-badge">${dateFormatted}</span>
        <span class="day-line"></span>
        <span class="day-count">${dayEvents.length} events</span>
      </div>
    `;

    dayEvents.forEach((ev, idx) => {
      const sevClass = (ev.severity || 'info').toLowerCase();
      const isCritical = sevClass === 'critical';
      const timeStr = ev.timestamp ? formatTimestamp(ev.timestamp) : '—';

      html += `
        <div class="timeline-event-card sev-${sevClass} ${ev.is_suspicious ? 'suspicious-card' : ''}">
          <div class="timeline-bullet bullet-${sevClass}">
            <span class="bullet-inner"></span>
          </div>
          <div class="timeline-content-box">
            <div class="event-meta-row">
              <span class="event-timestamp">${timeStr}</span>
              <div class="badge-group">
                <span class="badge ${getSeverityBadgeClass(sevClass)}">${sevClass.toUpperCase()}</span>
                <span class="badge badge-info">${escapeHtml(formatEventType(ev.event_type))}</span>
                ${ev.is_suspicious ? '<span class="badge badge-critical">FLAGGED IOC</span>' : ''}
              </div>
            </div>

            <div class="event-title-text">
              ${escapeHtml(ev.event_description || 'Security Telemetry Event')}
            </div>

            <div class="event-details-bar">
              ${ev.source_ip ? `<span class="detail-pill"><span class="pill-label">SRC IP:</span> <code class="code-text">${escapeHtml(ev.source_ip)}</code></span>` : ''}
              ${ev.destination_ip ? `<span class="detail-pill"><span class="pill-label">DST IP:</span> <code class="code-text">${escapeHtml(ev.destination_ip)}</code></span>` : ''}
              ${ev.username ? `<span class="detail-pill"><span class="pill-label">USER:</span> <strong style="color:#e8f0fe;">${escapeHtml(ev.username)}</strong></span>` : ''}
              ${ev.threat_category ? `<span class="detail-pill text-orange"><span class="pill-label">ATT&CK:</span> ${escapeHtml(ev.threat_category)}</span>` : ''}
            </div>

            ${ev.raw_log ? `
              <div class="event-raw-toggle" onclick="this.nextElementSibling.classList.toggle('open');">
                <span>View Raw Event Payload &rsaquo;</span>
              </div>
              <div class="event-raw-box">
                <pre class="raw-pre"><code>${escapeHtml(ev.raw_log)}</code></pre>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    });
  }

  container.innerHTML = html;
}

function formatDayHeader(dayStr) {
  try {
    const d = new Date(dayStr);
    return d.toLocaleDateString('en-GB', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
  } catch (_) {
    return dayStr;
  }
}

function getSeverityBadgeClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

function formatEventType(etype) {
  if (!etype) return 'Event';
  return etype.replace(/_/g, ' ').toUpperCase();
}
