/* CYBERTRACE AI — SOC Dashboard JavaScript */

let threatChart = null;
let trendChart = null;
let currentTrendRange = '14d';

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadThreatSeverityChart();
  loadEventTrendChart(currentTrendRange);
  loadRecentActivity();

  // Refresh button
  const refreshBtn = document.getElementById('refreshDashboardBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshBtn.classList.add('loading');
      Promise.all([loadStats(), loadThreatSeverityChart(), loadEventTrendChart(currentTrendRange), loadRecentActivity()]).finally(() => {
        refreshBtn.classList.remove('loading');
        showNotification('Dashboard telemetry refreshed', 'info');
      });
    });
  }

  // Quick Action Modal handlers
  setupQuickCaseModal();

  // Trend range buttons
  document.querySelectorAll('.pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentTrendRange = btn.dataset.range || '14d';
      loadEventTrendChart(currentTrendRange);
    });
  });

  // Auto-refresh every 60s
  setInterval(() => {
    loadStats();
    loadRecentActivity();
  }, 60000);
});

async function loadStats() {
  try {
    const data = await apiRequest('/api/dashboard/stats');
    
    // Update counter values
    animateCounter('statTotalCases', data.total_cases ?? data.open_cases ?? 0);
    animateCounter('stat-cases', data.total_cases ?? data.open_cases ?? 0);

    animateCounter('statEvidenceFiles', data.total_evidence ?? 0);
    animateCounter('stat-evidence', data.total_evidence ?? 0);

    animateCounter('statThreatAlerts', data.threat_alerts ?? 0);
    animateCounter('stat-alerts', data.threat_alerts ?? 0);

    animateCounter('statCriticalEvents', data.critical_events ?? 0);
    animateCounter('stat-critical', data.critical_events ?? 0);

    animateCounter('stat-open', data.open_cases ?? 0);
    animateCounter('stat-suspicious', data.suspicious_events ?? 0);
  } catch (e) {
    console.error('Failed to load stats:', e);
  }
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
  const steps = 15;
  const increment = (target - start) / steps;
  let current = start;
  let step = 0;
  const timer = setInterval(() => {
    step++;
    current += increment;
    el.textContent = Math.round(step === steps ? target : current);
    if (step >= steps) {
      el.textContent = target;
      clearInterval(timer);
    }
  }, 25);
}

async function loadThreatSeverityChart() {
  try {
    const data = await apiRequest('/api/dashboard/threat-severity');
    const ctx = document.getElementById('threatSeverityChart') || document.getElementById('threat-chart');
    if (!ctx) return;

    if (threatChart) threatChart.destroy();

    const totalAlerts = (data.data || []).reduce((a, b) => a + b, 0);
    const badge = document.getElementById('donutTotalBadge');
    if (badge) badge.textContent = `${totalAlerts} Active Alerts`;

    threatChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.data,
          backgroundColor: data.colors,
          borderColor: '#0a0e1a',
          borderWidth: 3,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#8892a4',
              font: { size: 11, family: 'Inter' },
              padding: 12,
              boxWidth: 10,
              boxHeight: 10
            }
          },
          tooltip: {
            backgroundColor: '#162032',
            titleColor: '#e8f0fe',
            bodyColor: '#8892a4',
            borderColor: '#1e2d3d',
            borderWidth: 1,
            padding: 10
          }
        }
      }
    });

    // Custom legend if present
    const legendEl = document.getElementById('donutLegend');
    if (legendEl && data.labels) {
      legendEl.innerHTML = data.labels.map((label, idx) => `
        <div class="legend-item" style="display:flex;align-items:center;gap:.5rem;font-size:.78rem;color:#8892a4;">
          <span style="width:8px;height:8px;border-radius:50%;background:${data.colors[idx]}"></span>
          <span>${label}: <strong style="color:#e8f0fe">${data.data[idx]}</strong></span>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Threat severity chart error:', e);
  }
}

async function loadEventTrendChart(range = '14d') {
  try {
    const data = await apiRequest('/api/dashboard/event-trend?range=' + range);
    const ctx = document.getElementById('eventTrendChart') || document.getElementById('trend-chart');
    if (!ctx) return;

    if (trendChart) trendChart.destroy();

    const canvasCtx = ctx.getContext('2d');
    const gradient = canvasCtx.createLinearGradient(0, 0, 0, 240);
    gradient.addColorStop(0, 'rgba(0,212,255,0.28)');
    gradient.addColorStop(1, 'rgba(0,212,255,0.01)');

    trendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Forensic Events',
          data: data.data,
          borderColor: '#00d4ff',
          backgroundColor: gradient,
          borderWidth: 2.2,
          pointRadius: 3,
          pointBackgroundColor: '#00d4ff',
          pointBorderColor: '#0a0e1a',
          pointBorderWidth: 2,
          pointHoverRadius: 6,
          tension: 0.35,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#162032',
            titleColor: '#e8f0fe',
            bodyColor: '#8892a4',
            borderColor: '#1e2d3d',
            borderWidth: 1,
            padding: 10
          }
        },
        scales: {
          x: {
            ticks: { color: '#8892a4', font: { size: 10 } },
            grid: { color: 'rgba(30,45,61,0.3)', drawBorder: false }
          },
          y: {
            ticks: { color: '#8892a4', font: { size: 10 } },
            grid: { color: 'rgba(30,45,61,0.3)', drawBorder: false },
            beginAtZero: true
          }
        }
      }
    });
  } catch (e) {
    console.error('Event trend chart error:', e);
  }
}

async function loadRecentActivity() {
  const tbody = document.getElementById('recentActivityTableBody') || document.getElementById('activity-tbody');
  if (!tbody) return;

  try {
    const data = await apiRequest('/api/dashboard/recent-activity');
    if (!data.activities || data.activities.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="table-empty-cell" style="text-align:center;padding:2rem;color:#8892a4;">No recent forensic actions recorded</td></tr>`;
      return;
    }

    tbody.innerHTML = data.activities.map(a => `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.74rem;white-space:nowrap;color:#8892a4;">
          ${formatTimestamp(a.timestamp)}
        </td>
        <td>
          <span class="code-text" style="color:#00d4ff;">${escapeHtml(a.action)}</span>
        </td>
        <td>${escapeHtml(a.username || 'System')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.74rem;">${escapeHtml(a.resource_id || a.resource_type || '—')}</td>
        <td>
          <span class="badge ${a.action.includes('UPLOAD') || a.action.includes('CASE') ? 'badge-info' : (a.action.includes('FAIL') || a.action.includes('ALERT') ? 'badge-critical' : 'badge-low')}">
            ${a.action.includes('ALERT') ? 'Alert' : (a.action.includes('FAIL') ? 'Warning' : 'Info')}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('Failed to load recent activity:', e);
  }
}

function setupQuickCaseModal() {
  const modal = document.getElementById('quickNewCaseModal') || document.getElementById('quick-new-case-modal');
  const openBtn = document.getElementById('qaNewCaseBtn');
  const closeBtn = document.getElementById('closeCaseModalBtn');
  const cancelBtn = document.getElementById('cancelCaseModalBtn');
  const form = document.getElementById('quickNewCaseForm');

  if (!modal) return;

  const openModal = () => {
    modal.style.display = 'flex';
    modal.classList.add('active');
    const input = document.getElementById('qaCaseTitle') || document.getElementById('qc-title');
    if (input) input.focus();
  };

  const closeModal = () => {
    modal.style.display = 'none';
    modal.classList.remove('active');
    if (form) form.reset();
  };

  if (openBtn) openBtn.addEventListener('click', openModal);
  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (cancelBtn) cancelBtn.addEventListener('click', closeModal);

  window.goToNewCase = openModal;
  window.closeQuickModal = closeModal;

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = (document.getElementById('qaCaseTitle') || document.getElementById('qc-title'))?.value?.trim();
      const priority = (document.getElementById('qaCasePriority') || document.getElementById('qc-priority'))?.value || 'medium';
      const description = (document.getElementById('qaCaseDesc') || document.getElementById('qc-desc'))?.value || '';

      if (!title) {
        showNotification('Case title is required', 'error');
        return;
      }

      try {
        showLoading('Initializing case dossier…');
        const res = await apiRequest('/api/cases', 'POST', { title, priority, description });
        hideLoading();
        showNotification(`Case ${res.case?.case_id || ''} created successfully!`, 'success');
        closeModal();
        loadStats();
        loadRecentActivity();
      } catch (err) {
        hideLoading();
        showNotification('Failed to create case: ' + err.message, 'error');
      }
    });
  }
}
