/* CYBERTRACE AI — Dashboard Page JavaScript */

let threatChart = null;
let trendChart = null;

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadThreatSeverityChart();
  loadEventTrendChart();
  loadRecentActivity();
  // Auto-refresh every 60s
  setInterval(() => { loadStats(); loadRecentActivity(); }, 60000);
});

async function loadStats() {
  try {
    const data = await apiRequest('/api/dashboard/stats');
    animateCounter('stat-cases', data.total_cases);
    animateCounter('stat-evidence', data.total_evidence);
    animateCounter('stat-alerts', data.threat_alerts);
    animateCounter('stat-critical', data.critical_events);
    animateCounter('stat-open', data.open_cases);
    animateCounter('stat-suspicious', data.suspicious_events);
  } catch (e) {
    console.error('Failed to load stats:', e);
  }
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const steps = 20;
  const increment = (target - start) / steps;
  let current = start;
  let step = 0;
  const timer = setInterval(() => {
    step++;
    current += increment;
    el.textContent = Math.round(step === steps ? target : current);
    if (step >= steps) clearInterval(timer);
  }, 30);
}

async function loadThreatSeverityChart() {
  try {
    const data = await apiRequest('/api/dashboard/threat-severity');
    const ctx = document.getElementById('threat-chart');
    if (!ctx) return;
    if (threatChart) threatChart.destroy();
    threatChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.data,
          backgroundColor: data.colors,
          borderColor: '#0f1923',
          borderWidth: 3,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#8892a4',
              font: { size: 11, family: 'Inter' },
              padding: 14,
              boxWidth: 12,
              boxHeight: 12
            }
          },
          tooltip: {
            backgroundColor: '#162032',
            titleColor: '#e8f0fe',
            bodyColor: '#8892a4',
            borderColor: '#1e2d3d',
            borderWidth: 1
          }
        }
      }
    });
  } catch (e) { console.error('Chart error:', e); }
}

async function loadEventTrendChart() {
  try {
    const data = await apiRequest('/api/dashboard/event-trend');
    const ctx = document.getElementById('trend-chart');
    if (!ctx) return;
    if (trendChart) trendChart.destroy();
    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, 'rgba(0,212,255,0.25)');
    gradient.addColorStop(1, 'rgba(0,212,255,0)');
    trendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Events',
          data: data.data,
          borderColor: '#00d4ff',
          backgroundColor: gradient,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#00d4ff',
          pointBorderColor: '#0f1923',
          pointBorderWidth: 2,
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#162032',
            titleColor: '#e8f0fe',
            bodyColor: '#8892a4',
            borderColor: '#1e2d3d',
            borderWidth: 1
          }
        },
        scales: {
          x: {
            ticks: { color: '#4a5568', font: { size: 10 } },
            grid: { color: 'rgba(30,45,61,0.5)', drawBorder: false }
          },
          y: {
            ticks: { color: '#4a5568', font: { size: 10 } },
            grid: { color: 'rgba(30,45,61,0.5)', drawBorder: false },
            beginAtZero: true
          }
        }
      }
    });
  } catch (e) { console.error('Trend chart error:', e); }
}

async function loadRecentActivity() {
  try {
    const data = await apiRequest('/api/dashboard/recent-activity');
    const tbody = document.getElementById('activity-tbody');
    if (!tbody) return;
    if (!data.activities || data.activities.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="empty-icon">📋</div><div>No recent activity</div></td></tr>`;
      return;
    }
    tbody.innerHTML = data.activities.map(a => `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.72rem;">${formatTimestamp(a.timestamp)}</td>
        <td>${escapeHtml(a.action)}</td>
        <td>${escapeHtml(a.username || 'System')}</td>
        <td>${escapeHtml(a.resource_type || '—')}</td>
        <td>${escapeHtml(a.ip_address || '—')}</td>
      </tr>`).join('');
  } catch (e) { console.error('Activity error:', e); }
}

function goToNewCase() { document.getElementById('quick-new-case-modal').style.display = 'flex'; }
function closeQuickModal() { document.getElementById('quick-new-case-modal').style.display = 'none'; }

async function quickCreateCase() {
  const title = document.getElementById('qc-title').value.trim();
  if (!title) { showNotification('Case title is required', 'error'); return; }
  try {
    showLoading('Creating case…');
    await apiRequest('/api/cases', 'POST', {
      title,
      description: document.getElementById('qc-desc').value,
      priority: document.getElementById('qc-priority').value
    });
    hideLoading();
    showNotification('Case created successfully!', 'success');
    closeQuickModal();
    loadStats();
  } catch (e) {
    hideLoading();
    showNotification('Failed to create case: ' + e.message, 'error');
  }
}
