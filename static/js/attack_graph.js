/* CYBERTRACE AI — Attack Reconstruction Graph JavaScript */

let graphData = { nodes: [], edges: [] };
let canvas, ctx;
let scale = 1, panX = 0, panY = 0;
let isPanning = false, lastMx = 0, lastMy = 0;
let hoveredNode = null;
let selectedNode = null;
let showLabels = true;

const NODE_COLORS = {
  ip: { normal: '#3b82f6', suspicious: '#ff4757', text: '#fff' },
  user: { normal: '#00d4ff', suspicious: '#ffa502', text: '#000' },
  sys: { normal: '#a855f7', suspicious: '#ff4757', text: '#fff' },
  event: { normal: '#ffd32a', suspicious: '#ff4757', text: '#000' }
};

const EDGE_COLORS = {
  confirmed: '#00ff88',
  inferred: '#64748b'
};

document.addEventListener('DOMContentLoaded', () => {
  canvas = document.getElementById('attackGraphCanvas') || document.getElementById('attack-canvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  loadCaseOptions();

  // Mouse pan/zoom/click
  canvas.addEventListener('mousedown', onMouseDown);
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseup', onMouseUp);
  canvas.addEventListener('mouseleave', () => {
    isPanning = false;
    hoveredNode = null;
    drawGraph();
  });
  canvas.addEventListener('wheel', onWheel, { passive: false });

  // Toolbar buttons
  document.getElementById('graphZoomInBtn')?.addEventListener('click', () => { scale = Math.min(3, scale * 1.25); drawGraph(); });
  document.getElementById('graphZoomOutBtn')?.addEventListener('click', () => { scale = Math.max(0.3, scale / 1.25); drawGraph(); });
  document.getElementById('graphResetBtn')?.addEventListener('click', resetViewport);

  const toggleLabelsBtn = document.getElementById('graphToggleLabelsBtn');
  if (toggleLabelsBtn) {
    toggleLabelsBtn.addEventListener('click', () => {
      showLabels = !showLabels;
      const textSpan = document.getElementById('labelToggleText');
      if (textSpan) textSpan.textContent = `Labels: ${showLabels ? 'On' : 'Off'}`;
      drawGraph();
    });
  }

  const refreshBtn = document.getElementById('refreshGraphBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadGraph();
      showNotification('Attack graph topology recomputed', 'info');
    });
  }

  // Inspector Action Buttons
  document.getElementById('btnFilterLogsForNode')?.addEventListener('click', () => {
    if (selectedNode) {
      const q = encodeURIComponent(selectedNode.label);
      window.location.href = `/logs?search=${q}`;
    }
  });

  document.getElementById('btnAskAiAboutNode')?.addEventListener('click', () => {
    if (selectedNode) {
      window.location.href = `/ai-assistant`;
    }
  });

  // Initial load
  loadGraph();
});

async function loadCaseOptions() {
  try {
    const data = await apiRequest('/api/cases/list?per_page=100');
    const sel = document.getElementById('graphCaseSelector') || document.getElementById('graph-case-id');
    if (!sel || !data.cases) return;

    data.cases.forEach(c => {
      sel.add(new Option(`${c.case_id} — ${c.title.substring(0, 36)}`, c.id));
    });

    sel.addEventListener('change', () => loadGraph());
  } catch (e) {
    console.error('Case options load error:', e);
  }
}

function resizeCanvas() {
  if (!canvas) return;
  const container = canvas.parentElement;
  if (!container) return;
  canvas.width = container.clientWidth || 960;
  canvas.height = Math.max(560, container.clientHeight || 560);
  drawGraph();
}

async function loadGraph() {
  const caseId = (document.getElementById('graphCaseSelector') || document.getElementById('graph-case-id'))?.value;
  drawEmptyState('Calculating graph topology & correlation vectors…');

  try {
    const url = '/api/attack-graph/data' + (caseId ? `?case_id=${caseId}` : '');
    const data = await apiRequest(url);
    graphData = data;

    // Update stats
    setElementText('nodeCountText', data.stats?.total_nodes ?? data.nodes?.length ?? 0);
    setElementText('edgeCountText', data.stats?.total_edges ?? data.edges?.length ?? 0);
    setElementText('node-count', data.stats?.total_nodes ?? data.nodes?.length ?? 0);
    setElementText('edge-count', data.stats?.total_edges ?? data.edges?.length ?? 0);

    // Spread nodes relative to current canvas dimensions
    spreadNodes(graphData.nodes);
    resetViewport();
  } catch (err) {
    drawEmptyState('Error loading attack graph: ' + err.message);
  }
}

function spreadNodes(nodes) {
  if (!nodes || !nodes.length) return;
  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h / 2;
  const radius = Math.min(w, h) * 0.38;

  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    node.x = cx + radius * Math.cos(angle);
    node.y = cy + radius * Math.sin(angle);
  });
}

function resetViewport() {
  scale = 1;
  panX = 0;
  panY = 0;
  drawGraph();
}

function drawGraph() {
  if (!ctx || !canvas) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Background
  ctx.fillStyle = '#0a0e1a';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Background grid
  ctx.strokeStyle = 'rgba(30,45,61,0.35)';
  ctx.lineWidth = 1;
  const gridSize = 48 * scale;
  const offsetX = (panX % gridSize + gridSize) % gridSize;
  const offsetY = (panY % gridSize + gridSize) % gridSize;

  for (let x = offsetX; x < canvas.width; x += gridSize) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
  }
  for (let y = offsetY; y < canvas.height; y += gridSize) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
  }

  if (!graphData.nodes || !graphData.nodes.length) {
    drawEmptyState('No entities mapped in this incident scope.');
    return;
  }

  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(scale, scale);

  // 1. Draw Edges
  graphData.edges.forEach(edge => drawEdge(edge));

  // 2. Draw Nodes
  graphData.nodes.forEach(node => drawNode(node));

  ctx.restore();
}

function drawEdge(edge) {
  const from = graphData.nodes.find(n => n.id === edge.from);
  const to = graphData.nodes.find(n => n.id === edge.to);
  if (!from || !to) return;

  const isConfirmed = edge.type === 'confirmed';
  ctx.beginPath();
  ctx.moveTo(from.x, from.y);

  // Smooth quadratic curve
  const mx = (from.x + to.x) / 2;
  const my = (from.y + to.y) / 2 - 16;
  ctx.quadraticCurveTo(mx, my, to.x, to.y);

  ctx.strokeStyle = isConfirmed ? EDGE_COLORS.confirmed : EDGE_COLORS.inferred;
  ctx.lineWidth = isConfirmed ? 2 : 1.2;
  ctx.globalAlpha = isConfirmed ? 0.75 : 0.5;

  if (isConfirmed) {
    ctx.setLineDash([]);
  } else {
    ctx.setLineDash([6, 5]);
  }
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.globalAlpha = 1;

  // Arrowhead pointing towards target
  const angle = Math.atan2(to.y - my, to.x - mx);
  const arrowLen = 9;
  const ax = to.x - 22 * Math.cos(angle);
  const ay = to.y - 22 * Math.sin(angle);

  ctx.beginPath();
  ctx.moveTo(ax, ay);
  ctx.lineTo(ax - arrowLen * Math.cos(angle - Math.PI / 6), ay - arrowLen * Math.sin(angle - Math.PI / 6));
  ctx.lineTo(ax - arrowLen * Math.cos(angle + Math.PI / 6), ay - arrowLen * Math.sin(angle + Math.PI / 6));
  ctx.closePath();
  ctx.fillStyle = isConfirmed ? EDGE_COLORS.confirmed : EDGE_COLORS.inferred;
  ctx.fill();

  // Edge label if visible
  if (showLabels && edge.label) {
    ctx.fillStyle = isConfirmed ? '#8892a4' : '#64748b';
    ctx.font = `${9 / scale}px 'JetBrains Mono', monospace`;
    ctx.textAlign = 'center';
    ctx.fillText(edge.label, mx, my - 6);
  }
}

function drawNode(node) {
  const colors = NODE_COLORS[node.type] || NODE_COLORS.ip;
  const isSelected = selectedNode === node;
  const isHovered = hoveredNode === node;
  const baseColor = node.is_suspicious ? colors.suspicious : colors.normal;
  const radius = isSelected ? 24 : (isHovered ? 21 : 18);

  // Threat glow
  if (node.is_suspicious) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius + 10, 0, Math.PI * 2);
    const grad = ctx.createRadialGradient(node.x, node.y, radius, node.x, node.y, radius + 10);
    grad.addColorStop(0, 'rgba(255,71,87,0.4)');
    grad.addColorStop(1, 'rgba(255,71,87,0)');
    ctx.fillStyle = grad;
    ctx.fill();
  } else if (isSelected) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(0,212,255,0.3)';
    ctx.fill();
  }

  // Draw node body
  ctx.beginPath();
  if (node.type === 'sys') {
    // Diamond
    ctx.moveTo(node.x, node.y - radius);
    ctx.lineTo(node.x + radius, node.y);
    ctx.lineTo(node.x, node.y + radius);
    ctx.lineTo(node.x - radius, node.y);
    ctx.closePath();
  } else {
    // Circle
    ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
  }

  ctx.fillStyle = baseColor;
  ctx.fill();
  ctx.strokeStyle = isSelected ? '#ffffff' : (isHovered ? '#00d4ff' : 'rgba(255,255,255,0.25)');
  ctx.lineWidth = isSelected ? 2.5 : 1.5;
  ctx.stroke();

  // Glyph icon inside node
  const glyph = { ip: '🌐', user: '👤', sys: '🖥️', event: '⚡' }[node.type] || '●';
  ctx.font = `${13 / scale}px Arial`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(glyph, node.x, node.y);

  // Label text below node
  if (showLabels && node.label) {
    ctx.font = `${10 / scale}px 'JetBrains Mono', monospace`;
    ctx.fillStyle = node.is_suspicious ? '#ff4757' : (isSelected ? '#00d4ff' : '#8892a4');
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const displayLabel = node.label.length > 20 ? node.label.substring(0, 18) + '…' : node.label;
    ctx.fillText(displayLabel, node.x, node.y + radius + 5);
  }
}

function drawEmptyState(msg) {
  if (!ctx || !canvas) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#0a0e1a';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#8892a4';
  ctx.font = '14px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(msg, canvas.width / 2, canvas.height / 2);
}

function onMouseDown(e) {
  isPanning = true;
  lastMx = e.clientX;
  lastMy = e.clientY;
}

function onMouseMove(e) {
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left - panX) / scale;
  const my = (e.clientY - rect.top - panY) / scale;

  // Hover detection
  const prev = hoveredNode;
  hoveredNode = graphData.nodes?.find(n => {
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx * dx + dy * dy) <= 22;
  }) || null;

  canvas.style.cursor = hoveredNode ? 'pointer' : (isPanning ? 'grabbing' : 'grab');
  if (prev !== hoveredNode) drawGraph();

  if (isPanning) {
    panX += e.clientX - lastMx;
    panY += e.clientY - lastMy;
    lastMx = e.clientX;
    lastMy = e.clientY;
    drawGraph();
  }
}

function onMouseUp(e) {
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left - panX) / scale;
  const my = (e.clientY - rect.top - panY) / scale;

  // Check if click on a node
  const clicked = graphData.nodes?.find(n => {
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx * dx + dy * dy) <= 22;
  });

  if (clicked) {
    selectedNode = clicked;
    updateInspectorPanel(selectedNode);
    drawGraph();
  }

  isPanning = false;
}

function onWheel(e) {
  e.preventDefault();
  const delta = e.deltaY > 0 ? 0.9 : 1.1;
  scale = Math.max(0.3, Math.min(3, scale * delta));
  drawGraph();
}

function updateInspectorPanel(node) {
  const emptyPanel = document.getElementById('nodeInfoEmpty');
  const contentPanel = document.getElementById('nodeInfoContent');

  if (!node) {
    if (emptyPanel) emptyPanel.style.display = 'block';
    if (contentPanel) contentPanel.style.display = 'none';
    return;
  }

  if (emptyPanel) emptyPanel.style.display = 'none';
  if (contentPanel) contentPanel.style.display = 'block';

  setElementText('infoEntityTypeBadge', (node.type || 'ENTITY').toUpperCase());
  setElementText('infoEntityLabel', node.label || 'Unknown');
  setElementText('infoNodeType', node.type?.toUpperCase() || '—');
  setElementText('infoNodeThreat', node.is_suspicious ? 'Critical Threat Risk' : 'Normal / Monitored');
  setElementText('infoNodeFirstSeen', node.first_seen || '—');
  setElementText('infoNodeDegree', `${node.degree || 1} Connected Vertices`);
  setElementText('infoNodeDescription', node.description || 'Observed entity in telemetry correlation graph.');

  const threatEl = document.getElementById('infoNodeThreat');
  if (threatEl) {
    threatEl.className = 'e-val ' + (node.is_suspicious ? 'text-red' : 'text-cyan');
  }
}

function setElementText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
