/* CYBERTRACE AI — Attack Reconstruction Graph JavaScript */

let graphData = { nodes: [], edges: [] };
let canvas, ctx;
let scale = 1, panX = 0, panY = 0;
let isPanning = false, lastMx = 0, lastMy = 0;
let hoveredNode = null;

const NODE_COLORS = {
  ip: { normal: '#3b82f6', suspicious: '#ff4757', text: '#fff' },
  user: { normal: '#00d4ff', suspicious: '#ffa502', text: '#000' },
  event: { normal: '#ffd32a', suspicious: '#ff4757', text: '#000' }
};
const EDGE_COLORS = { confirmed: '#00ff88', inferred: '#4a5568' };

document.addEventListener('DOMContentLoaded', () => {
  canvas = document.getElementById('attack-canvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Pan interactions
  canvas.addEventListener('mousedown', onMouseDown);
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseup', () => { isPanning = false; });
  canvas.addEventListener('mouseleave', () => { isPanning = false; hoveredNode = null; drawGraph(); });
  canvas.addEventListener('wheel', onWheel, { passive: false });

  loadGraph();
});

function resizeCanvas() {
  if (!canvas) return;
  const container = canvas.parentElement;
  canvas.width = container.clientWidth;
  canvas.height = Math.max(500, container.clientHeight);
  drawGraph();
}

async function loadGraph() {
  const caseId = document.getElementById('graph-case-id')?.value;
  if (!caseId) {
    drawEmptyState('Select a case to load the attack graph');
    return;
  }
  drawEmptyState('Loading graph data…');
  try {
    const data = await apiRequest('/api/attack-graph/data?case_id=' + caseId);
    graphData = data;

    // Update stats
    setEl('node-count', data.stats?.total_nodes || 0);
    setEl('edge-count', data.stats?.total_edges || 0);
    setEl('suspicious-count', data.stats?.suspicious_nodes || 0);

    // Auto-layout if not already set
    spreadNodes(data.nodes);
    scale = 1; panX = 0; panY = 0;
    drawGraph();
  } catch (e) {
    drawEmptyState('Error loading graph: ' + e.message);
  }
}

function spreadNodes(nodes) {
  if (!nodes.length) return;
  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h / 2;
  const radius = Math.min(w, h) * 0.35;
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    node.x = cx + radius * Math.cos(angle);
    node.y = cy + radius * Math.sin(angle);
  });
}

function drawGraph() {
  if (!ctx || !canvas) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Dark background
  ctx.fillStyle = '#0a0e1a';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Grid
  ctx.strokeStyle = 'rgba(30,45,61,0.4)';
  ctx.lineWidth = 1;
  const gridSize = 50 * scale;
  const offsetX = panX % gridSize;
  const offsetY = panY % gridSize;
  for (let x = offsetX; x < canvas.width; x += gridSize) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
  }
  for (let y = offsetY; y < canvas.height; y += gridSize) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
  }

  if (!graphData.nodes.length) return;

  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(scale, scale);

  // Draw edges
  graphData.edges.forEach(edge => drawEdge(edge));
  // Draw nodes
  graphData.nodes.forEach(node => drawNode(node));

  ctx.restore();
}

function drawEdge(edge) {
  const from = graphData.nodes.find(n => n.id === edge.from);
  const to = graphData.nodes.find(n => n.id === edge.to);
  if (!from || !to) return;

  ctx.beginPath();
  ctx.moveTo(from.x, from.y);
  // Slight curve
  const mx = (from.x + to.x) / 2;
  const my = (from.y + to.y) / 2 - 20;
  ctx.quadraticCurveTo(mx, my, to.x, to.y);

  ctx.strokeStyle = edge.type === 'confirmed' ? EDGE_COLORS.confirmed : EDGE_COLORS.inferred;
  ctx.lineWidth = edge.type === 'confirmed' ? 2 : 1;
  ctx.globalAlpha = 0.6;
  if (edge.type === 'inferred') {
    ctx.setLineDash([5, 5]);
  } else {
    ctx.setLineDash([]);
  }
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.globalAlpha = 1;

  // Arrow head
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  const arrowLen = 10;
  const ax = to.x - arrowLen * Math.cos(angle);
  const ay = to.y - arrowLen * Math.sin(angle);
  ctx.beginPath();
  ctx.moveTo(to.x, to.y);
  ctx.lineTo(ax - 5 * Math.sin(angle), ay + 5 * Math.cos(angle));
  ctx.lineTo(ax + 5 * Math.sin(angle), ay - 5 * Math.cos(angle));
  ctx.closePath();
  ctx.fillStyle = edge.type === 'confirmed' ? EDGE_COLORS.confirmed : EDGE_COLORS.inferred;
  ctx.fill();

  // Edge label
  if (edge.label) {
    ctx.fillStyle = '#4a5568';
    ctx.font = `${10 / scale}px Inter, sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(edge.label, mx, my - 5);
  }
}

function drawNode(node) {
  const colors = NODE_COLORS[node.type] || NODE_COLORS.ip;
  const color = node.is_suspicious ? colors.suspicious : colors.normal;
  const isHovered = hoveredNode === node;
  const radius = isHovered ? 22 : 18;

  // Glow for suspicious
  if (node.is_suspicious) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
    const gradient = ctx.createRadialGradient(node.x, node.y, radius, node.x, node.y, radius + 8);
    gradient.addColorStop(0, 'rgba(255,71,87,0.3)');
    gradient.addColorStop(1, 'rgba(255,71,87,0)');
    ctx.fillStyle = gradient;
    ctx.fill();
  }

  // Node circle
  ctx.beginPath();
  ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.fill();
  ctx.strokeStyle = isHovered ? '#fff' : 'rgba(255,255,255,0.2)';
  ctx.lineWidth = isHovered ? 2 : 1;
  ctx.stroke();

  // Node type icon
  const icon = { ip: '🌐', user: '👤', event: '⚡' }[node.type] || '●';
  ctx.font = `${13 / scale}px Arial`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(icon, node.x, node.y);

  // Label
  ctx.font = `${10 / scale}px Inter, sans-serif`;
  ctx.fillStyle = node.is_suspicious ? '#ff4757' : '#8892a4';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.fillText(node.label?.substring(0, 15), node.x, node.y + radius + 4);
}

function drawEmptyState(text) {
  if (!ctx || !canvas) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#0a0e1a';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#4a5568';
  ctx.font = '14px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, canvas.width / 2, canvas.height / 2);
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

  // Check hover
  const prev = hoveredNode;
  hoveredNode = graphData.nodes.find(n => {
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx * dx + dy * dy) < 20;
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

function onWheel(e) {
  e.preventDefault();
  const delta = e.deltaY > 0 ? 0.9 : 1.1;
  scale = Math.max(0.3, Math.min(3, scale * delta));
  drawGraph();
}

function zoomIn() { scale = Math.min(3, scale * 1.2); drawGraph(); }
function zoomOut() { scale = Math.max(0.3, scale / 1.2); drawGraph(); }
function resetView() { scale = 1; panX = 0; panY = 0; drawGraph(); }
function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
