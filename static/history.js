const historyState = { device: "pi5", range: "24h", points: [], error: null };
const chartColors = { temperature: "#b56bfa", ram: "#9e63f5", disk: "#d477e8", load: "#8b5cf6" };
const chartLabels = { temperature: "Temperature", ram: "RAM Usage", disk: "Disk Usage", load: "Load Average" };
const chartUnits = { temperature: "°C", ram: "%", disk: "%", load: "" };
const charts = [...document.querySelectorAll(".chart-card")];

function chartTime(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function chartNumber(value) {
  return Number.isFinite(value) ? (Math.round(value * 10) / 10).toString() : "—";
}

function drawChart(card) {
  const canvas = card.querySelector("canvas");
  const metric = canvas.dataset.metric;
  const context = canvas.getContext("2d");
  if (!context) return;
  const width = Math.max(1, Math.floor(canvas.clientWidth));
  const height = Math.max(1, Math.floor(canvas.clientHeight));
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.font = "11px Inter, system-ui, sans-serif";
  context.textBaseline = "middle";
  const bounds = { left: 42, right: width - 13, top: 16, bottom: height - 28 };
  if (bounds.right <= bounds.left || bounds.bottom <= bounds.top) return;
  const values = historyState.points.map(point => typeof point[metric] === "number" && Number.isFinite(point[metric]) ? point[metric] : null);
  const valid = values.filter(value => value !== null);
  if (historyState.error || valid.length === 0) {
    context.fillStyle = "#a895b6";
    context.textAlign = "center";
    context.fillText(historyState.error || "Waiting for the first sample…", width / 2, height / 2);
    card._chartPositions = [];
    return;
  }
  let min = Math.min(...valid);
  let max = Math.max(...valid);
  const padding = Math.max((max - min) * 0.15, metric === "load" ? 0.1 : 1);
  min = Math.max(0, min - padding);
  max += padding;
  if (max <= min) max = min + 1;
  const y = value => bounds.bottom - (value - min) / (max - min) * (bounds.bottom - bounds.top);
  const firstValid = values.findIndex(value => value !== null);
  const lastValid = values.findLastIndex(value => value !== null);
  const x = index => firstValid === lastValid
    ? (bounds.left + bounds.right) / 2
    : bounds.left + (index - firstValid) / (lastValid - firstValid) * (bounds.right - bounds.left);

  context.strokeStyle = "rgba(177, 129, 205, .13)";
  context.fillStyle = "#a895b6";
  context.lineWidth = 1;
  context.textAlign = "right";
  for (let line = 0; line <= 3; line++) {
    const yy = bounds.top + line / 3 * (bounds.bottom - bounds.top);
    context.beginPath();
    context.moveTo(bounds.left, yy);
    context.lineTo(bounds.right, yy);
    context.stroke();
    context.fillText(chartNumber(max - line / 3 * (max - min)), bounds.left - 8, yy);
  }
  context.textAlign = "left";
  context.fillText(chartTime(historyState.points[firstValid].timestamp), bounds.left, height - 9);
  context.textAlign = "right";
  context.fillText(chartTime(historyState.points[lastValid].timestamp), bounds.right, height - 9);

  const color = chartColors[metric];
  const fill = context.createLinearGradient(0, bounds.top, 0, bounds.bottom);
  fill.addColorStop(0, `${color}40`);
  fill.addColorStop(1, `${color}00`);
  let segment = [];
  function paintSegment() {
    if (!segment.length) return;
    context.beginPath();
    context.moveTo(segment[0].x, bounds.bottom);
    for (const point of segment) context.lineTo(point.x, point.y);
    context.lineTo(segment.at(-1).x, bounds.bottom);
    context.closePath();
    context.fillStyle = fill;
    context.fill();
    context.beginPath();
    context.moveTo(segment[0].x, segment[0].y);
    for (const point of segment.slice(1)) context.lineTo(point.x, point.y);
    context.strokeStyle = color;
    context.lineWidth = 2;
    context.lineJoin = "round";
    context.stroke();
    if (segment.length === 1) {
      context.beginPath();
      context.arc(segment[0].x, segment[0].y, 3, 0, Math.PI * 2);
      context.fillStyle = color;
      context.fill();
    }
    segment = [];
  }
  card._chartPositions = values.map((value, index) => value === null ? null : { x: x(index), y: y(value), value, timestamp: historyState.points[index].timestamp });
  for (const point of card._chartPositions) {
    if (point) segment.push(point);
    else paintSegment();
  }
  paintSegment();
}

function drawAllCharts() {
  for (const card of charts) drawChart(card);
}

async function loadHistory() {
  const device = historyState.device;
  const range = historyState.range;
  try {
    const response = await fetch(`/api/history?device=${encodeURIComponent(device)}&range=${encodeURIComponent(range)}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const points = await response.json();
    if (!Array.isArray(points)) throw new Error("Invalid history response");
    if (device !== historyState.device || range !== historyState.range) return;
    historyState.points = points;
    historyState.error = null;
  } catch (error) {
    if (device !== historyState.device || range !== historyState.range) return;
    historyState.points = [];
    historyState.error = "History temporarily unavailable";
    console.error("History refresh failed:", error);
  }
  drawAllCharts();
}

for (const group of [document.getElementById("history-devices"), document.getElementById("history-ranges")]) {
  group.addEventListener("click", event => {
    const button = event.target.closest("button");
    if (!button || !group.contains(button)) return;
    const key = button.dataset.device ? "device" : "range";
    const value = button.dataset[key];
    if (historyState[key] === value) return;
    historyState[key] = value;
    for (const choice of group.querySelectorAll("button")) choice.setAttribute("aria-pressed", String(choice === button));
    historyState.points = [];
    historyState.error = null;
    drawAllCharts();
    loadHistory();
  });
}

for (const card of charts) {
  const canvas = card.querySelector("canvas");
  const tooltip = card.querySelector(".chart-tooltip");
  canvas.addEventListener("pointermove", event => {
    const positions = card._chartPositions || [];
    if (!positions.length) { tooltip.hidden = true; return; }
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    let nearest = null;
    for (const point of positions) if (point && (!nearest || Math.abs(point.x - x) < Math.abs(nearest.x - x))) nearest = point;
    if (!nearest || Math.abs(nearest.x - x) > 28) { tooltip.hidden = true; return; }
    const metric = canvas.dataset.metric;
    tooltip.textContent = `${chartLabels[metric]}: ${chartNumber(nearest.value)}${chartUnits[metric]} · ${chartTime(nearest.timestamp)}`;
    tooltip.style.left = `${Math.min(Math.max(nearest.x, 90), rect.width - 90)}px`;
    tooltip.style.top = `${Math.max(0, nearest.y - 42)}px`;
    tooltip.hidden = false;
  });
  canvas.addEventListener("pointerleave", () => { tooltip.hidden = true; });
}

if ("ResizeObserver" in window) {
  const observer = new ResizeObserver(() => requestAnimationFrame(drawAllCharts));
  for (const card of charts) observer.observe(card.querySelector("canvas"));
} else window.addEventListener("resize", drawAllCharts);
loadHistory();
setInterval(loadHistory, 60000);
