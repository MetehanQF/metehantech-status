const metricLabels = { temperature: "Temperature", ram: "RAM", disk: "Disk", load: "Load Average" };
const devicesEl = document.getElementById("devices");
const servicesEl = document.getElementById("services");

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
}

function meterValue(key, raw) {
  const match = String(raw ?? "").match(/^\s*(\d+(?:\.\d+)?)/);
  if (!match) return null;
  const number = Number(match[1]);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : null;
}

function meterTone(key, value) {
  if (value === null) return "unknown";
  const critical =  key === "temperature" ? 80 : 90;
  const warning = key === "temperature" ? 70 : 80;
  return value >= critical ? "critical" : value >= warning ? "warning" : "normal";
}

function renderDevice(device) {
  const card = element("article", `panel device-card ${device.online ? "online" : "offline"}`);
  const head = element("div", "device-head");
  const identity = element("div", "device-identity");
  identity.append(element("p", "eyebrow", device.kind), element("h3", "", device.name));
  const state = element("span", `state ${device.online ? "good" : "bad"}`);
  state.append(element("span", "state-dot"), document.createTextNode(device.online ? "Online" : "Offline"));
  head.append(identity, state);
  card.append(head);

  const metrics = element("div", "metrics");
  for (const [key, label] of Object.entries(metricLabels)) {
    const raw = device.metrics?.[key] ?? "UNKNOWN";
    const metric = element("div", `metric ${String(raw).toUpperCase() === "UNKNOWN" ? "metric-unknown" : ""}`);
    metric.append(element("span", "metric-label", label), element("strong", "metric-value", raw));
    if (key !== "load") {
      const value = meterValue(key, raw);
      const track = element("div", `meter ${meterTone(key, value)}`);
      track.setAttribute("role", "progressbar");
      track.setAttribute("aria-label", `${label} ${raw}`);
      track.setAttribute("aria-valuemin", "0");
      track.setAttribute("aria-valuemax", "100");
      if (value !== null) track.setAttribute("aria-valuenow", String(value));
      const fill = element("span", "meter-fill");
      fill.style.width = `${value ?? 0}%`;
      track.append(fill);
      metric.append(track);
    }
    metrics.append(metric);
  }
  card.append(metrics);
  if (device.uptime) {
    const uptime = element("p", "device-uptime");
    uptime.append(element("span", "", "Uptime"), element("strong", "", device.uptime));
    card.append(uptime);
  }

  const checks = element("div", "checks");
  for (const [name, value] of Object.entries(device.checks || {})) {
    const unknown = value === null;
    const healthy = !unknown && (name === "Throttled" ? value === false : value === true);
    const label = unknown ? `${name} · UNKNOWN` : name === "Throttled" ? `Throttled · ${healthy ? "OK" : "DETECTED"}` : name;
    const check = element("span", `check ${unknown ? "unknown" : healthy ? "good" : "bad"}`);
    check.append(element("span", "check-dot"), document.createTextNode(label));
    checks.append(check);
  }
  card.append(checks);
  return card;
}

function renderService(service) {
  const state = service.operational === null ? "unknown" : service.operational ? "good" : "bad";
  const card = element("article", `panel service-card ${state}`);
  const icon = element("span", `service-icon ${state}`, state === "unknown" ? "?" : state === "good" ? "✓" : "!");
  const info = element("div", "service-info");
  info.append(element("h3", "", service.name), element("span", "service-subtitle", state === "unknown" ? "UNKNOWN" : state === "good" ? "Operational" : "Down"));
  card.append(icon, info, element("span", `service-indicator ${state}`));
  return card;
}

function render(data) {
  const healthy = data.health ? data.health === "HEALTHY" : Boolean(data.operational);
  const overview = document.querySelector(".overview");
  overview.classList.toggle("problem", !healthy);
  document.getElementById("overview-icon").textContent = healthy ? "✓" : "!";
  document.getElementById("overall-status").textContent = healthy ? "All Systems Operational" : (data.health || "Problems Detected");
  document.getElementById("overview-description").textContent = healthy ? "All monitored devices and services are running normally." : "One or more monitored systems need attention.";
  document.getElementById("overview-pill").textContent = healthy ? "Operational" : "Attention needed";
  devicesEl.replaceChildren(...(data.devices || []).map(renderDevice));
  servicesEl.replaceChildren(...(data.services || []).map(renderService));
  const time = new Date(data.updated_at);
  const timeEl = document.getElementById("updated-at");
  timeEl.dateTime = data.updated_at;
  timeEl.textContent = Number.isNaN(time.getTime()) ? "—" : time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

async function refresh() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    document.querySelector(".overview").classList.add("problem");
    document.getElementById("overview-icon").textContent = "!";
    document.getElementById("overall-status").textContent = "Status Unavailable";
    document.getElementById("overview-description").textContent = "Could not retrieve the latest monitoring data.";
    document.getElementById("overview-pill").textContent = "Connection error";
    console.error("Status refresh failed:", error);
  }
}

refresh();
setInterval(refresh, 5000);
