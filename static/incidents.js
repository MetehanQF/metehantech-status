const incidentState = { status: "" };
const incidentSources = {
  pi5: "Raspberry Pi 5", pcold: "MetehanTechPcOld", docker: "Docker",
  cloudflared: "Cloudflare Tunnel", tailscale: "Tailscale", rustdesk: "RustDesk",
  metehantech_home: "MetehanTech Home", metehantech_clan: "MetehanTech Clan"
};
const incidentsList = document.getElementById("incidents-list");

function incidentElement(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const value = Math.floor(seconds);
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.floor(value / 60)}m ${value % 60}s`;
  if (value < 86400) return `${Math.floor(value / 3600)}h ${Math.floor(value % 3600 / 60)}m`;
  return `${Math.floor(value / 86400)}d ${Math.floor(value % 86400 / 3600)}h`;
}

function incidentTime(timestamp) {
  if (!timestamp) return "—";
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

function addIncidentDetail(grid, label, value, className) {
  const item = incidentElement("div", "incident-detail");
  item.append(incidentElement("span", "", label), incidentElement("strong", className || "", value));
  grid.append(item);
  return item.querySelector("strong");
}

function renderIncident(incident) {
  const severity = incident.severity === "warning" ? "warning" : "critical";
  const active = incident.status === "active";
  const card = incidentElement("article", `panel incident-card ${severity}`);
  const top = incidentElement("div", "incident-top");
  top.append(incidentElement("span", `incident-severity ${severity}`, severity.toUpperCase()), incidentElement("span", `incident-badge ${active ? "active" : "resolved"}`, active ? "ACTIVE" : "RESOLVED"));
  card.append(top, incidentElement("h4", "", incident.title), incidentElement("p", "incident-source", incidentSources[incident.source] || incident.source));
  const grid = incidentElement("div", "incident-details");
  addIncidentDetail(grid, "Started", incidentTime(incident.started_at));
  addIncidentDetail(grid, "Recovered", active ? "Ongoing" : incidentTime(incident.resolved_at), active ? "ongoing" : "");
  const started = new Date(incident.started_at).getTime();
  const elapsed = (Date.now() - started) / 1000;
  const duration = addIncidentDetail(grid, "Duration", formatDuration(active ? elapsed : incident.duration_seconds == null ? NaN : Number(incident.duration_seconds)), "incident-duration");
  if (active && Number.isFinite(started)) duration.dataset.startedAt = incident.started_at;
  card.append(grid);
  return card;
}

function updateOngoingDurations() {
  for (const element of incidentsList.querySelectorAll(".incident-duration[data-started-at]")) {
    element.textContent = formatDuration((Date.now() - new Date(element.dataset.startedAt).getTime()) / 1000);
  }
}

async function loadIncidents() {
  const status = incidentState.status;
  const params = new URLSearchParams({ limit: "20" });
  if (status) params.set("status", status);
  try {
    const response = await fetch(`/api/incidents?${params}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    if (status !== incidentState.status) return;
    const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
    incidentsList.replaceChildren(...(incidents.length
      ? incidents.map(renderIncident)
      : [incidentElement("p", "events-empty panel", "No incidents match the current filter.")]));
  } catch (error) {
    if (status !== incidentState.status) return;
    incidentsList.replaceChildren(incidentElement("p", "events-empty panel", "Incident history temporarily unavailable."));
    console.error("Incident refresh failed:", error);
  }
}

document.getElementById("incident-statuses").addEventListener("click", event => {
  const button = event.target.closest("button");
  if (!button || !event.currentTarget.contains(button)) return;
  incidentState.status = button.dataset.status;
  for (const choice of event.currentTarget.querySelectorAll("button")) choice.setAttribute("aria-pressed", String(choice === button));
  loadIncidents();
});
loadIncidents();
setInterval(loadIncidents, 30000);
setInterval(updateOngoingDurations, 1000);
