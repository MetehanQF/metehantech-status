const eventState = { severity: "", source: "" };
const eventSources = {
  pi5: "Raspberry Pi 5", pcold: "MetehanTechPcOld", docker: "Docker",
  cloudflared: "Cloudflare Tunnel", tailscale: "Tailscale", rustdesk: "RustDesk",
  metehantech_home: "MetehanTech Home", metehantech_clan: "MetehanTech Clan"
};
const eventList = document.getElementById("events-list");
const incidentSummary = document.getElementById("events-summary");
const incidentCount = document.getElementById("active-incidents");

function eventElement(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
}

function eventTime(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
  });
}

function renderEvent(event) {
  const severity = ["info", "warning", "critical", "recovery"].includes(event.severity) ? event.severity : "info";
  const row = eventElement("article", `panel event-row ${severity}`);
  const icon = eventElement("span", "event-icon", severity === "recovery" ? "✓" : severity === "info" ? "i" : "!");
  icon.setAttribute("aria-label", severity);
  const main = eventElement("div", "event-main");
  const heading = eventElement("div", "event-heading");
  heading.append(eventElement("h3", "", event.title), eventElement("span", `event-status ${event.status === "active" ? "active" : "resolved"}`, event.status));
  main.append(heading, eventElement("p", "event-message", event.message));
  const meta = eventElement("div", "event-meta");
  meta.append(eventElement("span", "event-source", eventSources[event.source] || event.source));
  const time = eventElement("time", "", eventTime(event.timestamp));
  time.dateTime = event.timestamp;
  meta.append(time);
  main.append(meta);
  row.append(icon, main);
  return row;
}

function renderEvents(payload) {
  const count = Number(payload.active_incidents) || 0;
  incidentSummary.classList.toggle("has-incidents", count > 0);
  incidentSummary.querySelector(".events-summary-icon").textContent = count > 0 ? "!" : "✓";
  incidentCount.textContent = count > 0 ? `Active incidents: ${count}` : "No active incidents";
  const events = Array.isArray(payload.events) ? payload.events : [];
  if (events.length) eventList.replaceChildren(...events.map(renderEvent));
  else eventList.replaceChildren(eventElement("p", "events-empty panel", "No events match the current filters."));
}

async function loadEvents() {
  const severity = eventState.severity;
  const source = eventState.source;
  const params = new URLSearchParams({ limit: "50" });
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  try {
    const response = await fetch(`/api/events?${params}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    if (severity !== eventState.severity || source !== eventState.source) return;
    renderEvents(payload);
  } catch (error) {
    if (severity !== eventState.severity || source !== eventState.source) return;
    eventList.replaceChildren(eventElement("p", "events-empty panel", "Events temporarily unavailable."));
    console.error("Events refresh failed:", error);
  }
}

document.getElementById("event-severities").addEventListener("click", event => {
  const button = event.target.closest("button");
  if (!button || !event.currentTarget.contains(button)) return;
  eventState.severity = button.dataset.severity;
  for (const choice of event.currentTarget.querySelectorAll("button")) choice.setAttribute("aria-pressed", String(choice === button));
  loadEvents();
});
document.getElementById("event-source").addEventListener("change", event => {
  eventState.source = event.target.value;
  loadEvents();
});
loadEvents();
setInterval(loadEvents, 30000);
