const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const servicesEl = document.getElementById("admin-services");
const containersEl = document.getElementById("admin-containers");
const messageEl = document.getElementById("admin-message");
const logEl = document.getElementById("admin-log");
const logResourceEl = document.getElementById("log-resource");
let selectedResource = null;
let selectedLines = 100;
let activityLimit = 50;
let alertStatus = "active";
let alertSeverity = "";
let alertLimit = 50;
let backupPolling = false;

function showMessage(text, error = false) {
  messageEl.textContent = text;
  messageEl.className = `admin-alert${error ? " error" : ""}`;
  messageEl.hidden = false;
}

function resourceCard(resource, type) {
  const card = document.createElement("article");
  card.className = "panel admin-resource";
  const head = document.createElement("div");
  head.className = "admin-resource-head";
  const identity = document.createElement("div");
  const title = document.createElement("h3");
  title.textContent = resource.name;
  const id = document.createElement("span");
  id.className = "admin-resource-id";
  id.textContent = resource.id;
  identity.append(title, id);
  const state = document.createElement("span");
  state.className = `admin-state ${resource.state}`;
  state.textContent = resource.state;
  head.append(identity, state);
  const actions = document.createElement("div");
  actions.className = "admin-actions";
  const logs = document.createElement("button");
  logs.type = "button";
  logs.className = "admin-button";
  logs.textContent = "View logs";
  logs.addEventListener("click", () => selectLogs(type, resource.id));
  const restart = document.createElement("button");
  restart.type = "button";
  restart.className = "admin-button";
  restart.textContent = "Restart";
  restart.addEventListener("click", () => restartResource(type, resource.id, restart));
  actions.append(logs, restart);
  card.append(head, actions);
  return card;
}

function renderResources(target, resources, type) {
  if (!resources.length) {
    const empty = document.createElement("p");
    empty.className = "panel admin-empty";
    empty.textContent = type === "containers" ? "No Docker containers are configured in the admin whitelist." : "No approved services found.";
    target.replaceChildren(empty);
    return;
  }
  target.replaceChildren(...resources.map((resource) => resourceCard(resource, type)));
}

async function loadResources() {
  try {
    const response = await fetch("/api/admin/resources", { cache: "no-store" });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    renderResources(servicesEl, data.services || [], "services");
    renderResources(containersEl, data.containers || [], "containers");
  } catch (error) {
    showMessage("Could not load approved resources.", true);
  }
}

async function responseJson(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    return await response.json();
  } catch (error) {
    return null;
  }
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function waitForControlCenter(button) {
  showMessage("Restarting Control Center... reconnecting.");
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await wait(1000);
    try {
      const response = await fetch("/api/admin/health", { cache: "no-store" });
      const data = await responseJson(response);
      if (response.ok && data?.ok === true) {
        showMessage("Control Center restarted successfully.");
        button.disabled = false;
        await Promise.all([loadResources(), loadAlerts(), loadActivity()]);
        return;
      }
    } catch (error) {
      // A connection failure is expected while the Control Center process restarts.
    }
  }
  button.disabled = false;
  showMessage("Control Center restart is taking longer than expected. Refresh the page to check it.", true);
}

async function restartResource(type, id, button) {
  if (!window.confirm(`Restart ${id}?`)) return;
  const selfRestart = type === "services" && id === "metehantech-status.service";
  button.disabled = true;
  try {
    const response = await fetch(`/api/admin/${type}/${encodeURIComponent(id)}/restart`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
    });
    const data = await responseJson(response);
    if (selfRestart && (!response.ok || !data)) {
      await waitForControlCenter(button);
      return;
    }
    if (!response.ok) throw new Error(data?.error || `HTTP ${response.status}`);
    showMessage(data.message || "Restart requested.");
    if (selfRestart) {
      await waitForControlCenter(button);
      return;
    }
    await Promise.all([loadResources(), loadAlerts(), loadActivity()]);
  } catch (error) {
    if (selfRestart) {
      await waitForControlCenter(button);
      return;
    }
    showMessage(error.message || "Restart failed.", true);
  } finally {
    if (!selfRestart) button.disabled = false;
  }
}

async function selectLogs(type, id) {
  selectedResource = { type, id };
  logResourceEl.textContent = id;
  await loadLogs();
}

async function loadLogs() {
  if (!selectedResource) return;
  logEl.textContent = "Loading logs…";
  try {
    const { type, id } = selectedResource;
    const response = await fetch(`/api/admin/${type}/${encodeURIComponent(id)}/logs?lines=${selectedLines}`, { cache: "no-store" });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    logEl.textContent = data.log || "No log output.";
    loadActivity();
  } catch (error) {
    logEl.textContent = error.message || "Logs are unavailable.";
  }
}

function activityCell(value, className = "") {
  const cell = document.createElement("span");
  cell.className = className;
  cell.textContent = value || "—";
  return cell;
}

function renderActivity(entries) {
  const target = document.getElementById("admin-activity");
  const header = document.createElement("div");
  header.className = "admin-activity-row header";
  for (const label of ["Timestamp", "Action", "Target", "Result", "Client IP", "User agent"]) header.append(activityCell(label));
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "admin-activity-empty";
    empty.textContent = "No admin activity recorded yet.";
    target.replaceChildren(header, empty);
    return;
  }
  const rows = entries.map((entry) => {
    const row = document.createElement("div");
    row.className = "admin-activity-row";
    const timestamp = new Date(entry.timestamp);
    const displayTime = Number.isNaN(timestamp.getTime()) ? entry.timestamp : timestamp.toLocaleString();
    row.append(
      activityCell(displayTime),
      activityCell(entry.action),
      activityCell(entry.target),
      activityCell(entry.result, `activity-result ${entry.result}`),
      activityCell(entry.client_ip),
      activityCell(entry.user_agent),
    );
    return row;
  });
  target.replaceChildren(header, ...rows);
}

async function loadActivity() {
  try {
    const response = await fetch(`/api/admin/activity?limit=${activityLimit}`, { cache: "no-store" });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    renderActivity(data.entries || []);
  } catch (error) {
    showMessage(error.message || "Could not load admin activity.", true);
  }
}

function formatDuration(seconds) {
  const value = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const remainder = value % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${remainder}s`;
  return `${remainder}s`;
}

function renderAlerts(entries) {
  const target = document.getElementById("admin-alerts");
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "panel admin-empty";
    empty.textContent = "No alerts match this filter.";
    target.replaceChildren(empty);
    return;
  }
  const now = Date.now();
  const cards = entries.map((entry) => {
    const card = document.createElement("article");
    card.className = `panel admin-alert-card ${entry.status === "resolved" ? "resolved" : entry.severity}`;
    const head = document.createElement("div");
    head.className = "admin-alert-head";
    const identity = document.createElement("div");
    const severity = document.createElement("span");
    severity.className = `admin-alert-severity ${entry.status === "resolved" ? "resolved" : entry.severity}`;
    severity.textContent = entry.status === "resolved" ? "RESOLVED" : entry.severity;
    const title = document.createElement("h3");
    title.textContent = entry.title;
    const resource = document.createElement("p");
    resource.className = "admin-alert-target";
    resource.textContent = entry.target;
    identity.append(severity, title, resource);
    const status = document.createElement("span");
    status.className = `admin-alert-status ${entry.status}`;
    status.textContent = entry.status;
    head.append(identity, status);
    const message = document.createElement("p");
    message.className = "admin-alert-message";
    message.textContent = entry.message;
    const details = document.createElement("div");
    details.className = "admin-alert-details";
    const started = new Date(entry.created_at);
    const resolved = entry.resolved_at ? new Date(entry.resolved_at) : null;
    const duration = entry.duration_seconds ?? Math.max(0, Math.floor((now - started.getTime()) / 1000));
    for (const [label, value] of [
      ["Started", Number.isNaN(started.getTime()) ? entry.created_at : started.toLocaleString()],
      ["Resolved", resolved && !Number.isNaN(resolved.getTime()) ? resolved.toLocaleString() : "—"],
      [entry.status === "active" ? "Active for" : "Duration", formatDuration(duration)],
      ["Last value", entry.last_value || "—"],
      ["Threshold", entry.threshold],
    ]) {
      const item = document.createElement("span");
      item.append(document.createTextNode(`${label}: `), Object.assign(document.createElement("strong"), { textContent: value }));
      details.append(item);
    }
    card.append(head, message, details);
    return card;
  });
  target.replaceChildren(...cards);
}

async function loadAlerts() {
  const params = new URLSearchParams({ limit: String(alertLimit) });
  if (alertStatus) params.set("status", alertStatus);
  if (alertSeverity) params.set("severity", alertSeverity);
  try {
    const [alertsResponse, summaryResponse] = await Promise.all([
      fetch(`/api/admin/alerts?${params}`, { cache: "no-store" }),
      fetch("/api/admin/alerts/summary", { cache: "no-store" }),
    ]);
    const [alertsData, summaryData] = await Promise.all([responseJson(alertsResponse), responseJson(summaryResponse)]);
    if (!alertsResponse.ok || !alertsData) throw new Error(alertsData?.error || `HTTP ${alertsResponse.status}`);
    if (!summaryResponse.ok || !summaryData) throw new Error(summaryData?.error || `HTTP ${summaryResponse.status}`);
    document.getElementById("alert-critical-count").textContent = summaryData.active_critical;
    document.getElementById("alert-warning-count").textContent = summaryData.active_warning;
    document.getElementById("alert-resolved-count").textContent = summaryData.resolved_today;
    renderAlerts(alertsData.alerts || []);
  } catch (error) {
    showMessage(error.message || "Could not load infrastructure alerts.", true);
  }
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let amount = bytes;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function backupTime(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function backupFreshness(records, node, now = Date.now()) {
  const good = records.filter((r) => r.source_node === node && r.status === "success" && r.checksum_status === "verified" && r.verification_status === "verified" && Number.isFinite(Date.parse(r.finished_at)));
  good.sort((a, b) => Date.parse(b.finished_at) - Date.parse(a.finished_at));
  const last = good[0] || null;
  if (!last) return { last: null, level: "unknown", hours: null };
  const hours = (now - Date.parse(last.finished_at)) / 3600000;
  return { last, hours, level: hours < 0 ? "unknown" : hours < 24 ? "OK" : hours <= 36 ? "warning" : "critical" };
}

function renderBackupNode(node, record, records = []) {
  const card = document.querySelector(`.backup-node[data-node="${node}"]`);
  if (!card) return;
  const status = card.querySelector('[data-field="status"]');
  status.className = `admin-state ${record?.status || "unknown"}`;
  status.textContent = record?.status || "never";
  card.querySelector('[data-field="last"]').textContent = backupTime(record?.finished_at || record?.started_at);
  card.querySelector('[data-field="size"]').textContent = formatBytes(record?.size_bytes);
  card.querySelector('[data-field="verification"]').textContent = record?.verification_status || "—";
  card.querySelector('[data-field="phase"]').textContent = record?.phase || "Idle";
  let freshness = card.querySelector('[data-field="freshness"]');
  if (!freshness) {
    const field = document.createElement("div");
    const title = document.createElement("dt");
    title.textContent = "Last verified success / freshness";
    freshness = document.createElement("dd");
    freshness.dataset.field = "freshness";
    field.append(title, freshness);
    card.querySelector(".backup-details").append(field);
  }
  const state = backupFreshness(records, node);
  freshness.textContent = state.last ? `${backupTime(state.last.finished_at)} · ${state.level} (${state.hours.toFixed(1)} h)` : "unknown — no verified success in last 500 records";
  freshness.style.color = state.level === "OK" ? "#76dfad" : state.level === "warning" ? "#f1d490" : state.level === "critical" ? "#ffabb4" : "";

}

function backupHistoryRow(record) {
  const row = document.createElement("div");
  row.className = "backup-history-row";
  const identity = document.createElement("div");
  const id = document.createElement("strong");
  id.textContent = record.backup_id;
  const meta = document.createElement("span");
  meta.textContent = `${record.source_node.toUpperCase()} → ${record.destination_node.toUpperCase()} · ${backupTime(record.started_at)}`;
  identity.append(id, meta);
  const phase = document.createElement("span");
  phase.textContent = record.phase;
  const size = document.createElement("span");
  size.textContent = formatBytes(record.size_bytes);
  const verification = document.createElement("span");
  verification.textContent = record.verification_status;
  const status = document.createElement("span");
  status.className = `backup-status ${record.status}`;
  status.textContent = record.status;
  const actions = document.createElement("span");
  if (record.status === "success" || record.status === "verification_failed") {
    const verify = document.createElement("button");
    verify.type = "button";
    verify.className = "admin-button compact";
    verify.textContent = "Verify";
    verify.addEventListener("click", () => verifyBackup(record.backup_id, verify));
    actions.append(verify);
  } else {
    actions.textContent = "—";
  }
  row.append(identity, phase, size, verification, status, actions);
  return row;
}

function renderBackupHistory(records) {
  const target = document.getElementById("backup-history");
  const header = document.createElement("div");
  header.className = "backup-history-row header";
  for (const label of ["Restore point", "Phase", "Size", "Verification", "Status", "Action"]) {
    const cell = document.createElement("span");
    cell.textContent = label;
    header.append(cell);
  }
  if (!records.length) {
    const empty = document.createElement("p");
    empty.className = "admin-activity-empty";
    empty.textContent = "No restore points have been created.";
    target.replaceChildren(header, empty);
    return;
  }
  target.replaceChildren(header, ...records.map(backupHistoryRow));
}

function hideUnavailableBackupCenter() {
  const notices = document.querySelector(".backup-notices");
  const heading = notices?.previousElementSibling;
  const history = document.querySelector(".backup-history-panel");
  const activityHeading = history?.nextElementSibling?.querySelector(".eyebrow");
  if (activityHeading) activityHeading.textContent = "05 / ADMIN ACTIVITY";
  heading?.remove();
  notices?.remove();
  document.getElementById("backup-nodes")?.remove();
  history?.remove();
  backupPolling = false;
}

async function loadBackups() {
  try {
    const [historyResponse, summaryResponse] = await Promise.all([
      fetch("/api/admin/backups?limit=500", { cache: "no-store" }),
      fetch("/api/admin/backups/summary", { cache: "no-store" }),
    ]);
    if (historyResponse.status === 404 || summaryResponse.status === 404) {
      hideUnavailableBackupCenter();
      return;
    }
    const [history, summary] = await Promise.all([responseJson(historyResponse), responseJson(summaryResponse)]);
    if (!historyResponse.ok || !history) throw new Error(history?.error || `HTTP ${historyResponse.status}`);
    if (!summaryResponse.ok || !summary) throw new Error(summary?.error || `HTTP ${summaryResponse.status}`);
    renderBackupNode("pi", summary.nodes?.pi, history.backups || []);
    renderBackupNode("pcold", summary.nodes?.pcold, history.backups || []);
    renderBackupNode("cloud", summary.nodes?.cloud, history.backups || []);
    renderBackupHistory((history.backups || []).slice(0, 50));
    const notice = [...document.querySelectorAll(".backup-notices p")].find((p) => p.textContent.includes("Automatic timer / retention"));
    if (notice) notice.textContent = "Automatic timer / retention: Pi 01:10, PcOld 02:10 (Europe/Istanbul); Cloud BLOCKED (maintenance required); retention DRY-RUN ONLY.";

    backupPolling = Boolean(summary.active_job);
    document.querySelectorAll(".backup-start").forEach((button) => { button.disabled = backupPolling; });
  } catch (error) {
    showMessage(error.message || "Could not load backup status.", true);
  }
}

async function startBackup(node, button) {
  const labels = { pi: "Raspberry Pi 5", pcold: "MetehanTechPcOld", cloud: "Personal Cloud" };
  if (!Object.hasOwn(labels, node) || !window.confirm(`Start the fixed-whitelist ${labels[node]} backup?`)) return;
  button.disabled = true;
  try {
    const response = await fetch(`/api/admin/backups/${node}/start`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
    });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    showMessage(data.message || "Backup queued.");
    await Promise.all([loadBackups(), loadActivity()]);
  } catch (error) {
    showMessage(error.message || "Backup could not start.", true);
    button.disabled = false;
  }
}

async function loadCloudSummary() {
  const target = document.getElementById("cloud-summary");
  if (!target) return;
  try {
    const response = await fetch("/api/admin/cloud/summary", { cache: "no-store" });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    const components = Object.entries(data.containers || {});
    const healthy = components.length > 0 && components.every(([, value]) => ["healthy", "running"].includes(value.health));
    const state = document.getElementById("cloud-state");
    state.textContent = healthy ? "running" : "degraded";
    state.className = `admin-state ${healthy ? "running" : "failed"}`;
    document.getElementById("cloud-storage-used").textContent = data.storage ? `${formatBytes(data.storage.used)} (${data.storage.percent}%)` : "—";
    document.getElementById("cloud-storage-free").textContent = data.storage ? formatBytes(data.storage.free) : "—";
    document.getElementById("cloud-last-backup").textContent = backupTime(data.last_backup?.finished_at || data.last_backup?.started_at);
    document.getElementById("cloud-backup-verification").textContent = data.last_backup?.verification_status || "—";
    const rows = components.map(([label, value]) => {
      const row = document.createElement("div");
      row.className = "cloud-component-row";
      const name = document.createElement("span");
      name.textContent = label;
      const health = document.createElement("strong");
      health.textContent = value.health;
      health.className = `admin-state ${["healthy", "running"].includes(value.health) ? "running" : "failed"}`;
      row.append(name, health);
      return row;
    });
    document.getElementById("cloud-components").replaceChildren(...rows);
  } catch (error) {
    showMessage(error.message || "Cloud status is unavailable.", true);
  }
}

function cameraState(id, healthy, goodText, badText) {
  const node = document.getElementById(id);
  node.textContent = healthy ? goodText : badText;
  node.className = `camera-value ${healthy ? "good" : "bad"}`;
}

function cameraTime(value) {
  if (!value) return "Measuring";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function configureCameraLinks() {
  // Adresler kaynak kodda sabit degildir: sunucu bunlari <body> uzerindeki data
  // niteliklerine yazar (bkz. admin.py dashboard()). Kaynak: network.env
  const lanHost = document.body.dataset.lanHost || "";
  const tsHost = document.body.dataset.tailscaleHost || "";
  const allowed = new Set([lanHost, tsHost].filter(Boolean));
  if (!allowed.size) return;
  const host = allowed.has(window.location.hostname) ? window.location.hostname : lanHost;
  document.querySelectorAll("[data-camera-path]").forEach((link) => {
    link.href = `https://${host}:8971${link.dataset.cameraPath}`;
  });
}

async function loadCameraCenter() {
  const target = document.getElementById("camera-center");
  if (!target) return;
  try {
    const response = await fetch("/api/admin/camera", { cache: "no-store" });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    const online = data.camera?.online === true;
    const state = document.getElementById("camera-state");
    state.textContent = online ? "online" : "offline";
    state.className = `admin-state ${online ? "running" : "failed"}`;
    cameraState("camera-frigate", data.frigate?.running === true && data.frigate?.api_healthy === true, "RUNNING", "STOPPED");
    cameraState("camera-go2rtc", data.go2rtc?.healthy === true, "HEALTHY", "ERROR");
    cameraState("camera-recording", data.recording?.active === true, "ACTIVE", "UNAVAILABLE");
    cameraState("camera-nfs", data.nfs?.mounted === true, "MOUNTED", "OFFLINE");
    document.getElementById("camera-storage-used").textContent = data.storage?.used_bytes == null ? "—" : formatBytes(data.storage.used_bytes);
    document.getElementById("camera-storage-free").textContent = data.storage?.free_bytes == null ? "—" : formatBytes(data.storage.free_bytes);
    document.getElementById("camera-daily-growth").textContent = data.storage?.daily_growth_bytes == null ? "Measuring" : `${formatBytes(data.storage.daily_growth_bytes)}/day`;
    document.getElementById("camera-last-motion").textContent = cameraTime(data.last_motion);
    document.getElementById("camera-events-today").textContent = String(Number(data.events_today) || 0);
  } catch (error) {
    const state = document.getElementById("camera-state");
    state.textContent = "unavailable";
    state.className = "admin-state failed";
  }
}

async function verifyBackup(backupId, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/api/admin/backups/${encodeURIComponent(backupId)}/verify`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
    });
    const data = await responseJson(response);
    if (!response.ok || !data) throw new Error(data?.error || `HTTP ${response.status}`);
    showMessage("Backup verification completed successfully.");
    await Promise.all([loadBackups(), loadActivity()]);
  } catch (error) {
    showMessage(error.message || "Backup verification failed.", true);
    await loadBackups();
  } finally {
    button.disabled = false;
  }
}

for (const button of document.querySelectorAll(".log-lines")) {
  button.addEventListener("click", () => {
    selectedLines = Number(button.dataset.lines);
    document.querySelectorAll(".log-lines").forEach((item) => item.classList.toggle("active", item === button));
    loadLogs();
  });
}

for (const button of document.querySelectorAll(".activity-limit")) {
  button.addEventListener("click", () => {
    activityLimit = Number(button.dataset.limit);
    document.querySelectorAll(".activity-limit").forEach((item) => item.classList.toggle("active", item === button));
    loadActivity();
  });
}

for (const button of document.querySelectorAll("#alert-filters button")) {
  button.addEventListener("click", () => {
    alertStatus = button.dataset.status;
    alertSeverity = button.dataset.severity;
    document.querySelectorAll("#alert-filters button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    loadAlerts();
  });
}

for (const button of document.querySelectorAll("#alert-limits button")) {
  button.addEventListener("click", () => {
    alertLimit = Number(button.dataset.limit);
    document.querySelectorAll("#alert-limits button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    loadAlerts();
  });
}

const backupRefresh = document.getElementById("backup-refresh");
if (backupRefresh) {
  for (const button of document.querySelectorAll(".backup-start")) {
    button.addEventListener("click", () => startBackup(button.dataset.node, button));
  }
  backupRefresh.addEventListener("click", loadBackups);
}

configureCameraLinks();
// V2 navigation fetches expensive legacy details only while visible.
window.ccLoadView = function(view) {
  const jobs = {services:loadResources, alerts:loadAlerts, activity:loadActivity,
                cloud:loadCloudSummary, camera:loadCameraCenter, backups:loadBackups};
  if (jobs[view]) return jobs[view]();
};
window.setInterval(() => {
  if (document.hidden) return;
  const current = document.querySelector('.cc-view:not([hidden])');
  if (current) window.ccLoadView(current.id.replace('view-', ''));
}, 30000);
