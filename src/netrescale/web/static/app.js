"use strict";

const state = { session: null, overview: null, view: "overview", days: "7", minimum: "info", device: "", query: "", offset: 0, kind: "running", snapshot: null, comparison: "previous", codeMode: "diff", records: [], request: 0 };
const titles = { overview: "Overview", findings: "Findings", detection: "Detection", devices: "Devices", health: "Health", exposure: "Exposure", events: "Audit log", configurations: "Configuration", delivery: "Delivery", settings: "Settings", users: "Users", credentials: "Credentials", operations: "Operations", account: "My account" };
const healthView = { tab: "platform", device: "", outcome: "failures" };
const categories = { config_change: "Configuration", log_rule: "Log detection", session_reuse: "Session reuse", exposure: "Exposure", health: "Health", digest: "Digest" };
const levels = ["critical", "high", "medium", "low", "info"];
const $ = (selector) => document.querySelector(selector);
const formatNumber = (number) => number == null ? "--" : new Intl.NumberFormat("en-US").format(number);
const icons = () => globalThis.lucide?.createIcons({ attrs: { "stroke-width": 1.7 } });

function element(tag, attributes = {}, children = []) {
  const result = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key === "class") result.className = value;
    else if (key === "text") result.textContent = value;
    else if (key.startsWith("on")) result.addEventListener(key.slice(2), value);
    else if (key === "disabled") result.disabled = value;
    else result.setAttribute(key, value);
  }
  for (const child of children.flat()) if (child != null) result.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return result;
}

function icon(name) { return element("i", { "data-lucide": name, "aria-hidden": "true" }); }
function iconButton(name, label, action, disabled = false) { return element("button", { type: "button", class: "icon-button", title: label, "aria-label": label, onclick: action, disabled }, [icon(name)]); }
function badge(value, tone = value) { return element("span", { class: `badge ${levels.includes(tone) || ["online", "unmonitored", "pending", "delivered"].includes(tone) ? tone : ""}` }, [element("span", { class: "dot" }), value || "unknown"]); }
function textButton(label, action) { return element("button", { class: "text-button", onclick: action }, [label, icon("arrow-up-right")]); }
function navigate(view) { location.hash = view; }
function stamp(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat("en-GB", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }).format(date);
}
function relative(value) {
  if (!value) return "Not received";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
function forensicStamp(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC", timeZoneName: "short" }).format(date);
}
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { $("#toast").hidden = true; }, 4500);
}

async function api(path, options = {}) {
  const response = await fetch(`/api/${path}`, { credentials: "same-origin", ...options, headers: { "Content-Type": "application/json", ...(state.session ? { "x-csrf-token": state.session.csrf } : {}), ...options.headers } });
  const body = await response.json().catch(() => ({ detail: "Unexpected server response" }));
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("login")) showLogin();
    const error = new Error(typeof body.detail === "string" ? body.detail : "Request could not be completed");
    error.status = response.status;
    throw error;
  }
  return body;
}

function heading(title, subtitle, actions = []) {
  return element("div", { class: "page-heading" }, [element("div", {}, [element("h1", { text: title }), subtitle ? element("p", { text: subtitle }) : null]), element("div", { class: "heading-actions" }, actions)]);
}
function empty(title, message, symbol = "inbox") { return element("div", { class: "empty-state" }, [icon(symbol), element("h2", { text: title }), element("p", { text: message })]); }
function notice(message, error = false) { return element("div", { class: `notice ${error ? "error" : "warning"}`, role: "status" }, [icon("circle-alert"), element("span", { text: message })]); }
function section(title, children, action = null) { return element("section", { class: "section" }, [element("div", { class: "section-heading" }, [element("h2", { text: title }), action]), ...children]); }
function definitions(rows) { return element("dl", { class: "definition-list" }, rows.map(([label, value]) => element("div", {}, [element("dt", { text: label }), element("dd", {}, [value instanceof Node ? value : value == null ? "Not available" : String(value)])]))); }
const exposureStates = { vulnerable: ["Vulnerable", "critical"], possibly_exposed: ["Possibly exposed", "high"], unknown: ["Exposure unknown", "high"], vulnerable_not_exposed: ["Vulnerable, not exposed", "medium"], fixed: ["Fixed", "low"], not_affected: ["Not affected", "low"] };
const lifecycles = { supported: "Supported", end_of_maintenance: "End of maintenance", end_of_life: "End of life", unknown: "Unknown" };
const channels = { smtp: "Email / SMTP", siem: "SIEM", webhook: "Webhook" };
function exposureBadge(posture) { if (!posture) return badge("Not assessed", "info"); const [label, tone] = exposureStates[posture.worst] || ["Exposure unknown", "high"]; return badge(label, tone); }
function safeBuild(posture) { return posture?.min_safe_build ? [posture.train, posture.min_safe_build].filter(Boolean).join(" ") : "Not in advisory data"; }
function sinkState(sink) { if (sink.health?.failing) return ["Failing", "critical"]; if (sink.pending && sink.max_attempts) return ["Retrying", "medium"]; if (sink.pending) return ["Pending", "pending"]; return sink.last_delivered ? ["Delivered", "delivered"] : ["Untested", "info"]; }
function sinkFailure(sink) { return `${channels[sink.name] || sink.name}: failing since ${forensicStamp(sink.health.failing_since)}${sink.health.alerted ? "; alert sent through the other channels" : ""}`; }
function table(headers, rows, className = "") { return element("div", { class: "table-wrap" }, [element("table", { class: className }, [element("thead", {}, [element("tr", {}, headers.map((name) => element("th", { scope: "col", text: name })))]), element("tbody", {}, rows)])]); }

function updateChrome() {
  const overview = state.overview;
  if (!overview) return;
  const status = overview.status.state;
  const healthy = status === "healthy" && overview.database.available;
  const names = { healthy: "Monitor online", idle: "No devices configured", paused: "Monitoring paused", degraded: "Attention needed", stale: "Status stale", "not-running": "Monitor stopped", unavailable: "Status unavailable" };
  $("#service-state").className = `status-label ${healthy ? "" : "warn"}`;
  $("#service-state").replaceChildren(element("span", { class: "dot" }), document.createTextNode(overview.database.available ? names[status] || status : "Database unavailable"));
  $("#fleet-count").textContent = `${overview.devices.length} configured device${overview.devices.length === 1 ? "" : "s"}`;
  const alerts = overview.severity.critical + overview.severity.high;
  $("#nav-count").textContent = formatNumber(alerts);
  $("#nav-count").hidden = !alerts;
  $("#last-updated").textContent = `Updated ${new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" }).format(new Date())}`;
}

function metric(label, value, note, symbol, tone = "", suffix = null) {
  return element("article", { class: "metric" }, [element("div", { class: "metric-top" }, [label, icon(symbol)]), element("div", { class: "metric-value" }, [formatNumber(value), suffix ? element("small", { text: suffix }) : null]), element("p", { class: `metric-note ${tone}` }, [element("span", { class: "dot" }), note])]);
}

function forensicValue(record, ...names) {
  for (const source of [record, record.evidence]) {
    if (!source || typeof source !== "object") continue;
    for (const name of names) {
      const value = source[name];
      if (value !== undefined && value !== null && value !== "") return value;
    }
  }
  return null;
}

function valueList(value) {
  if (value == null || value === "") return [];
  if (Array.isArray(value)) return value.filter((item) => item != null && item !== "").map(String);
  return [String(value)];
}

function chips(values, tone = "") {
  return element("div", { class: "forensic-chips" }, valueList(values).map((value) => element("span", { class: `forensic-chip ${tone}`, text: value })));
}

function findingRow(record) {
  const context = [categories[record.category], record.rule_id].filter(Boolean).join(" · ");
  return element("tr", {}, [element("td", {}, [badge(record.severity)]), element("td", {}, [element("button", { class: "record-title", onclick: () => showRecord(record) }, [record.title || record.summary || "Untitled finding"]), element("span", { class: "record-summary", text: record.summary && record.summary !== record.title ? record.summary : context }), context ? element("span", { class: "record-subtitle", text: context }) : null]), element("td", { class: "nowrap", text: record.device || "Workspace" }), element("td", { class: "nowrap muted", text: stamp(record.observed_at), title: forensicStamp(record.observed_at) }), element("td", {}, [iconButton("chevron-right", "Open finding", () => showRecord(record))])]);
}

async function renderOverview() {
  const data = state.overview;
  const online = data.devices.filter((device) => device.state === "online").length;
  const critical = data.database.available ? data.severity.critical : null;
  const high = data.database.available ? data.severity.high : null;
  const total = Object.values(data.severity).reduce((sum, value) => sum + value, 0);
  const container = element("div", {}, [heading("Overview", "Security posture across your NetScaler estate", [element("span", { class: "date-label" }, [icon("calendar-days"), "Last 24 hours"])]), element("div", { class: "metrics" }, [metric("Monitored devices", online, `${data.devices.length - online} not currently monitored`, "server", online === data.devices.length && online ? "good" : "attention", `/ ${data.devices.length}`), metric("Critical findings", critical, "Last 24 hours", "shield-alert", critical ? "alert" : ""), metric("High findings", high, "Last 24 hours", "triangle-alert", high ? "attention" : ""), metric("Queued deliveries", data.database.pending_notifications, data.database.pending_notifications ? "Awaiting delivery" : "No pending deliveries", "send", data.database.pending_notifications ? "attention" : "good")])]);
  if (!data.database.available) container.append(notice(data.database.error, true));
  else if (["not-running", "stale", "unavailable"].includes(data.status.state)) container.append(notice("Monitoring status is not current. Stored findings may not reflect the present appliance state."));
  if (data.status.warnings?.length) container.append(notice(data.status.warnings.join(". ")));
  const fleet = element("div", { class: "fleet-list" }, data.devices.slice(0, 5).map((device) => element("div", { class: "fleet-item" }, [element("span", { class: "fleet-icon" }, [icon("server")]), element("div", { class: "fleet-name" }, [element("strong", { text: device.name }), element("small", { text: `${device.address}${device.pair ? ` / ${device.pair}` : ""}` })]), badge(device.state)])));
  const distribution = levels.map((level) => element("div", { class: "severity-row" }, [element("span", { text: level[0].toUpperCase() + level.slice(1) }), element("progress", { class: level, value: data.severity[level], max: Math.max(1, ...Object.values(data.severity)), "aria-label": `${level}: ${data.severity[level]}` }), element("strong", { text: formatNumber(data.severity[level]) })]));
  const lower = element("div", { class: "overview-lower" }, [section("Fleet health", data.devices.length ? [fleet] : [empty("No devices configured", "Inventory is empty.", "server")], textButton("All devices", () => navigate("devices"))), section("Finding severity", [...distribution, element("div", { class: "severity-summary" }, [element("strong", { text: data.database.available ? formatNumber(total) : "--" }), "findings in the last 24 hours"])])]);
  container.append(lower);
  if (data.database.available) {
    const records = await api("records/findings?days=1&limit=6");
    container.append(section("Latest findings", [records.items.length ? table(["Severity", "Finding", "Device", "Observed (UTC)", ""], records.items.map(findingRow), "records-table") : empty("No findings in the last 24 hours", "No matching records have been stored.", "shield-check")], textButton("All findings", () => navigate("findings"))));
  }
  return container;
}

function selectControl(label, options, value, onChange) {
  const select = element("select", { "aria-label": label, title: label, onchange: (event) => onChange(event.target.value) }, options.map(([key, text]) => element("option", { value: key, text })));
  select.value = value;
  return select;
}

function filters() {
  let searchTimer;
  const search = element("input", { type: "search", placeholder: "Search records...", "aria-label": "Search records", value: state.query, maxlength: "200", oninput: (event) => { clearTimeout(searchTimer); const value = event.target.value; searchTimer = setTimeout(() => { state.query = value; state.offset = 0; loadView(); }, 450); } });
  const toolbar = element("div", { class: "toolbar" }, [element("div", { class: "search-field" }, [icon("search"), search]), selectControl("Device", [["", "All devices"], ...state.overview.devices.map((device) => [device.name, device.name])], state.device, (value) => { state.device = value; state.offset = 0; loadView(); })]);
  if (state.view !== "events") toolbar.append(selectControl("Minimum severity", [["info", "All severities"], ["low", "Low and above"], ["medium", "Medium and above"], ["high", "High and above"], ["critical", "Critical only"]], state.minimum, (value) => { state.minimum = value; state.offset = 0; loadView(); }));
  toolbar.append(selectControl("Time range", [["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["400", "Last 400 days"]], state.days, (value) => { state.days = value; state.offset = 0; loadView(); }), iconButton("filter-x", "Reset filters", () => { state.query = ""; state.device = ""; state.minimum = "info"; state.days = "7"; state.offset = 0; loadView(); }));
  return toolbar;
}

async function renderRecords() {
  const audit = state.view === "events";
  const params = new URLSearchParams({ days: state.days, minimum: state.minimum, device: state.device, query: state.query, offset: state.offset, limit: 25, category: state.view === "exposure" ? "exposure" : "" });
  const records = await api(`records/${audit ? "events" : "findings"}?${params}`);
  state.records = records.items;
  const subtitles = { findings: "Detection results and monitoring health", events: "Indexed appliance audit and security events", exposure: "Stored firmware vulnerability assessments" };
  const root = element("div", {}, [heading(titles[state.view], subtitles[state.view], [iconButton("download", "Export visible records", () => download("netrescale-records.json", JSON.stringify(state.records, null, 2)), !records.items.length)]), filters()]);
  if (records.items.length) {
    const rows = audit ? records.items.map((record) => element("tr", {}, [element("td", { class: "nowrap muted", text: stamp(record.ts) }), element("td", {}, [element("button", { class: "record-title", onclick: () => showRecord(record, true), text: [record.feature, record.event].filter(Boolean).join(" ") || record.source }), element("span", { class: "record-subtitle", text: (record.message || "").slice(0, 95) })]), element("td", { class: "nowrap", text: record.device }), element("td", { text: record.fields?.User || "--" }), element("td", {}, [iconButton("chevron-right", "Open event", () => showRecord(record, true))])])) : records.items.map(findingRow);
    root.append(table(audit ? ["Observed (UTC)", "Event", "Device", "User", ""] : ["Severity", "Finding", "Device", "Observed (UTC)", ""], rows, "records-table"));
  } else root.append(empty("No matching records", "No records match the selected filters.", state.view === "exposure" ? "fingerprint" : "search"));
  const first = records.total ? state.offset + 1 : 0;
  root.append(element("div", { class: "pagination" }, [element("span", { text: `${formatNumber(first)}-${formatNumber(state.offset + records.items.length)} of ${formatNumber(records.total)} records` }), element("div", { class: "pagination-controls" }, [iconButton("chevron-left", "Previous page", () => { state.offset = Math.max(0, state.offset - 25); loadView(); }, state.offset === 0), element("span", { text: `Page ${Math.floor(state.offset / 25) + 1}` }), iconButton("chevron-right", "Next page", () => { state.offset += 25; loadView(); }, state.offset + 25 >= records.total)])]));
  return root;
}

function forensicSection(title, symbol, content, options = {}) {
  return element("section", { class: `forensic-section${options.wide ? " wide" : ""}${options.attention ? " attention" : ""}` }, [
    element("div", { class: "forensic-section-title" }, [icon(symbol), element("h3", { text: title })]),
    content instanceof Node ? content : element("p", { class: "forensic-copy", text: content }),
  ]);
}

function readableEvidence(record) {
  const evidence = record.evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return evidence ? element("pre", { text: String(evidence) }) : element("p", { class: "forensic-missing", text: "No supporting evidence was stored with this finding." });
  }
  const presentationKeys = new Set(["affected_users", "new_users", "users", "why_it_matters", "why", "impact", "remediation", "recommendation", "recommended_action", "attribution", "first_seen", "last_seen", "changed_at"]);
  const facts = Object.entries(evidence).filter(([key, value]) => key !== "diff" && !presentationKeys.has(key) && value != null && value !== "");
  const content = element("div", { class: "evidence-stack" });
  if (facts.length) {
    content.append(element("dl", { class: "evidence-facts" }, facts.map(([key, value]) => element("div", {}, [
      element("dt", { text: key.replaceAll("_", " ") }),
      element("dd", { class: typeof value === "object" ? "mono" : "", text: typeof value === "object" ? JSON.stringify(value, null, 2) : String(value) }),
    ]))));
  }
  if (evidence.diff) content.append(element("pre", { class: "forensic-diff", text: String(evidence.diff), tabindex: "0", "aria-label": "Redacted configuration evidence" }));
  if (!content.childNodes.length) content.append(element("p", { class: "forensic-missing", text: "No supporting evidence was stored with this finding." }));
  return content;
}

function showRecord(record, audit = false) {
  $("#detail-eyebrow").textContent = audit ? "AUDIT EVENT" : categories[record.category] || "FINDING";
  $("#detail-title").textContent = record.title || record.event || "Event details";
  const body = $("#detail-body");
  $("#detail-dialog").classList.toggle("forensic-dialog", !audit);
  if (audit) {
    body.replaceChildren(definitions([["Device", record.device || "Workspace"], ["Observed (UTC)", forensicStamp(record.ts)], ["Record ID", record.id]]));
    body.append(element("p", { text: record.message || "" }), element("h3", { text: "Evidence" }), element("pre", { text: JSON.stringify({ fields: record.fields, raw: record.raw }, null, 2) }));
    $("#detail-dialog").showModal();
    icons();
    return;
  }

  const affectedUsers = forensicValue(record, "new_users", "affected_users", "users", "user");
  const why = forensicValue(record, "why_it_matters", "why", "impact", "reasons");
  const remediation = forensicValue(record, "remediation", "recommendation", "recommended_action");
  const attribution = forensicValue(record, "attribution", "actor", "changed_by");
  const unattributed = Boolean(forensicValue(record, "unattributed"));
  const cves = forensicValue(record, "cve", "cves");
  const firstSeen = forensicValue(record, "first_seen");
  const lastSeen = forensicValue(record, "last_seen", "changed_at");
  const issue = forensicValue(record, "issue", "plain_language_issue", "summary") || record.title || "No plain-language description was stored.";

  const severity = element("div", { class: `finding-severity ${levels.includes(record.severity) ? record.severity : "info"}` }, [
    element("span", { class: "severity-label" }, [badge(record.severity)]),
    element("div", {}, [element("span", { class: "eyebrow", text: "WHAT HAPPENED" }), element("p", { text: String(issue) })]),
  ]);
  const metadata = element("dl", { class: "forensic-metadata" }, [
    ["Device", record.device || "Workspace"],
    ["Detected", forensicStamp(record.observed_at)],
    ...(firstSeen ? [["First seen", forensicStamp(firstSeen)]] : []),
    ...(lastSeen ? [["Last seen", forensicStamp(lastSeen)]] : []),
    ["Detection", record.rule_id || "Legacy finding"],
    ["Record ID", record.id || "Not recorded"],
  ].map(([label, value]) => element("div", {}, [element("dt", { text: label }), element("dd", { text: value })])));
  const grid = element("div", { class: "forensic-grid" });
  if (valueList(affectedUsers).length) grid.append(forensicSection("Affected or new users", "users-round", chips(affectedUsers, "user")));
  if (valueList(cves).length) grid.append(forensicSection("Related CVEs", "bug", chips(cves, "cve")));
  grid.append(
    forensicSection("Why it matters", "shield-alert", why ? (Array.isArray(why) ? chips(why) : String(why)) : "Context was not recorded in this older finding.", { attention: Boolean(why) }),
    forensicSection("Remediation", "list-checks", remediation ? (Array.isArray(remediation) ? element("ul", { class: "forensic-list" }, remediation.map((item) => element("li", { text: String(item) }))) : String(remediation)) : "No finding-specific remediation was recorded. Validate the evidence against the approved change record and follow the relevant NetScaler security guidance."),
  );
  const attributionText = valueList(attribution).length
    ? chips(attribution, "actor")
    : unattributed
      ? element("p", { class: "attribution-warning", text: "No matching audit-log entry was found for this change." })
      : element("p", { class: "forensic-missing", text: "Attribution was not available or was not recorded." });
  grid.append(forensicSection("Attribution", "user-search", attributionText, { attention: unattributed }), forensicSection("Evidence", "scan-search", readableEvidence(record), { wide: true }));
  body.replaceChildren(severity, metadata, grid);
  $("#detail-dialog").showModal();
  icons();
}

function renderDevices() {
  const devices = state.overview.devices;
  const actions = [];
  actions.push(element("button", { class: "secondary-button", onclick: () => openHealth() }, [icon("heart-pulse"), "Health"]));
  if (AdminUI.isAdmin()) actions.push(element("button", { class: "primary-button", onclick: () => AdminUI.openSettings("devices") }, [icon("pencil"), "Manage inventory"]));
  const root = element("div", {}, [heading("Devices", `${devices.length} devices in the configured inventory`, actions)]);
  if (!devices.length) return element("div", {}, [root, empty("No devices configured", "Inventory is empty.", "server")]);
  const rows = devices.map((device) => element("tr", {}, [element("td", { class: "device-name-cell" }, [element("button", { class: "record-title", text: device.name, onclick: () => AdminUI.openSettings("devices", device.name) }), element("span", { class: "record-subtitle mono", text: device.address }), AdminUI.canOperate() ? AdminUI.deviceActions(device.name) : null]), element("td", {}, [element("button", { class: "health-state-button", title: `Health details for ${device.name}`, onclick: () => openHealth(device.name) }, [badge(device.state)])]), element("td", { text: device.pair || "Standalone" }), element("td", {}, [badge(device.mode)]), element("td", {}, [exposureBadge(device.posture), device.posture ? element("span", { class: "record-subtitle", text: `Minimum safe build ${safeBuild(device.posture)}` }) : null]), element("td", { class: "nowrap muted", text: relative(device.nitro.last_ok), title: stamp(device.nitro.last_ok) }), element("td", { class: "nowrap muted", text: relative(device.syslog.last_received), title: stamp(device.syslog.last_received) }), element("td", {}, [iconButton("file-diff", `Configuration for ${device.name}`, () => { state.device = device.name; state.snapshot = null; navigate("configurations"); })])]));
  root.append(table(["Device", "State", "HA pair", "Mode", "Exposure", "Last poll", "Last syslog", ""], rows, "records-table"));
  devices.filter((device) => device.nitro.last_error || device.syslog.last_error).forEach((device) => root.append(element("div", { class: "section" }, [notice(`${device.name}: ${device.nitro.last_error || device.syslog.last_error}`, true)])));
  return root;
}

function openHealth(device = "") { healthView.device = device; healthView.tab = device ? "devices" : "platform"; if (state.view === "health") loadView(); else navigate("health"); }
function byteSize(value) { if (value == null) return "Unavailable"; const units = ["B", "KiB", "MiB", "GiB", "TiB"]; let index = 0; while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; } return `${value.toFixed(index ? 1 : 0)} ${units[index]}`; }
function duration(value) { if (value == null) return "Unavailable"; const seconds = Math.max(0, Math.floor(value)); return seconds >= 86400 ? `${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h` : seconds >= 3600 ? `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`; }

function healthFailure(record) {
  $("#detail-dialog").classList.remove("forensic-dialog");
  $("#detail-eyebrow").textContent = "ACTION DIAGNOSTIC";
  $("#detail-title").textContent = `${record.action} / ${record.target || "Platform"}`;
  $("#detail-body").replaceChildren(definitions([["Recorded (UTC)", forensicStamp(record.at)], ["Outcome", record.outcome], ["Response code", record.status], ["Error type", record.error_type], ["Duration", record.duration_ms == null ? "Not recorded" : `${record.duration_ms} ms`], ["Request ID", record.request_id], ...(record.actor ? [["Operator", record.actor]] : [])]), element("h3", { text: "Reason" }), element("pre", { text: record.error || "No diagnostic message was recorded for this action." }));
  $("#detail-dialog").showModal(); icons();
}

function postureDetails(posture) {
  if (!posture) return [element("p", { class: "table-note", text: "No exposure assessment has been recorded yet." })];
  const advisories = (values) => values?.length ? chips(values) : "None";
  return [element("div", { class: "section-heading" }, [element("h3", { text: "Exposure posture" }), exposureBadge(posture)]), definitions([["Firmware", posture.version], ["Minimum safe build", safeBuild(posture)], ["Release lifecycle", lifecycles[posture.lifecycle] || posture.lifecycle], ["Assessed (UTC)", forensicStamp(posture.assessed_at)], ["Vulnerable advisories", advisories(posture.actionable)], ["Needs attention", advisories(posture.needs_attention)]]), ...(posture.warnings || []).map((warning) => notice(warning))];
}

function sourceCoverage(feed) {
  const entries = feed.source_coverage || [];
  if (!entries.length) return [element("p", { class: "table-note", text: "No per-source coverage reported by this daemon." })];
  const rows = entries.map((entry) => { const missing = entry.expected && !entry.lines; return element("tr", {}, [element("td", { text: entry.source }), element("td", {}, [badge(entry.lines ? "Received" : missing ? "Never received" : "Not received", entry.lines ? "low" : missing ? "medium" : "info")]), element("td", { text: formatNumber(entry.lines) }), element("td", { class: "nowrap", text: forensicStamp(entry.last_received) })]); });
  const unclassified = feed.sources?.unknown?.lines;
  return [...(feed.missing_sources?.length ? [notice(`Expected log sources never received: ${feed.missing_sources.join(", ")}`)] : []), table(["Log source", "Coverage", "Lines", "Last received (UTC)"], rows), element("p", { class: "table-note", text: `Counted since the monitor started${unclassified ? `; ${formatNumber(unclassified)} unclassified line(s)` : ""}.` })];
}

function deviceHealth(device, stale) {
  const checks = [["Configuration polling", device.nitro], ["Exposure checks", device.exposure]];
  const root = element("section", { class: "health-device" }, [element("div", { class: "section-heading" }, [element("div", {}, [element("h2", { text: device.name }), element("p", { class: "table-note", text: `${device.address}:${device.nitro_port} / ${device.tls_verification} / ${device.pair || "Standalone"}` })]), element("div", { class: "row-actions" }, [badge(stale ? "Status unavailable" : device.state, stale ? "medium" : device.state), ...(AdminUI.isAdmin() ? [iconButton("settings-2", `Settings for ${device.name}`, () => AdminUI.openSettings("devices", device.name))] : [])])])]);
  if (AdminUI.canOperate()) root.append(AdminUI.deviceActions(device.name));
  const panels = checks.map(([label, check]) => element("section", { class: "health-check" }, [element("div", { class: "section-heading" }, [element("h3", { text: label }), badge(stale ? "Unknown" : check.last_error ? "Failed" : check.last_ok ? "OK" : "Not recorded", stale || check.last_error ? "medium" : check.last_ok ? "low" : "info")]), ...(check.last_error ? [notice(check.last_error, true)] : []), definitions([["Last attempt (UTC)", forensicStamp(check.last_attempt)], ["Last success (UTC)", forensicStamp(check.last_ok)], ["Last failure (UTC)", forensicStamp(check.last_failure)], ["Error type", check.error_type || "None recorded"], ["Attempts / successes", `${formatNumber(check.attempts)} / ${formatNumber(check.successes)}`], ["Failures / consecutive", `${formatNumber(check.total_failures)} / ${formatNumber(check.failures)}`]]), ...(check === device.exposure ? postureDetails(check.posture) : [])]));
  const feed = device.syslog;
  panels.push(element("section", { class: "health-check" }, [element("div", { class: "section-heading" }, [element("h3", { text: "Syslog ingestion" }), badge(!device.syslog_enabled ? "Disabled" : stale ? "Unknown" : feed.last_error ? "Failed" : feed.silent ? "Silent" : feed.last_received ? "Receiving" : "Not received", feed.last_error || feed.silent || stale ? "medium" : feed.last_received ? "low" : "info")]), ...(feed.last_error ? [notice(feed.last_error, true)] : []), ...(feed.silent ? [notice("NITRO is reachable but no recent syslog has been received.")] : []), definitions([["Last received (UTC)", forensicStamp(feed.last_received)], ["Lines received", formatNumber(feed.lines)], ["Lines parsed", formatNumber(feed.parsed)], ["Raw bytes", byteSize(feed.raw_bytes)]])]));
  root.append(element("div", { class: "health-checks" }, panels));
  if (device.syslog_enabled) root.append(element("section", { class: "health-check" }, [element("div", { class: "section-heading" }, [element("h3", { text: "Log source coverage" })]), ...sourceCoverage(feed)]));
  return root;
}

async function renderHealth() {
  const data = await api("health");
  const status = data.status;
  const stale = ["stale", "not-running", "unavailable"].includes(status.state);
  const root = element("div", {}, [heading("Health", "Device diagnostics and platform telemetry", [iconButton("download", "Export health diagnostics", () => download("netrescale-health.json", JSON.stringify(data, null, 2)))]), element("div", { class: "toolbar" }, [segmented([["platform", "Platform"], ["devices", "Devices"]], healthView.tab, (value) => { healthView.tab = value; loadView(); }), badge(status.state, stale || status.state === "degraded" ? "medium" : "info"), element("span", { class: "muted health-sample", text: `Daemon sample: ${forensicStamp(status.updated_at)}` })])]);
  if (stale) root.append(notice("Daemon telemetry is missing or stale. Any retained metrics below are not current.", true));
  if (!data.database.available) root.append(notice(data.database.error, true));
  for (const warning of status.warnings || []) root.append(notice(warning));
  if (healthView.tab === "platform") {
    const resources = data.resources;
    if (!resources) root.append(empty("Resource telemetry unavailable", "No resource sample was reported by this daemon.", "activity"));
    else {
      const process = resources.process || {}, memory = resources.memory || {};
      root.append(element("div", { class: "health-platform-grid" }, [section("Host", [definitions([["Hostname", resources.hostname], ["CPU cores", resources.cpu_count], ["Load average (1 / 5 / 15 min)", resources.load_average?.map((value) => value.toFixed(2)).join(" / ") || "Unavailable"], ["Physical memory", byteSize(memory.total_bytes)], ["Free memory (excludes cache)", byteSize(memory.free_bytes)], ["Host uptime", duration(resources.host_uptime_seconds)]])]), section("Monitoring process", [definitions([["PID", process.pid], ["Process uptime", duration(process.uptime_seconds)], ["CPU (100% = one core)", process.cpu_percent == null ? "Awaiting sample" : `${process.cpu_percent}%`], ["CPU time", duration(process.cpu_seconds)], ["Resident / peak memory", `${byteSize(process.rss_bytes)} / ${byteSize(process.peak_rss_bytes)}`], ["Threads / open descriptors", `${formatNumber(process.threads)} / ${formatNumber(process.open_fds)}`]])])]));
      const disks = Object.entries(resources.filesystems || {}).map(([name, disk]) => element("tr", {}, [element("td", { text: name }), element("td", { class: "mono", text: disk.path }), element("td", { text: byteSize(disk.total_bytes) }), element("td", { text: byteSize(disk.used_bytes) }), element("td", { text: byteSize(disk.free_bytes) }), element("td", { text: `${disk.used_percent ?? "--"}%` })]));
      root.append(section("Filesystems", [table(["Purpose", "Path", "Total", "Used", "Free", "Used %"], disks)]));
      if (Object.keys(resources.errors || {}).length) root.append(section("Unavailable measurements", [definitions(Object.entries(resources.errors))]));
    }
    if (data.database.available) {
      const db = data.database;
      const records = [["Indexed events", formatNumber(db.events)], ["Findings", formatNumber(db.findings)], ["Hunt runs", formatNumber(db.hunt_runs)], ["Database size", byteSize(db.database_bytes)], ["Last event received (UTC)", forensicStamp(db.last_event_received)], ["Last finding stored (UTC)", forensicStamp(db.last_finding_stored)], ["Last hunt started (UTC)", forensicStamp(db.last_hunt_started)]];
      const queue = [["Pending", formatNumber(db.pending_notifications)], ["Retrying", formatNumber(db.retrying_notifications)], ["Delivered", formatNumber(db.delivered_notifications)]];
      const sinks = data.delivery.sinks.map((sink) => element("div", { class: "delivery-health" }, [element("h3", { text: channels[sink.name] || sink.name }), definitions([["State", badge(...sinkState(sink))], ["Queued", formatNumber(sink.pending)], ["Oldest queued (UTC)", forensicStamp(sink.oldest_undelivered)], ["Most attempts", formatNumber(sink.max_attempts)], ["Failing since (UTC)", !sink.health ? "Daemon status unavailable" : sink.health.failing ? forensicStamp(sink.health.failing_since) : "Not failing"], ["Last delivered (UTC)", forensicStamp(sink.last_delivered)]]), ...(sink.health?.failing ? [notice(sinkFailure(sink), true)] : []), ...(sink.error ? [notice(sink.error, true)] : [])]));
      root.append(element("div", { class: "health-platform-grid" }, [section("Stored records", [definitions(records)]), section("Notification delivery", [definitions(queue), ...sinks])]));
    }
    const disabled = Object.entries(status.disabled_rules || {});
    if (disabled.length) root.append(section("Inactive monitoring rules", [definitions(disabled)]));
  } else {
    if (healthView.device && !data.devices.some((device) => device.name === healthView.device)) healthView.device = "";
    root.append(element("div", { class: "toolbar" }, [selectControl("Health device", [["", "All devices"], ...data.devices.map((device) => [device.name, device.name])], healthView.device, (value) => { healthView.device = value; loadView(); })]));
    const devices = data.devices.filter((device) => !healthView.device || device.name === healthView.device);
    root.append(...(devices.length ? devices.map((device) => deviceHealth(device, stale)) : [empty("No devices configured", "Inventory is empty.", "server")]));
  }
  if (data.actions.available) {
    const actions = data.actions.items.filter((record) => (healthView.tab !== "devices" || !healthView.device || record.target === healthView.device) && (healthView.outcome !== "failures" || !["requested", "completed"].includes(record.outcome)));
    const rows = actions.map((record) => element("tr", {}, [element("td", { class: "nowrap", text: stamp(record.at) }), element("td", {}, [element("button", { class: "record-title", text: record.action, onclick: () => healthFailure(record) }), element("span", { class: "record-subtitle", text: record.target || "Platform" })]), element("td", {}, [badge(record.outcome, record.outcome === "completed" ? "low" : "medium")]), element("td", { class: "health-error", text: record.error || (record.outcome === "requested" ? "No completion recorded yet" : "No error detail recorded") }), element("td", { class: "nowrap", text: record.duration_ms == null ? "--" : `${record.duration_ms} ms` }), element("td", {}, [iconButton("search", "Open action diagnostic", () => healthFailure(record))])]));
    root.append(section("Recent action diagnostics", [element("div", { class: "toolbar" }, [segmented([["failures", "Failures"], ["all", "All outcomes"]], healthView.outcome, (value) => { healthView.outcome = value; loadView(); })]), rows.length ? table(["Recorded (UTC)", "Action / target", "Outcome", "Reason", "Duration", ""], rows, "health-actions-table") : empty("No matching action diagnostics", "No matching records in the latest action history.", "check-check")]));
  } else if (data.actions.error) root.append(notice(data.actions.error, true));
  const findings = data.findings.items.filter((record) => healthView.tab !== "devices" || !healthView.device || record.device === healthView.device);
  root.append(section("Health findings / last 30 days", [findings.length ? table(["Severity", "Finding", "Device", "Observed (UTC)", ""], findings.map(findingRow), "records-table") : empty("No matching health findings", "No health findings in the selected period.", "heart-pulse")]));
  return root;
}

async function renderConfigurations() {
  const devices = state.overview.devices;
  const root = element("div", {}, [heading("Configuration", "Recorded snapshots and redacted change history")]);
  if (!devices.length) return element("div", {}, [root, empty("No devices configured", "Configuration history is not available.", "file-clock")]);
  if (!state.device || !devices.some((device) => device.name === state.device)) state.device = devices[0].name;
  root.append(element("div", { class: "toolbar" }, [selectControl("Configuration device", devices.map((device) => [device.name, device.name]), state.device, (value) => { state.device = value; state.snapshot = null; state.comparison = "previous"; loadView(); }), segmented([["running", "Running"], ["saved", "Saved"]], state.kind, (value) => { state.kind = value; state.snapshot = null; state.comparison = "previous"; loadView(); })]));
  const history = await api(`configurations/${encodeURIComponent(state.device)}?kind=${state.kind}`);
  if (!history.items.length) return element("div", {}, [root, empty("No snapshots recorded", "A successful configuration poll has not been recorded for this device.", "file-clock")]);
  if (state.snapshot == null || !history.items.some((item) => item.index === state.snapshot)) state.snapshot = history.items[0].index;
  if (state.comparison !== "previous" && !history.items.some((item) => String(item.index) === state.comparison && item.index !== state.snapshot)) state.comparison = "previous";
  const comparisonQuery = state.comparison === "previous" ? "" : `&compare_index=${state.comparison}`;
  const snapshot = await api(`configurations/${encodeURIComponent(state.device)}?kind=${state.kind}&index=${state.snapshot}${comparisonQuery}`);
  const list = element("div", { class: "snapshot-list", "aria-label": "Snapshot history" }, history.items.map((item) => element("button", { class: `snapshot ${item.index === state.snapshot ? "selected" : ""}`, "aria-pressed": String(item.index === state.snapshot), onclick: () => { state.snapshot = item.index; loadView(); } }, [icon("file-clock"), element("span", {}, [element("strong", { text: stamp(item.at) }), element("small", { class: "mono", text: item.sha256.slice(0, 12) }), element("small", { text: item.index === 0 ? "Baseline" : `Snapshot ${item.index}` })])])));
  const text = snapshot[state.codeMode] || (state.codeMode === "diff" ? "No differences between these snapshots." : "Empty snapshot.");
  const code = element("pre", { class: "config-code", tabindex: "0", "aria-label": "Redacted configuration" });
  text.split("\n").forEach((line) => {
    const style = state.codeMode !== "diff" ? "" : /^(---|\+\+\+|@@)/.test(line) ? "diff-header" : line.startsWith("+") ? "diff-add" : line.startsWith("-") ? "diff-remove" : "";
    code.append(element("span", { class: `code-line ${style}`, text: line || " " }));
  });
  const panel = element("section", { class: "code-panel" }, [element("div", { class: "code-toolbar" }, [segmented([["diff", "DIFF"], ["content", "Snapshot"]], state.codeMode, (value) => { state.codeMode = value; loadView(); }), element("div", { class: "row-actions" }, [iconButton("copy", "Copy redacted configuration", async () => { try { await navigator.clipboard.writeText(text); toast("Copied redacted configuration"); } catch { toast("Clipboard access unavailable"); } }), iconButton("download", "Download redacted configuration", () => download(`${state.device}-${state.kind}.${state.codeMode === "diff" ? "diff" : "txt"}`, text))])])]);
  if (state.codeMode === "diff") {
    const choices = [["previous", "Previous snapshot"], ...history.items.filter((item) => item.index !== state.snapshot).map((item) => [String(item.index), `#${item.index} - ${stamp(item.at)}`])];
    panel.append(element("div", { class: "toolbar comparison-toolbar" }, [element("label", { for: "config-comparison", text: "Compare with" }), selectControl("Comparison snapshot", choices, state.comparison, (value) => { state.comparison = value; loadView(); }), badge(`+${snapshot.changes.added} added`, "low"), badge(`-${snapshot.changes.removed} removed`, "high")]));
    panel.querySelector(".comparison-toolbar select").id = "config-comparison";
    panel.append(element("p", { class: "table-note comparison-note", text: snapshot.comparison ? `Snapshot ${snapshot.comparison.index} (${stamp(snapshot.comparison.at)}) to snapshot ${state.snapshot}` : "Empty baseline to first snapshot" }));
  }
  panel.append(code);
  root.append(element("div", { class: "config-layout" }, [list, panel]));
  return root;
}

function segmented(options, selected, onChange) { return element("div", { class: "segmented", role: "group" }, options.map(([value, label]) => element("button", { class: value === selected ? "selected" : "", "aria-pressed": String(value === selected), onclick: () => onChange(value), text: label }))); }

async function renderDelivery() {
  const data = await api("delivery");
  const actions = [element("button", { class: "primary-button", disabled: state.session.demo || state.session.role === "viewer" || !data.sinks.length, onclick: () => $("#confirm-dialog").showModal() }, [icon("send"), "Send test"])];
  if (AdminUI.isAdmin()) actions.unshift(element("button", { class: "secondary-button", onclick: () => AdminUI.openSettings("notify") }, [icon("pencil"), "Edit channels"]));
  const root = element("div", {}, [heading("Delivery", "Notification channels and persistent delivery queue", actions)]);
  if (!data.sinks.length) return element("div", {}, [root, empty("No notification channels", "No delivery destinations are configured.", "radio-tower")]);
  const rows = data.sinks.map((sink) => element("tr", {}, [element("td", {}, [element("strong", { text: channels[sink.name] || sink.name }), element("span", { class: "record-subtitle", text: sink.destination })]), element("td", {}, [badge(...sinkState(sink))]), element("td", {}, [badge(sink.min_severity)]), element("td", { text: formatNumber(sink.pending) }), element("td", { class: "nowrap", text: stamp(sink.oldest_undelivered), title: forensicStamp(sink.oldest_undelivered) }), element("td", { text: formatNumber(sink.max_attempts) }), element("td", { class: "nowrap", text: stamp(sink.last_delivered) })]));
  root.append(table(["Channel", "Status", "Severity floor", "Queued", "Oldest queued (UTC)", "Attempts", "Last delivered (UTC)"], rows, "records-table"), element("p", { class: "table-note", text: `Daily digest: ${String(data.digest_hour).padStart(2, "0")}:00 UTC` }));
  data.sinks.filter((sink) => sink.health?.failing).forEach((sink) => root.append(element("div", { class: "section" }, [notice(sinkFailure(sink), true)])));
  data.sinks.filter((sink) => sink.error).forEach((sink) => root.append(element("div", { class: "section" }, [notice(`${channels[sink.name] || sink.name}: ${sink.error}`, true)])));
  return root;
}

async function renderSettings() {
  const data = await api("settings");
  return element("div", {}, [heading("Workspace settings", `netrescale ${data.version}`, [badge("read-only")]), element("div", { class: "settings-grid" }, [section("Retention", [definitions([["Raw archive", `${data.retention.raw_days} days`], ["Indexed events", `${data.retention.events_days} days`], ["Findings", `${data.retention.findings_days} days`], ["Acknowledged source logs", `${data.syslog.source_days} days`]])]), section("Collection", [definitions([["Configuration poll", `${data.intervals.config_probe} seconds`], ["Full refresh", `${data.intervals.config_full / 3600} hours`], ["Syslog ingestion", data.syslog.enabled ? "Enabled" : "Disabled"], ["Syslog silence threshold", `${data.intervals.syslog_silence_alert / 60} minutes`]])]), section("Management allowlists", [definitions([["Admin networks", data.syslog.admin_networks.join(", ") || "Not configured"], ["Admin users", data.syslog.admin_users.join(", ") || "Not configured"]])]), section("HA pairs", [data.ha_pairs.length ? definitions(data.ha_pairs.map((pair) => [pair.name, `${pair.nodes.join(" / ")} (${pair.sync_grace_seconds}s grace)`])) : element("p", { class: "muted", text: "No HA pairs configured" })])])]);
}

function download(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const link = element("a", { href: url, download: filename });
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadView() {
  if (!state.session) return;
  if (state.adminDirty) { toast("Save your settings changes before refreshing"); return; }
  const searchFocused = document.activeElement?.matches('input[type="search"]');
  const searchPosition = searchFocused ? document.activeElement.selectionStart : null;
  const request = ++state.request;
  const candidate = location.hash.slice(1) || "overview";
  if (state.view !== candidate) { state.offset = 0; state.snapshot = null; }
  state.view = titles[candidate] ? candidate : "overview";
  $("#breadcrumb-title").textContent = titles[state.view];
  document.title = `${titles[state.view]} | netrescale`;
  document.querySelectorAll("[data-view]").forEach((link) => { link.classList.toggle("active", link.dataset.view === state.view); if (link.dataset.view === state.view) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); });
  $("#refresh").disabled = true;
  $("#content").setAttribute("aria-busy", "true");
  try {
    state.overview = await api("overview");
    if (request !== state.request) return;
    updateChrome();
    const renders = { overview: renderOverview, findings: renderRecords, detection: AdminUI.detection, health: renderHealth, exposure: renderRecords, events: renderRecords, devices: renderDevices, configurations: renderConfigurations, delivery: renderDelivery, settings: AdminUI.isAdmin() ? AdminUI.settings : renderSettings, users: AdminUI.users, credentials: AdminUI.credentials, operations: AdminUI.operations, account: AdminUI.account };
    const view = await renders[state.view]();
    if (request !== state.request) return;
    $("#content").replaceChildren(view);
    AdminUI.focusSettingsDevice();
    AdminUI.syncDeviceActions();
    if (searchFocused) {
      const search = $('#content input[type="search"]');
      search?.focus({ preventScroll: true });
      if (search && searchPosition != null) search.setSelectionRange(searchPosition, searchPosition);
    }
    icons();
  } catch (error) {
    if (request !== state.request || !state.session) return;
    $("#content").replaceChildren(heading(titles[state.view]), notice(error.message, true), element("button", { class: "secondary-button", onclick: loadView }, [icon("refresh-cw"), "Retry"]));
    icons();
  } finally {
    if (request === state.request) { $("#refresh").disabled = false; $("#content").setAttribute("aria-busy", "false"); }
  }
}

function showLogin() { state.session = null; state.overview = null; state.records = []; state.request += 1; AdminUI.reset(); $("#content").replaceChildren(); $("#detail-body").replaceChildren(); $("#application").hidden = true; $("#auth-view").hidden = false; $("#boot").hidden = true; $("#detail-dialog").close(); $("#confirm-dialog").close(); $("#password").value = ""; document.title = "Sign in | netrescale"; icons(); }
function showApp(session) { state.session = session; state.adminDirty = false; $("#session-name").textContent = session.username; $("#application").hidden = false; $("#auth-view").hidden = true; $("#boot").hidden = true; $("#demo-banner").hidden = !session.demo; $("#logout").hidden = !!session.demo; document.querySelectorAll("[data-roles]").forEach(link => { link.hidden = !link.dataset.roles.split(",").includes(session.role); }); closeMenu(); loadView(); }
function closeMenu() { $("#sidebar").classList.remove("open"); $("#scrim").hidden = true; }

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#login-error").hidden = true; $("#login-submit").disabled = true;
  try { await api("login", { method: "POST", body: JSON.stringify({ username: $("#username").value, password: $("#password").value }) }); $("#password").value = ""; showApp(await api("session")); }
  catch (error) { $("#login-error").textContent = error.message; $("#login-error").hidden = false; }
  finally { $("#login-submit").disabled = false; }
});
$("#show-password").addEventListener("click", () => { const show = $("#password").type === "password"; $("#password").type = show ? "text" : "password"; $("#show-password").setAttribute("aria-label", show ? "Hide password" : "Show password"); $("#show-password").title = show ? "Hide password" : "Show password"; });
$("#logout").addEventListener("click", async () => { try { await api("logout", { method: "POST", body: "{}" }); showLogin(); } catch (error) { toast(error.message); } });
$("#refresh").addEventListener("click", loadView);
$("#menu-toggle").addEventListener("click", () => { $("#sidebar").classList.add("open"); $("#scrim").hidden = false; });
$("#scrim").addEventListener("click", closeMenu);
$("#detail-close").addEventListener("click", () => $("#detail-dialog").close());
["confirm-close", "confirm-cancel"].forEach((id) => $(`#${id}`).addEventListener("click", () => $("#confirm-dialog").close()));
$("#confirm-send").addEventListener("click", async () => { $("#confirm-send").disabled = true; try { const result = await api("delivery/test", { method: "POST", body: "{}" }); $("#confirm-dialog").close(); toast(`Test queued for ${result.queued.join(", ")}`); loadView(); } catch (error) { toast(error.message); } finally { $("#confirm-send").disabled = false; } });
$("#account-open").addEventListener("click", () => navigate("account"));
window.addEventListener("hashchange", () => { if (state.adminDirty) { if (!confirm("Discard unsaved settings changes?")) { history.replaceState(null, "", `#${state.view}`); return; } state.adminDirty = false; } closeMenu(); loadView(); });
window.addEventListener("beforeunload", event => { if (state.adminDirty) { event.preventDefault(); event.returnValue = ""; } });
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeMenu(); });
setInterval(() => { if (state.session && !state.adminDirty && !document.hidden && !$(".admin-dialog") && !$("#detail-dialog").open && !$("#confirm-dialog").open && !document.activeElement.closest(".toolbar, .settings-editor, .account-form") && !["operations", "detection", "account"].includes(state.view)) loadView(); }, 30000);

(async () => {
  icons();
  try {
    const auth = await api("auth");
    $("#setup-message").hidden = auth.configured;
    $("#login-submit").disabled = !auth.configured;
    try { showApp(await api("session")); } catch { showLogin(); }
  } catch { $("#boot").replaceChildren(element("span", { class: "brand", text: "netrescale" }), element("p", { class: "error-text", text: "Unable to reach the web service." }), element("button", { class: "secondary-button", onclick: () => location.reload(), text: "Retry" })); }
})();
