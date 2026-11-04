"use strict";

const AdminUI = (() => {
  let settingsTab = "devices";
  let settingsDevice = null;
  let operationsTab = "monitor";
  let detectionTab = "logs";
  let detectionDevice = "";
  let selectedHunt = null;
  let historyFilters = { days: "30", device: "", source: "", offset: 0 };
  let ruleScope = "custom";
  let settingsDraft = null;
  let deviceCredentials = { items: [], error: null };
  const deviceWork = new Map();
  let fieldSequence = 0;
  const isAdmin = () => state.session?.role === "admin";
  const canOperate = () => ["admin", "operator"].includes(state.session?.role);
  const human = (value) => value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
  const errorBox = (error) => notice(error.message || String(error), true);
  const primary = (label, symbol, action, disabled = false) => element("button", { type: "button", class: "primary-button", onclick: action, disabled }, [icon(symbol), label]);

  async function call(action, parameters = {}) {
    try { return await api("admin/action", { method: "POST", body: JSON.stringify({ action, parameters }) }); }
    catch (error) {
      if (error.status !== 428) throw error;
      await reauthenticate();
      return api("admin/action", { method: "POST", body: JSON.stringify({ action, parameters }) });
    }
  }

  function field(label, type = "text", value = "", options = {}) {
    const id = `admin-field-${++fieldSequence}`;
    const attrs = { id, name: options.name || label, "aria-label": label };
    let input;
    if (type === "select") input = element("select", attrs, options.choices.map(([key, text]) => element("option", { value: key, text })));
    else if (type === "textarea") input = element("textarea", { ...attrs, rows: options.rows || 4, spellcheck: "false" });
    else input = element("input", { ...attrs, type, autocomplete: type === "password" ? options.current ? "current-password" : "new-password" : "off" });
    if (type === "checkbox") input.checked = !!value;
    else if (type !== "file") input.value = value ?? "";
    if (options.required) input.required = true;
    if (options.disabled) input.disabled = true;
    for (const key of ["min", "max", "minLength", "maxLength", "pattern", "accept", "step"]) {
      if (options[key] != null) input[key] = key === "pattern" ? options[key].replaceAll("-]", "\\-]") : options[key];
    }
    const wrapper = element("div", { class: `form-field ${type === "checkbox" ? "checkbox-field" : ""}` }, [element("label", { for: id, text: label }), input]);
    return { wrapper, input, value: () => type === "checkbox" ? input.checked : input.value };
  }

  function dialog(title, children, submitLabel, onSubmit, options = {}) {
    const modal = element("dialog", { class: `admin-dialog ${options.wide ? "wide-dialog" : ""}`, id: options.id || "admin-dialog" });
    const form = element("form", { class: "admin-form" });
    const messages = element("div", { role: "alert" });
    const submit = element("button", { type: "submit", class: options.danger ? "danger-button" : "primary-button", text: submitLabel });
    const close = () => modal.close();
    modal.append(element("header", { class: "dialog-header" }, [element("h2", { text: title }), iconButton("x", "Close dialog", close)]));
    form.append(...children, messages, element("div", { class: "form-actions" }, [element("button", { type: "button", class: "secondary-button", onclick: close, text: "Cancel" }), submit]));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      submit.disabled = true;
      messages.replaceChildren();
      try { await onSubmit(); modal.close(); }
      catch (error) { messages.replaceChildren(errorBox(error)); icons(); }
      finally { submit.disabled = false; }
    });
    modal.append(form);
    modal.addEventListener("close", () => { modal.remove(); options.onClose?.(); }, { once: true });
    document.body.append(modal);
    modal.showModal();
    modal.querySelector('input:not(:disabled), select:not(:disabled), textarea:not(:disabled)')?.focus();
    icons();
    return modal;
  }

  function confirmAction(title, message, action, label = "Confirm", danger = false) {
    return dialog(title, [element("p", { class: "confirmation-text", text: message })], label, action, { danger });
  }

  function reauthenticate() {
    return new Promise((resolve, reject) => {
      const password = field("Current password", "password", "", { required: true, current: true });
      let verified = false;
      dialog("Verify your identity", [password.wrapper], "Verify", async () => {
        await api("reauth", { method: "POST", body: JSON.stringify({ password: password.value() }) });
        password.input.value = ""; verified = true; resolve();
      }, { id: "reauth-dialog", onClose: () => { if (!verified) reject(new Error("Verification cancelled")); } });
    });
  }

  function showResult(title, value) {
    $("#detail-dialog").classList.remove("forensic-dialog");
    $("#detail-eyebrow").textContent = "OPERATION RESULT";
    $("#detail-title").textContent = title;
    $("#detail-body").replaceChildren(element("pre", { text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }));
    $("#detail-dialog").showModal();
    icons();
  }

  async function operation(title, action, parameters = {}) {
    try { toast(`${title} in progress`); const result = await call(action, parameters); showResult(title, result); }
    catch (error) { toast(`${title} failed`); showResult(`${title} failed`, error.message); }
  }

  function deviceActions(device) {
    const work = deviceWork.get(device);
    const busy = work?.status === "running";
    const actions = [["device.probe", "Probe", "plug-zap"], ["device.poll", "Poll configuration", "file-diff"], ["device.exposure", "Assess exposure", "fingerprint"], ...(isAdmin() ? [["device.pin", "Inspect TLS key", "shield-check"]] : [])];
    const controls = element("div", { class: "device-action-buttons" }, actions.map(([action, label, symbol]) => iconButton(symbol, `${label}: ${device}`, () => runDeviceAction(device, action, label), !canOperate() || state.session?.demo || busy)));
    const status = element("div", { class: `device-action-state${work?.status === "failed" ? " error-text" : ""}`, role: "status" });
    if (work) {
      status.append(element("span", { class: busy ? "action-spinner" : "" }, [icon(busy ? "loader-circle" : work.status === "failed" ? "circle-alert" : "check")]), element("span", { text: `${work.label}: ${busy ? "working..." : work.status === "failed" ? "failed" : "complete"}` }));
      if (!busy) status.append(iconButton("external-link", `View ${work.label.toLowerCase()} result for ${device}`, () => showResult(`${work.label}: ${device}`, work.error || work.result)));
    }
    return element("div", { class: "device-actions", "data-device": device, "aria-busy": String(!!busy) }, [controls, status]);
  }

  function syncDeviceActions() {
    document.querySelectorAll(".device-actions[data-device]").forEach((node) => node.replaceWith(deviceActions(node.dataset.device)));
    const activity = document.getElementById("device-activity");
    if (!activity) return;
    const running = [...deviceWork.entries()].filter(([_device, work]) => work.status === "running");
    activity.hidden = !running.length;
    activity.replaceChildren(element("span", { class: "action-spinner" }, [icon("loader-circle")]), element("span", { text: running.map(([device, work]) => `${device}: ${work.label}`).join("; ") }), textButton("Devices", () => navigate("devices")));
    icons();
  }

  async function runDeviceAction(device, action, label) {
    if (!canOperate() || state.session.demo || deviceWork.get(device)?.status === "running") return;
    const session = state.session;
    const work = { action, label, status: "running", result: null, error: null };
    deviceWork.set(device, work); syncDeviceActions();
    try {
      const result = await call(action, { device });
      if (state.session !== session || deviceWork.get(device) !== work) return;
      work.status = "complete"; work.result = result;
      if (action === "device.pin") await inspectPin(device, result);
      else if (state.view === "devices") showResult(`${label}: ${device}`, result);
      else toast(`${device}: ${label} complete`);
    } catch (error) {
      if (state.session !== session || deviceWork.get(device) !== work) return;
      work.status = "failed"; work.error = error.message;
      if (state.view === "devices") showResult(`${label} failed: ${device}`, error.message);
      else toast(`${device}: ${label} failed`);
    } finally { syncDeviceActions(); }
  }

  async function users() {
    if (!isAdmin()) return empty("Administrator access required", "Your account cannot manage users.", "lock-keyhole");
    const data = await call("users.list");
    const rows = data.items.map((user) => element("tr", {}, [element("td", { text: user.name }), element("td", {}, [badge(user.role)]), element("td", {}, [badge(user.enabled ? "online" : "disabled")]), element("td", { class: "row-actions" }, [iconButton("user-pen", `Edit user ${user.name}`, () => userForm(user), state.session.demo), iconButton("trash-2", `Delete user ${user.name}`, () => confirmAction("Delete user?", `Delete ${user.name} and revoke their sessions?`, async () => { await call("users.delete", { name: user.name }); toast("User deleted"); loadView(); }, "Delete user", true), state.session.demo || user.name === state.session.username)])]));
    return element("div", {}, [heading("Users", "Web accounts and access roles", [primary("Add user", "user-plus", () => userForm(), state.session.demo)]), table(["Username", "Role", "Status", "Actions"], rows)]);
  }

  function userForm(user = null) {
    const name = field("Username", "text", user?.name, { required: true, disabled: !!user, pattern: "[A-Za-z0-9][A-Za-z0-9._-]{0,63}" });
    const password = field(user ? "New password (optional)" : "Password", "password", "", { required: !user, minLength: 16, maxLength: 256 });
    const role = field("Role", "select", user?.role || "viewer", { choices: [["viewer", "Viewer"], ["operator", "Operator"], ["admin", "Administrator"]] });
    const enabled = field("Account enabled", "checkbox", user?.enabled ?? true);
    dialog(user ? `Edit ${user.name}` : "Create web user", [name.wrapper, password.wrapper, role.wrapper, enabled.wrapper], "Save user", async () => {
      await call("users.save", { name: name.value(), password: password.value() || undefined, role: role.value(), enabled: enabled.value(), create: !user });
      const ownPassword = user?.name === state.session.username && password.value();
      password.input.value = "";
      if (ownPassword) { showLogin(); toast("Password changed. Sign in again."); } else { toast("User saved"); loadView(); }
    });
  }

  async function credentials() {
    if (!isAdmin()) return empty("Administrator access required", "Your account cannot manage credentials.", "lock-keyhole");
    const data = await call("credentials.list");
    const root = element("div", {}, [heading("Credentials", "Encrypted appliance and relay credentials", [primary("Add credential", "key-round", () => credentialForm(), state.session.demo)])]);
    const rows = data.items.map((credential) => element("tr", {}, [element("td", {}, [element("strong", { text: credential.name }), element("span", { class: "record-subtitle", text: `local:${credential.name}` })]), element("td", { text: credential.username }), element("td", { text: credential.users.join(", ") || "Unassigned" }), element("td", { class: "nowrap", text: stamp(credential.updated) }), element("td", { class: "row-actions" }, [iconButton("pencil", `Edit credential ${credential.name}`, () => credentialForm(credential), state.session.demo), iconButton("plug-zap", `Test credential ${credential.name}`, () => operation("Credential test", "credentials.test", { name: credential.name }), state.session.demo), iconButton("trash-2", `Delete credential ${credential.name}`, () => confirmAction("Delete credential?", `Delete ${credential.name} from the encrypted vault?`, async () => { await call("credentials.delete", { name: credential.name }); toast("Credential deleted"); loadView(); }, "Delete credential", true), state.session.demo || !!credential.users.length)])]));
    root.append(rows.length ? table(["Name", "Username", "Referenced by", "Updated (UTC)", "Actions"], rows, "records-table") : empty("No credentials stored", "The vault has no credential entries.", "key-round"));
    if (data.blocked.length) {
      const blockedRows = data.blocked.map((item) => element("tr", {}, [
        element("td", { text: item.device }), element("td", { text: item.credential }),
        element("td", { text: stamp(item.since) })
      ]));
      root.append(section("Blocked credentials", [table(["Device", "Credential", "Rejected (UTC)"], blockedRows)]));
    }
    return root;
  }

  function credentialForm(credential = null, onSaved = null) {
    const name = field("Credential name", "text", credential?.name, { required: true, disabled: !!credential, pattern: "[A-Za-z0-9][A-Za-z0-9._-]{0,63}" });
    const username = field("Appliance username", "text", credential?.username, { required: true, maxLength: 256 });
    const password = field(credential ? "New password (optional)" : "Password", "password", "", { required: !credential, maxLength: 4096 });
    const key = field("SSH private key file (optional)", "file");
    const removeKey = field("Remove existing SSH key", "checkbox", false, { disabled: !credential?.has_ssh_key });
    key.input.addEventListener("change", () => { password.input.required = !credential && !key.input.files.length; });
    const advanced = element("details", { class: "device-advanced" }, [
      element("summary", {}, [icon("key-round"), "SSH key (advanced)"]), key.wrapper, removeKey.wrapper
    ]);
    dialog(credential ? `Edit ${credential.name}` : "Create credential", [name.wrapper, username.wrapper, password.wrapper, advanced], "Save credential", async () => {
      const file = key.input.files[0];
      if (file && file.size > 32768) throw new Error("SSH key exceeds 32 KB");
      await call("credentials.save", { name: name.value(), username: username.value(), password: password.value() || undefined, ssh_private_key: file ? await file.text() : undefined, remove_ssh_key: removeKey.value(), create: !credential });
      password.input.value = ""; key.input.value = ""; toast("Credential stored in the encrypted vault");
      if (onSaved) await onSaved(name.value()); else loadView();
    });
  }

  const sections = [["devices", "Devices"], ["ha_pairs", "HA pairs"], ["defaults", "Collection"], ["syslog", "Syslog"], ["notify", "Notifications"], ["retention", "Retention"], ["web", "Web access"], ["general", "Platform"], ["paths", "Host paths"]];
  function schemaFor(schema) { return schema.$ref ? settingsDraft.schema.$defs[schema.$ref.split("/").pop()] : schema; }
  function defaultValue(schema) {
    schema = schemaFor(schema);
    if (Object.hasOwn(schema, "default")) return structuredClone(schema.default);
    if (schema.anyOf) return defaultValue(schema.anyOf.find((entry) => entry.type !== "null"));
    if (schema.type === "object") return Object.fromEntries(Object.entries(schema.properties).map(([key, value]) => [key, defaultValue(value)]));
    if (schema.type === "array") return [];
    if (schema.type === "boolean") return false;
    if (schema.type === "integer" || schema.type === "number") return schema.minimum ?? 0;
    return schema.enum?.[0] ?? "";
  }
  function assign(path, value) { let current = settingsDraft.document; for (const key of path.slice(0, -1)) current = current[key]; current[path.at(-1)] = value; state.adminDirty = true; $("#settings-save")?.removeAttribute("disabled"); $("#settings-state").textContent = "Unsaved changes"; }

  async function refreshDeviceCredentials() {
    try { deviceCredentials = { ...(await call("credentials.list")), error: null }; }
    catch { deviceCredentials = { items: [], error: "Stored credentials are unavailable. Check vault and daemon status." }; }
  }

  function credentialSelector(value, path, redraw, disabled) {
    const credentials = deviceCredentials.items.filter((credential) => credential.has_password !== false);
    const defaultRef = settingsDraft.document.defaults.nitro_credential;
    const inherited = credentials.find((credential) => `local:${credential.name}` === defaultRef);
    const defaultLabel = inherited ? `${inherited.name} (${inherited.username})` : `${defaultRef} - not available`;
    const choices = [["", `Use default: ${defaultLabel}`], ...credentials.map((credential) => [
      `local:${credential.name}`, `${credential.name} (${credential.username})`
    ])];
    if (value && !choices.some(([reference]) => reference === value)) choices.push([value, `${value} - not available`]);
    const input = field("Stored credential", "select", value || "", {
      disabled: disabled || !!deviceCredentials.error, choices
    });
    input.input.addEventListener("change", () => assign(path, input.value() || null));
    const controls = element("div", { class: "credential-picker" });
    input.input.replaceWith(controls);
    controls.append(input.input, iconButton("plus", "Create stored credential", () => credentialForm(null, async (name) => {
      await refreshDeviceCredentials();
      assign(path, `local:${name}`);
      redraw();
    }), disabled));
    return input.wrapper;
  }

  function deviceFields(device, index, redraw, disabled) {
    const schema = schemaFor(settingsDraft.schema.$defs.Device);
    const path = ["devices", index];
    const name = field("Device name", "text", device.name, {
      disabled, required: true, pattern: schema.properties.name.pattern, maxLength: 63
    });
    const address = field("Management IP (NSIP)", "text", device.nsip, { disabled, required: true });
    const pinning = field("Use TLS key fingerprint (SPKI)", "checkbox", device.spki_pinning !== false, { disabled });
    const pin = field("TLS key fingerprint (SPKI)", "text", device.spki_pin || "", { disabled: disabled || !pinning.value() });
    const ca = field("Trusted CA bundle (optional server path)", "text", device.ca_bundle || "", { disabled });
    const updateTlsFields = () => {
      pin.wrapper.hidden = !pinning.value();
      pin.input.disabled = disabled || !pinning.value();
      ca.input.placeholder = settingsDraft.document.defaults.ca_bundle || (pinning.value() ? "None (pin only)" : "System CA trust store");
    };
    updateTlsFields();
    name.input.addEventListener("input", () => assign([...path, "name"], name.value()));
    address.input.addEventListener("input", () => assign([...path, "nsip"], address.value().trim()));
    pin.input.addEventListener("input", () => assign([...path, "spki_pin"], pin.value().trim() || null));
    pinning.input.addEventListener("change", () => { assign([...path, "spki_pinning"], pinning.value()); updateTlsFields(); });
    ca.input.addEventListener("input", () => assign([...path, "ca_bundle"], ca.value().trim() || null));
    const basics = element("div", { class: "settings-fields" }, [
      name.wrapper, address.wrapper, credentialSelector(device.nitro_credential, [...path, "nitro_credential"], redraw, disabled), pinning.wrapper, pin.wrapper, ca.wrapper
    ]);
    const advancedKeys = ["nitro_port", "firmware_variant", "syslog_sources", "timezone", "date_format"];
    const advanced = element("details", { class: "device-advanced" }, [
      element("summary", {}, [icon("settings-2"), "Advanced"]),
      element("div", { class: "settings-fields" }, advancedKeys.map((key) =>
        schemaField(schema.properties[key], device[key], [...path, key], redraw, disabled)))
    ]);
    const root = element("div", {}, [basics, advanced]);
    if (device.mode !== "observe") root.prepend(element("div", { class: "notice warning" }, [
      "Active SSH collection is unavailable.",
      element("button", { type: "button", class: "secondary-button", disabled,
        onclick: () => { assign([...path, "mode"], "observe"); redraw(); }, text: "Use read-only mode" })
    ]));
    return root;
  }

  function deviceEditor(redraw, disabled) {
    const devices = settingsDraft.document.devices;
    const schema = schemaFor(settingsDraft.schema.$defs.Device);
    const root = element("section", { class: "settings-array device-editor" }, [
      element("div", { class: "section-heading" }, [element("h2", { text: "Devices" }),
        element("div", { class: "row-actions" }, [iconButton("refresh-cw", "Reload stored credentials", async () => { await refreshDeviceCredentials(); redraw(); }, disabled), element("button", { type: "button", class: "secondary-button", disabled,
          onclick: () => { assign(["devices"], [...devices, defaultValue(schema)]); redraw(); }
        }, [icon("plus"), "Add device"])])
      ])
    ]);
    if (deviceCredentials.error) root.append(notice(deviceCredentials.error, true));
    else if (!deviceCredentials.items.some((credential) => credential.has_password !== false)) root.append(notice("No password credentials stored in the vault."));
    if (!devices.length) root.append(empty("No devices configured", "Inventory is empty.", "server"));
    root.append(...devices.map((device, index) => element("section", { class: "settings-array-item", id: `device-settings-${device.name}`, "aria-label": device.name || "New device" }, [
      element("div", { class: "section-heading" }, [element("h3", { text: device.name || "New device" }),
        element("div", { class: "row-actions" }, [badge("read-only"), iconButton("trash-2", `Remove ${device.name || index + 1}`,
          () => removeDevice(index, redraw), disabled)])
      ]), deviceFields(device, index, redraw, disabled)
    ])));
    return root;
  }

  function removeDevice(index, redraw) {
    const device = settingsDraft.document.devices[index];
    const linked = settingsDraft.document.ha_pairs.filter((pair) => pair.nodes.includes(device.name));
    const remove = () => {
      assign(["devices"], settingsDraft.document.devices.filter((_entry, number) => number !== index));
      if (linked.length) assign(["ha_pairs"], settingsDraft.document.ha_pairs.filter((pair) => !pair.nodes.includes(device.name)));
      redraw();
    };
    if (linked.length) confirmAction("Remove device?", `Remove ${device.name} and its HA pair ${linked.map((pair) => pair.name).join(", ")}? Other devices are retained.`, remove, "Remove device", true);
    else remove();
  }
  function schemaField(schema, value, path, redraw, disabled = false) {
    schema = schemaFor(schema);
    const label = human(String(path.at(-1)));
    const nullable = schema.anyOf?.some((entry) => entry.type === "null");
    const resolved = nullable ? schemaFor(schema.anyOf.find((entry) => entry.type !== "null")) : schema;
    if (path[0] === "ha_pairs" && path.length === 3 && path[2] === "nodes") {
      const nodes = value || [];
      const assigned = new Set(settingsDraft.document.ha_pairs.flatMap((pair, index) => index === path[1] ? [] : pair.nodes));
      return element("div", { class: "settings-fields ha-node-selectors" }, [0, 1].map((position) => {
        const selected = nodes[position] || "";
        const choices = [["", "Select a device"], ...settingsDraft.document.devices.filter((device) => device.name && (device.name === selected || (!assigned.has(device.name) && device.name !== nodes[1 - position]))).map((device) => [device.name, `${device.name} (${device.nsip})`])];
        if (selected && !choices.some(([name]) => name === selected)) choices.push([selected, `${selected} (not in inventory)`]);
        const input = field(position === 0 ? "First device" : "Second device", "select", selected, { choices, disabled, required: true });
        input.input.addEventListener("change", () => { const updated = [nodes[0] || "", nodes[1] || ""]; updated[position] = input.value(); assign(path, updated); redraw(); });
        return input.wrapper;
      }));
    }
    if (nullable && resolved.type === "object") {
      const enabled = field(`${label} enabled`, "checkbox", value != null, { disabled });
      enabled.input.addEventListener("change", () => { assign(path, enabled.value() ? defaultValue(resolved) : null); redraw(); });
      return element("fieldset", { class: "settings-fieldset" }, [element("legend", { text: label }), enabled.wrapper, value == null ? null : schemaField(resolved, value, path, redraw, disabled)]);
    }
    if (resolved.type === "object") return element("div", { class: "settings-fields" }, Object.entries(resolved.properties).map(([key, child]) => schemaField(child, value?.[key], [...path, key], redraw, disabled)));
    if (resolved.type === "array") {
      const itemSchema = schemaFor(resolved.items);
      if (itemSchema.type === "object") {
        const items = value || [];
        return element("section", { class: "settings-array" }, [element("div", { class: "section-heading" }, [element("h2", { text: label }), element("button", { type: "button", class: "secondary-button", disabled, onclick: () => { assign(path, [...items, defaultValue(itemSchema)]); redraw(); } }, [icon("plus"), `Add ${path.at(-1) === "devices" ? "device" : "pair"}`])]), ...items.map((item, index) => element("section", { class: "settings-array-item" }, [element("div", { class: "section-heading" }, [element("h3", { text: item.name || `New ${label.toLowerCase()}` }), iconButton("trash-2", `Remove ${item.name || index + 1}`, () => { assign(path, items.filter((_entry, number) => number !== index)); redraw(); }, disabled)]), schemaField(itemSchema, item, [...path, index], redraw, disabled)]))]);
      }
      const input = field(label, "textarea", (value || []).join("\n"), { disabled, rows: 3 });
      input.input.addEventListener("input", () => assign(path, input.value().split(/\r?\n/).map((item) => item.trim()).filter(Boolean)));
      return input.wrapper;
    }
    const type = resolved.enum ? "select" : resolved.type === "boolean" ? "checkbox" : ["integer", "number"].includes(resolved.type) ? "number" : path.join(".").includes("webhook.url") ? "password" : "text";
    const input = field(label, type, value ?? "", { disabled, choices: resolved.enum?.map((item) => [item, human(String(item))]), min: resolved.minimum, max: resolved.maximum, minLength: resolved.minLength, maxLength: resolved.maxLength, pattern: resolved.pattern, step: resolved.type === "integer" ? 1 : "any" });
    input.input.addEventListener(type === "checkbox" || type === "select" ? "change" : "input", () => { const raw = input.value(); assign(path, type === "number" ? raw === "" && nullable ? null : Number(raw) : raw === "" && nullable ? null : raw); });
    return input.wrapper;
  }

  async function settings() {
    settingsDraft = await call("settings.get");
    await refreshDeviceCredentials();
    state.adminDirty = false;
    const root = element("div", {}, [heading("Settings", "Application configuration and inventory")]);
    const messages = element("div", { id: "settings-messages", role: "status" });
    const stateLabel = element("span", { id: "settings-state", class: "muted", text: settingsDraft.pending_apply ? "Saved settings need activation" : "Settings saved" });
    const editor = element("form", { id: "settings-editor", class: "settings-editor" });
    const tabs = element("div", { class: "admin-tabs", role: "tablist", "aria-label": "Settings sections" });
    let saving = false;
    function redraw() {
      tabs.replaceChildren(...sections.map(([key, title]) => element("button", { type: "button", role: "tab", "aria-selected": String(settingsTab === key), class: settingsTab === key ? "selected" : "", onclick: () => { settingsTab = key; redraw(); }, text: title })));
      if (settingsTab === "devices") editor.replaceChildren(deviceEditor(redraw, state.session.demo));
      else if (settingsTab === "general") {
        const keys = ["database_url", "max_credential_age_days", "admin_group"];
        editor.replaceChildren(element("div", { class: "settings-fields" }, keys.map((key) => schemaField(settingsDraft.schema.properties[key], settingsDraft.document[key], [key], redraw, key === "admin_group" || state.session.demo))));
      } else editor.replaceChildren(schemaField(settingsDraft.schema.properties[settingsTab], settingsDraft.document[settingsTab], [settingsTab], redraw, settingsTab === "paths" || state.session.demo));
      if (settingsTab === "paths") editor.prepend(notice("Host-managed storage paths. A coordinated host migration is required to change these locations."));
      if (settingsTab === "web") editor.prepend(notice("Changing web access or session settings requires a new sign-in."));
      icons();
    }
    async function save() {
      if (saving || !editor.reportValidity()) return;
      saving = true;
      const draft = settingsDraft, session = state.session;
      const controls = [...root.querySelectorAll("input,select,textarea,button")].map((control) => [control, control.disabled]);
      controls.forEach(([control]) => { control.disabled = true; });
      root.setAttribute("aria-busy", "true");
      stateLabel.textContent = "Saving settings...";
      messages.replaceChildren();
      try {
        const result = await call("settings.save", { document: structuredClone(draft.document), revision: draft.revision });
        if (state.session !== session || settingsDraft !== draft) return;
        draft.revision = result.revision;
        draft.pending_apply = !result.applied;
        state.adminDirty = !result.applied;
        (result.warnings || []).forEach((warning) => messages.append(notice(warning)));
        if (!result.applied) {
          stateLabel.textContent = "Saved; activation failed";
          (result.errors || [{ error: "Settings could not be activated. Save again to retry." }]).forEach((error) => messages.append(notice(error.error, true)));
          return;
        }
        stateLabel.textContent = result.setup_error ? "Saved; monitoring needs attention" : "Settings saved";
        redraw();
        if (result.setup_error) messages.append(notice(result.setup_error, true));
        if (result.web_reload) {
          stateLabel.textContent = "Saved; reconnecting dashboard...";
          toast("Settings saved. Reconnecting...");
          setTimeout(() => location.reload(), 4500);
        } else toast(result.workers_reloaded ? "Settings saved; monitoring workers refreshed" : "Settings saved");
      } catch (error) { stateLabel.textContent = "Save failed"; messages.replaceChildren(errorBox(error)); }
      finally {
        controls.forEach(([control, disabled]) => { control.disabled = disabled; });
        saveButton.disabled = !!state.session?.demo;
        root.setAttribute("aria-busy", "false"); saving = false; icons();
      }
    }
    const saveButton = primary("Save settings", "save", save, state.session.demo); saveButton.id = "settings-save";
    editor.addEventListener("submit", (event) => { event.preventDefault(); save(); });
    root.append(element("div", { class: "settings-actions" }, [stateLabel, saveButton]), messages, tabs, editor);
    redraw();
    return root;
  }

  async function account() {
    const current = field("Current password", "password", "", { required: true, current: true });
    const password = field("New password", "password", "", { required: true, minLength: 16, maxLength: 256 });
    const confirmation = field("Confirm new password", "password", "", { required: true, minLength: 16, maxLength: 256 });
    const messages = element("div", { role: "alert" });
    const form = element("form", { class: "account-form" }, [current.wrapper, password.wrapper, confirmation.wrapper, messages, element("button", { type: "submit", class: "primary-button", disabled: state.session.demo }, [icon("key-round"), "Change password"])]);
    form.addEventListener("submit", async (event) => { event.preventDefault(); if (password.value() !== confirmation.value()) { messages.replaceChildren(notice("Passwords do not match", true)); return; } try { await call("account.password", { current_password: current.value(), password: password.value() }); showLogin(); toast("Password changed. Sign in again."); } catch (error) { messages.replaceChildren(errorBox(error)); } });
    return element("div", {}, [heading("My account", `${state.session.username} / ${human(state.session.role)}`), form]);
  }

  function huntResults(result, savedRun = null) {
    const root = section("Hunt results", [], iconButton("download", "Export hunt results", () => download(savedRun ? `hunt-${savedRun.id}.json` : "scalar-hunt.json", JSON.stringify(savedRun || result, null, 2))));
    root.append(element("p", { class: "table-note", text: `${formatNumber(result.lines)} lines scanned, ${formatNumber(result.findings.length)} findings` }));
    if (!savedRun) {
      const runs = result.runs || (result.run ? [result.run] : []);
      if (runs.length) root.append(element("div", { class: "saved-hunt-links" }, runs.map((run) => textButton(`Saved run ${run.id.slice(0, 8)}${run.source ? ` / ${run.source}` : ""}`, () => openHunt(run.id)))));
    }
    if (result.truncated) root.append(notice("Result limit reached; additional matches may exist."));
    if (result.captures?.some((capture) => capture.truncated)) root.append(notice("Some captures contain only the latest 1 MiB or 10,000 lines. Earlier log content was not scanned."));
    const disabled = Object.entries(result.disabled_rules || {});
    if (disabled.length) root.append(element("details", { class: "device-advanced" }, [element("summary", { text: `${disabled.length} inactive rules` }), definitions(disabled)]));
    let minimum = "info", query = "", offset = 0;
    const records = element("div", { class: "hunt-records" });
    const filters = element("div", { class: "toolbar" }, [selectControl("Hunt minimum severity", [["info", "All severities"], ["low", "Low and above"], ["medium", "Medium and above"], ["high", "High and above"], ["critical", "Critical only"]], minimum, (value) => { minimum = value; offset = 0; redraw(); }), element("input", { type: "search", placeholder: "Search hunt results", "aria-label": "Search hunt results", oninput: (event) => { query = event.target.value.toLowerCase(); offset = 0; redraw(); } })]);
    function redraw() {
      const matches = result.findings.filter((finding) => levels.indexOf(finding.severity) <= levels.indexOf(minimum) && [finding.title, finding.summary, finding.device, finding.rule_id].join(" ").toLowerCase().includes(query));
      records.replaceChildren(matches.length ? table(["Severity", "Finding", "Device", "Observed (UTC)", ""], matches.slice(offset, offset + 50).map(findingRow), "records-table") : empty("No matching findings", "No rule matches in the selected sample and filters.", "scan-search"));
      records.append(element("div", { class: "pagination" }, [element("span", { text: `${matches.length ? offset + 1 : 0}-${Math.min(offset + 50, matches.length)} of ${formatNumber(matches.length)} findings` }), element("div", { class: "pagination-controls" }, [iconButton("chevron-left", "Previous hunt results", () => { offset -= 50; redraw(); }, offset === 0), iconButton("chevron-right", "Next hunt results", () => { offset += 50; redraw(); }, offset + 50 >= matches.length)])]));
      icons();
    }
    root.append(filters, records);
    redraw();
    return root;
  }

  function showLog(capture) {
    $("#detail-dialog").classList.remove("forensic-dialog");
    $("#detail-eyebrow").textContent = `${capture.device} / ${stamp(capture.collected_at)}`;
    $("#detail-title").textContent = capture.path;
    const code = element("pre", { class: "config-code", tabindex: "0", "aria-label": "Collected log text" });
    const count = element("p", { class: "table-note", role: "status" });
    const lines = capture.text.split("\n");
    function filter(query = "") {
      const matches = lines.filter((line) => line.toLowerCase().includes(query.toLowerCase()));
      code.textContent = matches.slice(0, 500).join("\n") || "No matching lines.";
      count.textContent = `${formatNumber(matches.length)} matching lines, ${Math.min(matches.length, 500)} shown`;
    }
    const toolbar = element("div", { class: "toolbar" }, [element("input", { type: "search", placeholder: "Search log text", "aria-label": "Search log text", oninput: (event) => filter(event.target.value) }), iconButton("download", "Download log sample", () => download(`${capture.device}-${capture.source}.log`, capture.text))]);
    $("#detail-body").replaceChildren(toolbar, definitions([["Captured (UTC)", forensicStamp(capture.collected_at)], ["Retained lines", capture.lines], ["Retained bytes", formatNumber(capture.retained_bytes)], ["SHA-256 of retained original", capture.sha256]]), ...(capture.truncated ? [notice("Partial capture: earlier content was not retained.")] : []), count, code);
    filter();
    $("#detail-dialog").showModal();
    icons();
  }

  async function deviceLogs(root) {
    const devices = state.overview.devices;
    if (!devices.length) { root.append(empty("No devices configured", "Inventory is empty.", "server")); return; }
    if (state.session.demo) { root.append(empty("No collected logs", "Device connections are disabled in the preview.", "file-search")); return; }
    if (!devices.some((device) => device.name === detectionDevice)) detectionDevice = devices[0].name;
    const device = detectionDevice;
    const selected = new Set();
    let items = [], busy = false;
    const messages = element("div", { role: "status", class: "detection-status" });
    const list = element("div");
    const results = element("div", { id: "detection-results" });
    const target = selectControl("Detection device", devices.map((entry) => [entry.name, entry.name]), device, (value) => { detectionDevice = value; loadView(); });
    const selection = (item) => ({ device, source: item.source, sha256: item.capture.sha256 });
    async function perform(message, action) {
      if (busy) return;
      busy = true; sync(); messages.replaceChildren(element("p", { class: "table-note", text: message }));
      try { await action(); }
      catch (error) { messages.replaceChildren(errorBox(error)); }
      finally { busy = false; sync(); icons(); }
    }
    const fetchButton = primary("Fetch selected logs", "download", () => perform(`Fetching logs from ${device}...`, async () => {
      const result = await call("logs.fetch", { device, sources: [...selected] });
      results.replaceChildren();
      messages.replaceChildren(element("p", { class: "table-note", text: `${result.captures.length} logs fetched, ${result.errors.length} unavailable` }), ...result.errors.map((error) => notice(`${error.path}: ${error.error}`, true)));
      await refresh();
    }));
    const huntButton = primary("Hunt selected logs", "scan-search", () => perform("Scanning retained log captures...", async () => {
      const result = { findings: [], captures: [], runs: [], disabled_rules: {}, lines: 0, truncated: false };
      for (const item of items.filter((entry) => selected.has(entry.source) && entry.capture)) {
        const scan = await call("logs.hunt", selection(item));
        result.findings.push(...scan.findings); result.captures.push(scan.capture);
        result.runs.push({ ...scan.run, source: item.source });
        Object.assign(result.disabled_rules, scan.disabled_rules); result.lines += scan.lines; result.truncated ||= scan.truncated;
      }
      result.findings.sort((before, after) => levels.indexOf(before.severity) - levels.indexOf(after.severity));
      results.replaceChildren(huntResults(result)); messages.replaceChildren();
      results.scrollIntoView({ block: "start", behavior: "smooth" });
    }));
    function sync() {
      target.disabled = busy;
      fetchButton.disabled = busy || !selected.size;
      huntButton.disabled = busy || !items.some((item) => selected.has(item.source) && item.capture);
      list.querySelectorAll("input,button").forEach((control) => { control.disabled = busy || control.dataset.unavailable === "true"; });
      root.querySelectorAll('[role="tab"]').forEach((tab) => { tab.disabled = busy; });
    }
    async function refresh(selectAll = false) {
      items = (await call("logs.list", { device })).items;
      if (selectAll) items.forEach((item) => selected.add(item.source));
      const rows = items.map((item) => {
        const checkbox = element("input", { type: "checkbox", class: "log-select", "aria-label": `Select ${item.path}`, onchange: () => { if (checkbox.checked) selected.add(item.source); else selected.delete(item.source); sync(); } });
        checkbox.checked = selected.has(item.source);
        const view = iconButton("file-search", `View ${item.path}`, () => perform("Opening captured log...", async () => { showLog(await call("logs.read", selection(item))); messages.replaceChildren(); }), !item.capture);
        view.dataset.unavailable = String(!item.capture);
        return element("tr", {}, [element("td", {}, [checkbox]), element("td", {}, [element("strong", { class: "mono", text: item.path }), element("span", { class: "record-subtitle", text: item.source })]), element("td", {}, [badge(item.capture ? item.capture.truncated ? "Partial" : "Captured" : "Not fetched", item.capture ? item.capture.truncated ? "medium" : "low" : "info")]), element("td", { class: "nowrap", text: item.capture ? stamp(item.capture.collected_at) : "Never" }), element("td", { class: "nowrap", text: item.capture ? `${formatNumber(item.capture.lines)} lines / ${formatNumber(item.capture.retained_bytes)} B` : "--" }), element("td", {}, [view])]);
      });
      list.replaceChildren(table(["", "Log file", "Capture", "Collected (UTC)", "Retained", ""], rows, "log-table")); sync(); icons();
    }
    root.append(element("div", { class: "toolbar detection-actions" }, [target, fetchButton, huntButton]), messages, list, results);
    await refresh(true);
  }

  function openHunt(identity) {
    selectedHunt = identity; detectionTab = "history";
    if (state.view === "detection") loadView(); else navigate("detection");
  }

  async function huntHistory(root) {
    if (state.session.demo) { root.append(empty("No hunt history", "No investigation runs in this preview.", "history")); return; }
    if (selectedHunt) {
      const run = await call("hunts.get", { id: selectedHunt });
      root.append(element("div", { class: "toolbar" }, [element("button", { class: "secondary-button", onclick: () => { selectedHunt = null; loadView(); } }, [icon("arrow-left"), "Hunt history"]), badge(run.status === "running" ? "Unfinished" : human(run.status), run.status === "complete" ? "low" : "medium"), element("span", { class: "mono", text: run.id })]));
      root.append(element("div", { class: "hunt-metadata" }, [definitions([["Device / source", `${run.device} / ${run.source}`], ["Run by", run.actor], ["Started (UTC)", forensicStamp(run.started_at)], ["Completed (UTC)", run.completed_at ? forensicStamp(run.completed_at) : "Not recorded"], ["Input", run.context.origin === "device" ? run.context.capture?.path : "Uploaded log"], ["Input SHA-256", run.context.input_sha256], ["Rule set SHA-256", run.context.rules_sha256], ["Rules at execution", run.context.rules?.length || 0]])]));
      if (run.error) root.append(notice(run.error, true));
      if (run.result) root.append(huntResults({ ...run.result, captures: run.context.capture ? [run.context.capture] : [] }, run));
      else root.append(notice("This run has no recorded results."));
      root.append(element("details", { class: "device-advanced" }, [element("summary", { text: "Rule definitions at execution" }), element("pre", { class: "config-code", text: JSON.stringify(run.context.rules || [], null, 2) })]));
      return;
    }
    const records = await call("hunts.list", { ...historyFilters, days: Number(historyFilters.days), limit: 25 });
    const deviceNames = [...new Set([...state.overview.devices.map((device) => device.name), "uploaded", ...records.items.map((run) => run.device), ...(historyFilters.device ? [historyFilters.device] : [])])];
    const change = (name, value) => { historyFilters[name] = value; historyFilters.offset = 0; loadView(); };
    root.append(element("div", { class: "toolbar" }, [selectControl("History device", [["", "All devices"], ...deviceNames.map((name) => [name, name])], historyFilters.device, (value) => change("device", value)), selectControl("History source", [["", "All sources"], ...["nslog", "bashlog", "shlog", "httperror", "httpaccess", "httpaccess-vpn", "notice", "auth"].map((source) => [source, source])], historyFilters.source, (value) => change("source", value)), selectControl("History time range", [["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["3650", "All retained runs"]], historyFilters.days, (value) => change("days", value)), iconButton("filter-x", "Reset history filters", () => { historyFilters = { days: "30", device: "", source: "", offset: 0 }; loadView(); })]));
    const rows = records.items.map((run) => element("tr", {}, [element("td", { class: "nowrap", text: stamp(run.started_at), title: forensicStamp(run.started_at) }), element("td", {}, [element("button", { class: "record-title", onclick: () => openHunt(run.id), text: run.device }), element("span", { class: "record-subtitle", text: `${run.source} / ${run.id.slice(0, 8)}` })]), element("td", { text: run.actor }), element("td", {}, [badge(run.status === "running" ? "Unfinished" : human(run.status), run.status === "complete" ? "low" : "medium")]), element("td", { text: formatNumber(run.finding_count) }), element("td", {}, [iconButton("file-search", `Open hunt ${run.id.slice(0, 8)}`, () => openHunt(run.id))])]));
    root.append(rows.length ? table(["Started (UTC)", "Device / source", "Run by", "Status", "Findings", ""], rows, "records-table") : empty("No hunt runs", "No saved runs match these filters.", "history"));
    root.append(element("div", { class: "pagination" }, [element("span", { text: `${records.total ? historyFilters.offset + 1 : 0}-${historyFilters.offset + rows.length} of ${formatNumber(records.total)} runs` }), element("div", { class: "pagination-controls" }, [iconButton("chevron-left", "Previous hunt runs", () => { historyFilters.offset -= 25; loadView(); }, historyFilters.offset === 0), iconButton("chevron-right", "Next hunt runs", () => { historyFilters.offset += 25; loadView(); }, historyFilters.offset + rows.length >= records.total)])]));
  }

  function ruleEditor(text, revision, title = "New hunt rule") {
    const definition = field("Rule definition (YAML or JSON)", "textarea", text, { rows: 18, required: true, maxLength: 262144 });
    definition.input.classList.add("rule-definition");
    const upload = field("Import rule file", "file", "", { accept: ".yaml,.yml,.json" });
    const messages = element("div", { role: "status", class: "rule-test-status" });
    upload.input.addEventListener("change", async () => {
      try { const file = upload.input.files[0]; if (!file) return; if (file.size > 262144) throw new Error("Rule file exceeds 256 KiB"); definition.input.value = await file.text(); messages.replaceChildren(); }
      catch (error) { messages.replaceChildren(errorBox(error)); }
    });
    definition.input.addEventListener("input", () => messages.replaceChildren());
    const test = element("button", { type: "button", class: "secondary-button", onclick: async () => {
      test.disabled = true; messages.replaceChildren();
      try { const result = await call("rules.validate", { text: definition.value() }); messages.replaceChildren(element("p", { class: "table-note", text: `${result.tested} test cases passed across ${result.rules.length} rules` })); }
      catch (error) { messages.replaceChildren(errorBox(error)); }
      finally { test.disabled = false; icons(); }
    } }, [icon("flask-conical"), "Test rules"]);
    dialog(title, [element("div", { class: "row-actions" }, [badge("Manual hunts", "info")]), upload.wrapper, definition.wrapper, test, messages], "Save rules", async () => {
      const result = await call("rules.save", { text: definition.value(), revision });
      toast(`${result.rules.length} hunt rules saved`); ruleScope = "custom"; await loadView();
    }, { id: "rule-editor", wide: true });
  }

  function newRuleText() {
    return JSON.stringify({ id: "custom-new-rule", title: "New hunt rule", severity: "medium", enabled: true, sources: ["nslog"], match: { raw_regex: "(?i)example-marker" }, description: "", provenance: "Custom rule", tests: { positive: [{ source: "nslog", line: "example-marker" }], negative: [{ source: "nslog", line: "ordinary log entry" }] } }, null, 2);
  }

  async function chooseTemplate(revision) {
    try {
      const pack = await call("rules.templates");
      const choice = field("Rule template", "select", pack.items[0].id, { choices: pack.items.map((item) => [item.id, item.title]) });
      const description = element("p", { class: "confirmation-text" });
      const preview = element("pre", { class: "config-code rule-template-preview" });
      const selected = () => pack.items.find((item) => item.id === choice.value());
      const redraw = () => { description.textContent = selected().description; preview.textContent = selected().yaml; };
      choice.input.addEventListener("change", redraw); redraw();
      let modal;
      const all = element("button", { type: "button", class: "secondary-button", onclick: () => { modal.close(); ruleEditor(pack.yaml, revision, "Import script templates"); } }, [icon("files"), `Review all ${pack.items.length} templates`]);
      modal = dialog("Script-derived templates", [definitions([["Source", `${pack.source.name} v${pack.source.version}`], ["Author", pack.source.author], ["Provenance", pack.source.provenance], ["Coverage", pack.source.coverage]]), choice.wrapper, description, preview, all], "Use template", async () => { modal.close(); ruleEditor(selected().yaml, revision, "Add template rule"); }, { id: "rule-template-dialog", wide: true });
    } catch (error) { toast(error.message); }
  }

  async function huntRules(root) {
    const catalog = await call("rules.list");
    const editable = isAdmin() && !state.session.demo;
    const actions = [primary("New rule", "plus", () => ruleEditor(newRuleText(), catalog.revision), !editable), element("button", { class: "secondary-button", disabled: !editable, onclick: () => chooseTemplate(catalog.revision) }, [icon("library"), "Templates"]), iconButton("upload", "Import hunt rules", () => ruleEditor("", catalog.revision, "Import hunt rules"), !editable), iconButton("download", "Export custom hunt rules", async () => { try { const exported = await call("rules.export"); download(exported.filename, exported.content); } catch (error) { toast(error.message); } }, state.session.demo)];
    root.append(element("div", { class: "rule-actions" }, [segmented([["custom", "Custom"], ["bundled", "Built-in"]], ruleScope, (value) => { ruleScope = value; loadView(); }), element("div", { class: "row-actions" }, actions)]));
    const rules = catalog.items.filter((rule) => (rule.origin || "bundled") === ruleScope);
    const rows = rules.map((rule) => {
      const enabled = element("input", { type: "checkbox", class: "log-select", "aria-label": `Enable ${rule.title}`, disabled: !editable || rule.origin !== "custom" });
      enabled.checked = rule.enabled !== false;
      enabled.addEventListener("change", async () => { enabled.disabled = true; try { await call("rules.enabled", { id: rule.id, enabled: enabled.checked, revision: catalog.revision }); await loadView(); } catch (error) { enabled.checked = rule.enabled; enabled.disabled = false; toast(error.message); } });
      const tools = [iconButton("file-code", `View rule ${rule.id}`, () => showResult(rule.title, rule.yaml || JSON.stringify(rule, null, 2)))];
      if (rule.origin === "custom" && editable) tools.push(iconButton("pencil", `Edit rule ${rule.id}`, () => ruleEditor(rule.yaml, catalog.revision, "Edit hunt rule")), iconButton("trash-2", `Delete rule ${rule.id}`, () => confirmAction("Delete hunt rule?", `${rule.title}. Existing hunt history and rule snapshots will be retained.`, async () => { await call("rules.delete", { id: rule.id, revision: catalog.revision }); loadView(); }, "Delete rule", true)));
      return element("tr", {}, [element("td", {}, [enabled]), element("td", {}, [element("strong", { text: rule.title }), element("span", { class: "record-subtitle mono", text: rule.id }), element("span", { class: "record-subtitle", text: rule.provenance || "Bundled rule" })]), element("td", {}, [badge(rule.severity)]), element("td", { text: rule.sources.join(", ") }), element("td", { class: "row-actions" }, tools)]);
    });
    root.append(rows.length ? table(["Enabled", "Rule", "Severity", "Sources", ""], rows, "rule-table") : empty("No custom hunt rules", "No custom definitions have been saved.", "list-filter"));
  }

  async function detection() {
    if (!canOperate()) return empty("Operator access required", "Your account cannot run hunts.", "lock-keyhole");
    const tabs = [["logs", "Device logs"], ["upload", "Upload log"], ["history", "History"], ["compare", "Config comparison"], ["rules", "Rules"]];
    const root = element("div", {}, [heading("Detection", "Appliance log captures and investigation results"), element("div", { class: "admin-tabs", role: "tablist", "aria-label": "Detection views" }, tabs.map(([key, label]) => element("button", { role: "tab", "aria-selected": String(detectionTab === key), class: detectionTab === key ? "selected" : "", onclick: () => { detectionTab = key; loadView(); }, text: label })))]);
    const disabled = state.session.demo;
    if (detectionTab === "logs") await deviceLogs(root);
    else if (detectionTab === "history") await huntHistory(root);
    else if (detectionTab === "upload") {
      const source = field("Log source", "select", "nslog", { choices: ["nslog", "bashlog", "shlog", "httperror", "httpaccess", "httpaccess-vpn", "notice", "auth"].map((value) => [value, value]) });
      const log = field("Log sample", "textarea", "", { rows: 10, maxLength: 1048576 });
      const file = field("Load log file", "file", "", { accept: ".log,.txt" });
      const messages = element("div", { role: "status" });
      const results = element("div");
      file.input.addEventListener("change", async () => {
        try {
          const selected = file.input.files[0];
          if (selected?.size > 1048576) throw new Error("Log upload exceeds 1 MiB");
          if (selected) {
            const bytes = new Uint8Array(await selected.arrayBuffer()); const chunks = [];
            for (let start = 0; start < bytes.length; start += 8192) chunks.push(String.fromCharCode(...bytes.slice(start, start + 8192)));
            log.input.value = chunks.join(""); messages.replaceChildren();
          }
        } catch (error) { messages.replaceChildren(errorBox(error)); }
      });
      const run = primary("Run hunt", "scan-search", async () => {
        run.disabled = true; messages.replaceChildren();
        try { results.replaceChildren(huntResults(await call("tools.hunt", { source: source.value(), text: log.value() }))); }
        catch (error) { messages.replaceChildren(errorBox(error)); }
        finally { run.disabled = disabled; icons(); }
      }, disabled);
      root.append(element("div", { class: "settings-fields" }, [source.wrapper, file.wrapper]), log.wrapper, run, messages, results);
    } else if (detectionTab === "compare") {
      const before = field("Before configuration", "textarea", "", { rows: 10, maxLength: 1048576 });
      const after = field("After configuration", "textarea", "", { rows: 10, maxLength: 1048576 });
      root.append(element("div", { class: "settings-fields" }, [before.wrapper, after.wrapper]), primary("Compare", "file-diff", async () => { try { showResult("Configuration difference", (await call("tools.diff", { before: before.value(), after: after.value() })).diff || "No differences."); } catch (error) { toast(error.message); } }, disabled));
    } else await huntRules(root);
    return root;
  }

  async function operations() {
    if (!canOperate()) return empty("Operator access required", "Your account cannot run platform actions.", "lock-keyhole");
    const tabs = [["monitor", "Monitor"], ["archive", "Archive"], ...(isAdmin() ? [["vault", "Vault"], ["setup", "Host setup"], ["audit", "Audit trail"]] : [])];
    if (!tabs.some(([key]) => key === operationsTab)) operationsTab = "monitor";
    const root = element("div", {}, [heading("Operations", "Platform controls and investigation tools"), element("div", { class: "admin-tabs", role: "tablist", "aria-label": "Operations sections" }, tabs.map(([key, label]) => element("button", { role: "tab", "aria-selected": String(key === operationsTab), class: key === operationsTab ? "selected" : "", onclick: () => { operationsTab = key; loadView(); }, text: label })))]);
    const target = field("Device", "select", state.overview.devices[0]?.name || "", { choices: state.overview.devices.map((device) => [device.name, device.name]) });
    const disabled = state.session.demo;
    if (operationsTab === "monitor") {
      const status = await call("platform.status");
      root.append(section("Monitoring service", [definitions([["Administration", status.administration], ["Monitoring", status.paused ? "Paused" : status.setup_error ? "Setup required" : "Running"], ["Setup status", status.setup_error || "Ready"]]), element("div", { class: "operation-actions" }, [primary(status.paused ? "Resume monitoring" : "Pause monitoring", status.paused ? "play" : "pause", () => confirmAction(status.paused ? "Resume monitoring?" : "Pause monitoring?", status.paused ? "Resume scheduled polling and collection." : "Scheduled polling and ingestion will pause. Queued notifications continue delivery.", async () => { await call(status.paused ? "monitor.resume" : "monitor.pause"); loadView(); }), disabled || !isAdmin()), primary("Initialize database", "database", () => confirmAction("Initialize database schema?", "Create missing application tables in the configured database. Existing records are retained.", async () => { await call("database.initialize"); toast("Database schema ready"); }), disabled || !isAdmin())]) ]));
    } else if (operationsTab === "archive") {
      const days = field("Lookback days", "number", 7, { min: 1, max: 3650 }); const query = field("Search text"); const anchor = field("Expected chain head (optional)");
      root.append(element("div", { class: "settings-fields" }, [target.wrapper, days.wrapper, query.wrapper, anchor.wrapper]), element("div", { class: "operation-actions" }, [primary("Search archive", "search", () => operation("Archive search", "archive.search", { device: target.value(), days: Number(days.value()), query: query.value() }), disabled), primary("Verify integrity", "shield-check", () => operation("Archive verification", "archive.verify", { device: target.value(), days: Number(days.value()), expected_head: anchor.value() || undefined }), disabled)]));
    } else if (operationsTab === "vault") {
      const status = await call("vault.status");
      root.append(definitions([["Credential entries", status.entries], ["Key identifier", status.key_id], ["Previous vault copy", status.backup_available ? "Available" : "Not available"]]), element("div", { class: "operation-actions" }, [primary("Download encrypted backup", "download", backupVault, disabled), primary("Restore encrypted backup", "upload", restoreVault, disabled)]));
      root.append(section("Host key maintenance", [element("pre", { class: "config-code", text: "sudo systemctl stop scalar\nsudo scalar vault rekey /root/new-escrow.json\nsudo systemctl start scalar" })]));
    } else if (operationsTab === "setup") {
      const server = field("Monitor server IP", "text", "", { required: true });
      root.append(element("div", { class: "settings-fields" }, [target.wrapper, server.wrapper]), element("div", { class: "operation-actions" }, [primary("Appliance commands", "file-code", async () => { try { showResult("Appliance setup commands", (await call("setup.snippets", { device: target.value(), server_ip: server.value() })).content); } catch (error) { toast(error.message); } }, disabled), primary("Rsyslog configuration", "file-output", async () => { try { download("60-scalar.conf", (await call("setup.rsyslog")).content); } catch (error) { toast(error.message); } }, disabled), primary("Firewall rules", "shield", async () => { try { download("scalar.nft", (await call("setup.firewall")).content); } catch (error) { toast(error.message); } }, disabled)]));
    } else if (operationsTab === "audit") {
      const records = await call("audit.list");
      const auditRows = records.items.map((record) => element("tr", {}, [
        element("td", { class: "nowrap", text: stamp(record.at) }), element("td", { text: record.actor }),
        element("td", { text: record.action }), element("td", { text: record.target || "--" }),
        element("td", {}, [badge(record.outcome)])
      ]));
      root.append(table(["Time (UTC)", "Actor", "Operation", "Target", "Outcome"], auditRows, "records-table"));
    }
    return root;
  }

  async function inspectPin(device, fetched = null) {
    try {
      const result = fetched || await call("device.pin", { device });
      const certificate = result.certificate;
      const verified = field("Fingerprint verified against the appliance", "checkbox", false, { required: true });
      dialog(`TLS key: ${device}`, [definitions([["Subject", certificate.subject], ["Issuer", certificate.issuer], ["SPKI SHA-256", certificate.spki_sha256], ["Expires", stamp(certificate.not_after)]]), verified.wrapper], "Save verified pin", async () => {
        const settings = await call("settings.get");
        const entry = settings.document.devices.find((item) => item.name === device);
        entry.spki_pin = certificate.spki_sha256;
        entry.spki_pinning = true;
        const result = await call("settings.save", { document: settings.document, revision: settings.revision });
        if (!result.applied) throw new Error(result.errors?.[0]?.error || "TLS pin saved; activation failed. Save again to retry.");
        toast(result.setup_error || "TLS pin saved and active");
      });
    } catch (error) { showResult("TLS inspection failed", error.message); }
  }

  function backupVault() {
    const passphrase = field("Backup passphrase", "password", "", { required: true, minLength: 16, maxLength: 256 });
    const repeat = field("Confirm passphrase", "password", "", { required: true, minLength: 16, maxLength: 256 });
    dialog("Encrypted vault backup", [passphrase.wrapper, repeat.wrapper], "Download backup", async () => {
      if (passphrase.value() !== repeat.value()) throw new Error("Passphrases do not match");
      const result = await call("vault.backup", { passphrase: passphrase.value() });
      download(result.filename, atob(result.content_base64)); passphrase.input.value = ""; repeat.input.value = ""; toast("Encrypted backup downloaded");
    });
  }

  function restoreVault() {
    const backup = field("Encrypted backup file", "file", "", { required: true, accept: ".json" });
    const password = field("Backup passphrase", "password", "", { required: true, minLength: 16, maxLength: 256 });
    const confirmation = field("Type RESTORE to confirm", "text", "", { required: true, pattern: "RESTORE" });
    dialog("Restore credential vault", [notice("Monitoring will pause. Existing credentials will be replaced; the current host encryption key is retained."), backup.wrapper, password.wrapper, confirmation.wrapper], "Restore vault", async () => {
      const file = backup.input.files[0];
      if (!file || file.size > 2 * 1024 * 1024) throw new Error("Backup must be smaller than 2 MB");
      const bytes = new Uint8Array(await file.arrayBuffer()); let encoded = "";
      for (let start = 0; start < bytes.length; start += 8192) encoded += String.fromCharCode(...bytes.slice(start, start + 8192));
      await call("vault.restore", { backup: btoa(encoded), passphrase: password.value(), confirmation: confirmation.value() });
      password.input.value = ""; toast("Vault restored. Monitoring remains paused."); operationsTab = "monitor"; loadView();
    }, { danger: true });
  }

  function openSettings(tab = "devices", device = null) { settingsTab = tab; settingsDevice = device; if (state.view === "settings") loadView(); else navigate("settings"); }
  function focusSettingsDevice() {
    if (state.view !== "settings" || settingsTab !== "devices" || !settingsDevice) return;
    const target = document.getElementById(`device-settings-${settingsDevice}`);
    settingsDevice = null;
    if (target) { target.scrollIntoView({ block: "center" }); target.querySelector("input")?.focus({ preventScroll: true }); }
  }
  function openOperations(tab = "devices") { if (["detection", "devices"].includes(tab)) { navigate(tab); return; } operationsTab = tab; navigate("operations"); }
  function reset() { settingsDraft = null; settingsDevice = null; detectionDevice = ""; selectedHunt = null; historyFilters = { days: "30", device: "", source: "", offset: 0 }; deviceCredentials = { items: [], error: null }; deviceWork.clear(); syncDeviceActions(); state.adminDirty = false; document.querySelectorAll(".admin-dialog").forEach(modal => modal.close()); }
  return { call, settings, users, credentials, detection, operations, account, openSettings, focusSettingsDevice, openOperations, deviceActions, syncDeviceActions, canOperate, isAdmin, reset };
})();
