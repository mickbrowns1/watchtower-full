// Watchtower — vanilla JS frontend. No build step, no framework.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `HTTP ${res.status}`);
  }
  return data;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function badge(text, kind) {
  return `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
}

function statusBadge(status) {
  const kind = status === "running" ? "green" : status === "not found" ? "grey" : "red";
  return badge(status, kind);
}

function healthBadge(health) {
  if (health === "healthy") return badge(health, "green");
  if (health === "unhealthy") return badge(health, "red");
  return badge(health, "grey");
}

// ─── Tabs ────────────────────────────────────────────────────────────────

const TAB_LOADERS = {
  dashboard: loadDashboard,
  diagnostics: loadDiagnostics,
  sources: loadSourcesTab,
  scenarios: loadScenariosTab,
  environments: loadEnvironments,
  logs: () => {},
};

function initTabs() {
  $$(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab").forEach((b) => b.classList.remove("active"));
      $$(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      $(`#panel-${btn.dataset.tab}`).classList.add("active");
      if (btn.dataset.tab !== "sources") stopStream();
      TAB_LOADERS[btn.dataset.tab]?.();
    });
  });
}

// ─── Dashboard ──────────────────────────────────────────────────────────

function nameCell(r) {
  return `${escapeHtml(r.display_name || r.label)} <span class="muted">(${escapeHtml(r.label)})</span>`;
}

async function loadDashboard() {
  try {
    const rows = await api("/api/status");
    $("#status-cards").innerHTML = rows.map((r) => `
      <div class="card">
        <h3>${escapeHtml(r.display_name || r.label)}</h3>
        <div class="muted" style="margin:-0.4rem 0 0.6rem">${escapeHtml(r.tagline || r.label)}</div>
        <div class="row"><span>Status</span><span>${statusBadge(r.status)}</span></div>
        <div class="row"><span>Health</span><span>${healthBadge(r.health)}</span></div>
        <div class="row"><span>Uptime</span><span>${escapeHtml(r.uptime)}</span></div>
        <div class="row" style="margin-top:0.5rem;justify-content:flex-end">
          <button class="btn small ghost" onclick="restartContainer('${r.label}', '${escapeHtml(r.display_name || r.label)}')" ${r.found ? "" : "disabled"}>Restart</button>
        </div>
      </div>
    `).join("");
  } catch (e) {
    $("#status-cards").innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }

  try {
    const rows = await api("/api/resources");
    $("#resources-table").innerHTML = renderTable(
      ["Container", "CPU %", "Mem usage", "Mem limit", "Net I/O"],
      rows.map((r) => r.running
        ? [nameCell(r), `${r.cpu_pct.toFixed(1)}%`, `${r.mem_usage_mib.toFixed(1)} MiB`, `${r.mem_limit_mib} MiB`, `↓${r.rx_kib} KiB / ↑${r.tx_kib} KiB`]
        : [nameCell(r), "-", "-", "-", "-"]),
    );
  } catch (e) {
    $("#resources-table").innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function restartContainer(label, displayName) {
  if (!confirm(`Restart ${displayName || label}?`)) return;
  try {
    await api(`/api/restart/${label}`, { method: "POST" });
    loadDashboard();
  } catch (e) {
    alert(`Restart failed: ${e.message}`);
  }
}

function renderTable(headers, rows) {
  if (!rows.length) return `<div class="muted">No data.</div>`;
  return `<table><thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

// ─── Diagnostics ────────────────────────────────────────────────────────

async function loadDiagnostics() {
  loadEnvSummary();
  loadTls();
  loadDns();
  loadVolume();
}

async function loadEnvSummary() {
  const el = $("#env-summary");
  el.innerHTML = "Loading…";
  try {
    const s = await api("/api/environment/summary");
    const rows = Object.entries(s.values).map(([k, v]) => [
      `<span class="mono">${escapeHtml(k)}</span>`, v ? escapeHtml(v) : `<span class="muted">(not set)</span>`,
    ]);
    let extra = "";
    if (s.matched_profile) extra = `<p class="muted">Matches saved environment: ${badge(s.matched_profile, "green")}</p>`;
    else if (s.has_saved_environments) extra = `<p class="muted">Live .env doesn't match any saved environment. Capture it on the Environments tab.</p>`;
    else extra = `<p class="muted">No saved environments yet — see the Environments tab.</p>`;
    el.innerHTML = renderTable(["Key", "Value"], rows) + extra;
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadTls() {
  const el = $("#tls-results");
  el.innerHTML = "Loading…";
  try {
    const rows = await api("/api/tls");
    if (!rows.length) { el.innerHTML = `<div class="muted">No HEC_URL/SDL_BASE_URL configured to check.</div>`; return; }
    el.innerHTML = rows.map((r) => r.ok ? `
      <div class="card">
        <h3>${escapeHtml(r.label)} — ${escapeHtml(r.host)}</h3>
        <div class="row"><span>Handshake</span><span>${badge("OK " + r.tls_version, "green")}</span></div>
        <div class="row"><span>Subject</span><span>${escapeHtml(r.subject)}</span></div>
        <div class="row"><span>Issuer</span><span>${escapeHtml(r.issuer)}</span></div>
        <div class="row"><span>Expires</span><span>${escapeHtml(r.expires)}</span></div>
      </div>` : `
      <div class="card">
        <h3>${escapeHtml(r.label)} — ${escapeHtml(r.host)}</h3>
        <div class="row"><span>Handshake</span><span>${badge("FAIL", "red")}</span></div>
        <div class="row"><span>Error</span><span>${escapeHtml(r.error)}</span></div>
      </div>`).join("");
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadDns() {
  const el = $("#dns-results");
  el.innerHTML = "Loading…";
  try {
    const rows = await api("/api/dns");
    el.innerHTML = renderTable(["Host", "Result"], rows.map((r) =>
      r.ok ? [r.host, badge("OK", "green") + " " + escapeHtml(r.ips.join(", "))]
           : [r.host, badge("FAIL", "red") + " " + escapeHtml(r.error)]));
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadVolume() {
  const el = $("#volume-results");
  el.innerHTML = "Loading…";
  try {
    const rows = await api("/api/volume");
    el.innerHTML = renderTable(["Path", "Contents", "Host disk"], rows.map((r) =>
      r.mounted ? [r.label, `${r.contents_mib.toFixed(2)} MiB`, `${r.host_used_gib.toFixed(1)}/${r.host_total_gib.toFixed(1)} GiB used`]
                : [r.label, badge("not mounted", "yellow"), "-"]));
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// ─── Sources ────────────────────────────────────────────────────────────

async function loadSourcesTab() {
  loadSources();
  loadConnectivity();
  loadPorts();
}

async function loadSources() {
  const el = $("#sources-results");
  el.innerHTML = "Loading…";
  try {
    const data = await api("/api/sources");
    let html = "";
    if (data["sgcia"]) {
      const d = data["sgcia"];
      html += `<div class="card"><h3>${escapeHtml(d.display_name)} <span class="muted">(sgcia — ${escapeHtml(d.note)})</span></h3>
        <div class="row"><span>HEC_URL</span><span>${escapeHtml(d.HEC_URL || "(not set)")}</span></div>
        <div class="row"><span>HEC_TOKEN</span><span>${escapeHtml(d.HEC_TOKEN || "(not set)")}</span></div>
        <div class="row"><span>HEC_INDEX</span><span>${escapeHtml(d.HEC_INDEX || "(not set)")}</span></div></div>`;
    }
    if (data["log-generator"]) {
      const d = data["log-generator"];
      html += `<div class="card"><h3>${escapeHtml(d.display_name)} <span class="muted">(log-generator — ${escapeHtml(d.note)})</span></h3>
        <div class="row"><span>SDL_BASE_URL</span><span>${escapeHtml(d.SDL_BASE_URL || "(not set)")}</span></div>
        <div class="row"><span>SDL_WRITE_TOKEN</span><span>${escapeHtml(d.SDL_WRITE_TOKEN || "(not set)")}</span></div>
        <div class="row"><span>SCENARIO_CHANCE</span><span>${escapeHtml(d.SCENARIO_CHANCE || "(default)")}</span></div>
        <div class="row"><span>LOG_INTERVAL_MS</span><span>${escapeHtml(d.LOG_INTERVAL_MS || "(default)")}</span></div>
        <div class="row"><span>LOG_BURST</span><span>${escapeHtml(d.LOG_BURST || "(default)")}</span></div></div>`;
    }
    el.innerHTML = `<div class="card-grid">${html}</div>`;
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadConnectivity() {
  const el = $("#connectivity-results");
  el.innerHTML = "Loading…";
  try {
    const rows = await api("/api/connectivity");
    el.innerHTML = renderTable(["Target", "Result"], rows.map((r) =>
      r.ok ? [r.label, badge("OK", "green") + ` ${r.host}:${r.port} (${r.ms} ms)`]
           : [r.label, badge("FAIL", "red") + ` ${r.host}:${r.port} — ${escapeHtml(r.error)}`]));
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadPorts() {
  const el = $("#ports-results");
  el.innerHTML = "Loading…";
  try {
    const rows = await api("/api/ports");
    el.innerHTML = renderTable(["Container", "Published ports"], rows.map((r) =>
      [nameCell(r), r.ports.length ? r.ports.map(escapeHtml).join("<br/>") : "(none)"]));
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function runSyslogTest() {
  const el = $("#syslog-test-result");
  el.textContent = "Sending…";
  try {
    const r = await api("/api/syslog/test", { method: "POST" });
    el.innerHTML = r.confirmed
      ? `${badge("Confirmed", "green")} events_in ${r.before} → ${r.after}`
      : `${badge("No change", "yellow")} (${r.before} → ${r.after}) — check sgcia logs.`;
  } catch (e) {
    el.innerHTML = `<span class="muted">Error: ${escapeHtml(e.message)}</span>`;
  }
}

let streamTimer = null;
function toggleStream(on) {
  if (on) {
    pollStream();
    streamTimer = setInterval(pollStream, 2000);
  } else {
    stopStream();
  }
}
function stopStream() {
  if (streamTimer) { clearInterval(streamTimer); streamTimer = null; }
  $("#stream-toggle").checked = false;
}
async function pollStream() {
  try {
    const stats = await api("/api/syslog/stats");
    const keys = ["events_in", "events_out", "events_dropped", "parse_errors", "batches_sent", "batches_failed", "retries"];
    $("#stream-results").innerHTML = renderTable(["Metric", "Value"], keys.map((k) => [k, escapeHtml(stats[k] ?? "-")]));
  } catch (e) {
    $("#stream-results").innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// ─── Scenarios ──────────────────────────────────────────────────────────

async function loadScenariosTab() {
  try {
    const scenarios = await api("/api/scenarios");
    $("#scenario-select").innerHTML = scenarios.map((s) =>
      `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} — ${escapeHtml(s.title)}</option>`).join("");
  } catch (e) {
    $("#scenario-select").innerHTML = `<option value="">Error: ${escapeHtml(e.message)}</option>`;
  }
  try {
    const categories = await api("/api/categories");
    $("#category-select").innerHTML = Object.entries(categories).map(([letter, label]) =>
      `<option value="${letter}">${letter} — ${escapeHtml(label)}</option>`).join("");
  } catch (e) {
    $("#category-select").innerHTML = `<option value="">Error: ${escapeHtml(e.message)}</option>`;
  }
}

function setScenarioOutput(text) {
  $("#scenario-output").textContent = text;
}

async function fireScenario(all) {
  const name = all ? "all" : $("#scenario-select").value;
  if (!name) { alert("Pick a scenario first."); return; }
  const label = all ? "ALL 24 scenarios" : name;
  if (!confirm(`Fire ${label}? This sends real synthetic events into the pipeline.`)) return;
  setScenarioOutput(`Firing ${name}…`);
  try {
    const r = await api("/api/fire/scenario", { method: "POST", body: JSON.stringify({ name }) });
    setScenarioOutput(r.output);
  } catch (e) {
    setScenarioOutput(`Error: ${e.message}`);
  }
}

async function fireCategory() {
  const category = $("#category-select").value;
  if (!category) { alert("Pick a category first."); return; }
  if (!confirm(`Fire every scenario mapped to category ${category}?`)) return;
  setScenarioOutput(`Firing category ${category}…`);
  try {
    const r = await api("/api/fire/category", { method: "POST", body: JSON.stringify({ category }) });
    setScenarioOutput(r.output);
  } catch (e) {
    setScenarioOutput(`Error: ${e.message}`);
  }
}

async function fireSources() {
  if (!confirm("Send one test event to all 15 sources (14 via sgcia + direct-to-SDL EDR)?")) return;
  setScenarioOutput("Sending one test event per source…");
  try {
    const r = await api("/api/fire/sources", { method: "POST" });
    setScenarioOutput(r.output);
  } catch (e) {
    setScenarioOutput(`Error: ${e.message}`);
  }
}

// ─── Environments ───────────────────────────────────────────────────────

let knownEnvironments = [];
let editingEnvironmentName = null;

async function loadEnvironments() {
  const el = $("#environments-table");
  el.innerHTML = "Loading…";
  try {
    const envs = await api("/api/environments");
    knownEnvironments = envs;
    if (!envs.length) {
      el.innerHTML = `<div class="muted">No saved environments yet. Capture the current .env or add one below.</div>`;
      return;
    }
    el.innerHTML = renderTable(
      ["Name", "SDL_BASE_URL", "HEC_INDEX", "Live?", "Actions"],
      envs.map((e) => [
        escapeHtml(e.name),
        escapeHtml(e.values.SDL_BASE_URL || "(not set)"),
        escapeHtml(e.values.HEC_INDEX || "(not set)"),
        e.matches_live ? badge("active", "green") : "",
        `<div class="actions-cell">
           <button class="btn small ghost" onclick="startEditEnvironment('${escapeHtml(e.name)}')">Reconfigure</button>
           <button class="btn small" onclick="applyEnvironment('${escapeHtml(e.name)}')">Activate</button>
           <button class="btn small danger" onclick="deleteEnvironment('${escapeHtml(e.name)}')">Decommission</button>
         </div>`,
      ]),
    );
  } catch (e) {
    el.innerHTML = `<div class="muted">Error: ${escapeHtml(e.message)}</div>`;
  }
}

async function captureEnvironment() {
  const name = $("#capture-name").value.trim();
  try {
    const r = await api("/api/environments/capture", { method: "POST", body: JSON.stringify({ name }) });
    $("#capture-name").value = "";
    loadEnvironments();
    alert(`Snapshotted live .env as '${r.name}'.`);
  } catch (e) {
    alert(`Snapshot failed: ${e.message}`);
  }
}

function startEditEnvironment(name) {
  const env = knownEnvironments.find((e) => e.name === name);
  if (!env) return;
  editingEnvironmentName = name;
  const form = $("#add-env-form");
  form.reset();
  form.elements["name"].value = env.name;
  form.elements["name"].disabled = true;
  // Only prefill non-secret fields -- secret inputs stay blank (their
  // current value is redacted server-side, so we can't and shouldn't
  // round-trip it back through the DOM). Leaving them blank keeps the
  // existing stored value on save.
  form.elements["HEC_URL"].value = env.values.HEC_URL || "";
  form.elements["HEC_INDEX"].value = env.values.HEC_INDEX || "";
  form.elements["SDL_BASE_URL"].value = env.values.SDL_BASE_URL || "";
  form.elements["SDL_ACCOUNT_ID"].value = env.values.SDL_ACCOUNT_ID || "";
  $("#add-env-heading").textContent = `Reconfiguring: ${name}`;
  $("#env-form-submit").textContent = "Save changes";
  $("#cancel-edit-btn").style.display = "";
  $("#edit-mode-banner").style.display = "";
  $("#edit-mode-name").textContent = name;
  $("#env-form-result").textContent = "";
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}

function cancelEditEnvironment() {
  editingEnvironmentName = null;
  const form = $("#add-env-form");
  form.reset();
  form.elements["name"].disabled = false;
  $("#add-env-heading").innerHTML = 'Register outpost <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(add environment)</span>';
  $("#env-form-submit").textContent = "Register outpost";
  $("#cancel-edit-btn").style.display = "none";
  $("#edit-mode-banner").style.display = "none";
}

async function addEnvironment(evt) {
  evt.preventDefault();
  const form = $("#add-env-form");
  const data = Object.fromEntries(new FormData(form).entries());
  const result = $("#env-form-result");
  try {
    if (editingEnvironmentName) {
      const { name, ...fields } = data;
      await api(`/api/environments/${encodeURIComponent(editingEnvironmentName)}`, { method: "PUT", body: JSON.stringify(fields) });
      result.textContent = `Reconfigured '${editingEnvironmentName}'.`;
      cancelEditEnvironment();
    } else {
      await api("/api/environments", { method: "POST", body: JSON.stringify(data) });
      result.textContent = `Registered '${data.name}'.`;
      form.reset();
    }
    loadEnvironments();
  } catch (e) {
    result.textContent = `Error: ${e.message}`;
  }
  return false;
}

async function applyEnvironment(name) {
  if (!confirm(`Activate outpost '${name}'? This rewrites .env and recreates verifier, sgcia, and log-generator — ambient traffic will briefly pause.`)) return;
  const el = $("#environments-table");
  try {
    el.insertAdjacentHTML("afterbegin", `<div class="muted" id="apply-status">Activating '${name}' — rewriting .env and recreating containers (can take up to a minute)…</div>`);
    const r = await api(`/api/environments/${encodeURIComponent(name)}/apply`, { method: "POST" });
    $("#apply-status")?.remove();
    alert(r.ok ? `Activated '${name}'. Stack recreated.` : `docker compose exited ${r.returncode}:\n${r.stderr}`);
    loadEnvironments();
    loadDashboard();
  } catch (e) {
    $("#apply-status")?.remove();
    alert(`Activate failed: ${e.message}`);
  }
}

async function deleteEnvironment(name) {
  if (!confirm(`Decommission saved outpost '${name}'? (This does not touch .env.)`)) return;
  try {
    await api(`/api/environments/${encodeURIComponent(name)}`, { method: "DELETE" });
    loadEnvironments();
  } catch (e) {
    alert(`Decommission failed: ${e.message}`);
  }
}

// ─── Logs ───────────────────────────────────────────────────────────────

async function fetchLogs() {
  const label = $("#logs-container").value;
  const lines = $("#logs-lines").value || 50;
  const el = $("#logs-output");
  const wasAtBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  if (!logsFollowTimer) el.textContent = "Loading…";
  try {
    const r = await api(`/api/logs/${label}?lines=${lines}`);
    el.textContent = r.text || "(empty)";
    if (!logsFollowTimer || wasAtBottom) el.scrollTop = el.scrollHeight;
  } catch (e) {
    el.textContent = `Error: ${e.message}`;
  }
}

let logsFollowTimer = null;
function toggleLogsFollow(on) {
  if (on) {
    fetchLogs();
    logsFollowTimer = setInterval(fetchLogs, 2000);
  } else if (logsFollowTimer) {
    clearInterval(logsFollowTimer);
    logsFollowTimer = null;
  }
}

// ─── Init ───────────────────────────────────────────────────────────────

initTabs();
loadDashboard();
setInterval(() => {
  if ($("#panel-dashboard").classList.contains("active")) loadDashboard();
}, 8000);
