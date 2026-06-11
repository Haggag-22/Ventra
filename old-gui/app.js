/* Ventra Evidence Viewer - single page application (no dependencies). */

"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const state = {
  summary: null,
  packageLabel: null,
  platform: "aws",
  ctFilters: {
    search: "", eventNames: [], sources: [], regions: [],
    user: "", ip: "", errorsOnly: false,
    sort: "time", order: "desc", offset: 0,
  },
  ctFacets: null,
  findingFilters: { search: "", source: "", severity: "", offset: 0 },
  files: null,
  activeFile: null,
};

const PLATFORMS = {
  aws: { short: "AWS", name: "Amazon Web Services", cls: "aws" },
  azure: { short: "AZ", name: "Microsoft Azure", cls: "azure" },
  gcp: { short: "GCP", name: "Google Cloud", cls: "gcp" },
};

const PAGE = 100;

/* ------------------------------------------------------------- helpers */

async function api(path, params = {}) {
  const url = new URL(path, location.origin);
  Object.entries(params).forEach(([k, v]) => { if (v !== "" && v != null) url.searchParams.set(k, v); });
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

function fmtTime(value) {
  if (!value) return "—";
  const text = String(value).replace("T", " ").replace(/\+00:00$/, "Z");
  return text.length > 19 ? text.slice(0, 19) + "Z" : text;
}

function fmtBytes(bytes) {
  if (bytes == null) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0; let n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n.toFixed(n >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function highlightJson(obj) {
  const text = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  return esc(text)
    .replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?/g, (match, str, colon) =>
      colon ? `<span class="j-key">${str}</span>${colon}` : `<span class="j-str">${str}</span>`)
    .replace(/\b(true|false)\b/g, '<span class="j-bool">$1</span>')
    .replace(/\bnull\b/g, '<span class="j-null">null</span>')
    .replace(/(:\s*)(-?\d+(?:\.\d+)?)/g, '$1<span class="j-num">$2</span>');
}

function statusChip(status) {
  const map = {
    collected: ["ok", "Collected"],
    no_data_in_range: ["neutral", "No data in range"],
    not_enabled: ["warn", "Not enabled"],
    service_not_used: ["neutral", "Service not used"],
    permission_denied: ["danger", "Permission denied"],
    failed: ["danger", "Failed"],
    skipped: ["neutral", "Skipped"],
  };
  const [cls, label] = map[status] || ["neutral", status];
  return `<span class="chip ${cls}"><span class="dot"></span>${esc(label)}</span>`;
}

function sevChip(label) {
  const safe = esc(label || "UNKNOWN");
  return `<span class="chip sev-${safe}">${safe}</span>`;
}

function shortService(source) {
  return (source || "").replace(".amazonaws.com", "").replace(/^aws\./, "") || "—";
}

function filterBtnLabel(label, selected) {
  return selected.length ? `${label} (${selected.length})` : label;
}

function renderFacetMenu(menuId, items, selected) {
  const selectedSet = new Set(selected);
  if (!items.length) {
    return `<div class="filter-menu empty" hidden>No values in index</div>`;
  }
  return `
    <div class="filter-menu" id="${menuId}" hidden>
      <input type="text" class="filter-menu-search" placeholder="Filter list…"
             data-menu-search="${menuId}">
      <div class="filter-menu-list">
        ${items.map((item) => `
          <label class="filter-option" data-search="${esc(item.value.toLowerCase())}">
            <input type="checkbox" value="${esc(item.value)}"
              ${selectedSet.has(item.value) ? "checked" : ""}>
            <span class="filter-option-text">${esc(item.value)}</span>
            <span class="filter-option-count">${item.count.toLocaleString()}</span>
          </label>`).join("")}
      </div>
      <div class="filter-menu-actions">
        <button class="btn" type="button" data-menu-clear="${menuId}">Clear</button>
        <button class="btn primary" type="button" data-menu-apply="${menuId}">Apply</button>
      </div>
    </div>`;
}

function closeAllFilterMenus() {
  $$(".filter-menu").forEach((menu) => { menu.hidden = true; });
  $$(".filter-btn.open").forEach((btn) => btn.classList.remove("open"));
}

function bindFacetMenu(container, menuId, key, onChange) {
  const btn = $(`[data-filter-btn="${menuId}"]`, container);
  const menu = $(`#${menuId}`, container);
  btn?.addEventListener("click", (event) => {
    event.stopPropagation();
    const opening = menu.hidden;
    closeAllFilterMenus();
    if (opening) {
      menu.hidden = false;
      btn.classList.add("open");
      $(`[data-menu-search="${menuId}"]`, container)?.focus();
    }
  });
  $(`[data-menu-search="${menuId}"]`, container)?.addEventListener("input", (event) => {
    const query = event.target.value.trim().toLowerCase();
    $$(`.filter-option`, menu).forEach((row) => {
      row.hidden = query && !row.dataset.search.includes(query);
    });
  });
  $(`[data-menu-clear="${menuId}"]`, container)?.addEventListener("click", () => {
    $$('input[type="checkbox"]', menu).forEach((box) => { box.checked = false; });
  });
  $(`[data-menu-apply="${menuId}"]`, container)?.addEventListener("click", () => {
    const values = $$('input[type="checkbox"]:checked', menu).map((box) => box.value);
    onChange(values);
    closeAllFilterMenus();
  });
}

function ctQueryParams(filters) {
  return {
    search: filters.search,
    events: filters.eventNames.join(","),
    sources: filters.sources.join(","),
    regions: filters.regions.join(","),
    user: filters.user,
    ip: filters.ip,
    errors: filters.errorsOnly ? "1" : "",
    sort: filters.sort,
    order: filters.order,
    limit: PAGE,
    offset: filters.offset,
  };
}

/* -------------------------------------------------------------- drawer */

function openDrawer(title, bodyHtml) {
  $("#drawerTitle").textContent = title;
  $("#drawerBody").innerHTML = bodyHtml;
  $("#drawer").classList.add("open");
  $("#drawerBackdrop").classList.add("open");
}

function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawerBackdrop").classList.remove("open");
}

/* -------------------------------------------------------------- topbar */

function renderTopbar() {
  const scope = state.summary?.scope || {};
  const label = state.packageLabel ? esc(state.packageLabel) : "Evidence package";
  $("#topbarMeta").innerHTML = `
    <span class="meta-chip accent">${label}</span>
    <span class="meta-chip mono">Account <b>${esc(scope.account_id || "?")}</b></span>
    <span class="meta-chip">Window <b>${fmtTime(scope.time_window_start_utc)}</b> → <b>${fmtTime(scope.time_window_end_utc)}</b></span>
    <span class="meta-chip">Profile <b>${esc(scope.profile || "?")}</b></span>
    <span class="meta-chip">Regions <b>${(scope.regions || []).length}</b></span>`;
  $("#topbarActions").innerHTML = `
    <button class="btn" type="button" id="btnOpenPackage">Open Package</button>`;
  $("#btnOpenPackage").onclick = () => showUploadMenu();
}

/* ------------------------------------------------------------ overview */

async function viewOverview(el) {
  const s = state.summary;
  const byStatus = s.stats.by_status || {};
  const issues = s.issues || [];
  const ctData = s.cloudtrail_data || {};
  const ctWarnings = ctData.warnings || [];

  const issuesHtml = issues.length ? `
    <div class="callout">
      <b>${issues.length} collection issue(s)</b> — these sources were checked but could not be collected:
      <ul>${issues.slice(0, 12).map((i) =>
        `<li><span class="mono">${esc(i.collector)}</span> [${esc(i.region)}] — ${esc(i.status)}${i.detail ? ": " + esc(i.detail.slice(0, 140)) : ""}</li>`).join("")}
      ${issues.length > 12 ? `<li>… and ${issues.length - 12} more (see Collection Coverage)</li>` : ""}</ul>
    </div>` : "";

  const cloudTrailDataHtml = ctWarnings.length ? `
    <div class="callout">
      <b>CloudTrail S3 data events</b>
      <ul>${ctWarnings.map((warning) => `<li>${esc(warning)}</li>`).join("")}</ul>
      ${ctData.s3_data_events_collected ? `<div class="dim">${ctData.s3_data_events_collected.toLocaleString()} S3 data events indexed for timeline search.</div>` : ""}
    </div>` : (ctData.s3_data_events_collected ? `
    <div class="callout" style="border-color: var(--ok)">
      <b>CloudTrail S3 data events</b> — ${ctData.s3_data_events_collected.toLocaleString()} object-level events indexed for timeline search.
    </div>` : "");

  el.innerHTML = `
    <div class="page-title">Case Overview</div>
    <div class="page-sub">Evidence package summary and collection health</div>
    ${issuesHtml}
    ${cloudTrailDataHtml}
    <div class="grid cols-4">
      <div class="card"><div class="stat-label">CloudTrail Events</div>
        <div class="stat-value">${s.stats.events_indexed.toLocaleString()}</div>
        <div class="stat-foot">indexed for timeline search</div></div>
      <div class="card"><div class="stat-label">Security Findings</div>
        <div class="stat-value">${s.stats.findings.toLocaleString()}</div>
        <div class="stat-foot">GuardDuty · Security Hub · Inspector · Macie</div></div>
      <div class="card"><div class="stat-label">Artifacts Collected</div>
        <div class="stat-value">${s.stats.files.toLocaleString()}</div>
        <div class="stat-foot">files, each SHA-256 hashed</div></div>
      <div class="card"><div class="stat-label">Collectors Run</div>
        <div class="stat-value">${s.stats.collectors}</div>
        <div class="stat-foot">${byStatus.collected || 0} collected · ${(byStatus.permission_denied || 0) + (byStatus.failed || 0)} issues</div></div>
    </div>
    <div style="height:14px"></div>
    <div class="grid cols-2">
      <div class="card">
        <div class="card-title">Package</div>
        <dl class="kv">
          <dt>Account</dt><dd>${esc(s.scope.account_id)}</dd>
          <dt>Profile</dt><dd>${esc(s.scope.profile)}</dd>
          <dt>Window start</dt><dd>${fmtTime(s.scope.time_window_start_utc)}</dd>
          <dt>Window end</dt><dd>${fmtTime(s.scope.time_window_end_utc)}</dd>
          <dt>Regions</dt><dd>${esc((s.scope.regions || []).join(", ")) || "—"}</dd>
        </dl>
      </div>
      <div class="card">
        <div class="card-title">Collection Run</div>
        <dl class="kv">
          <dt>Tool</dt><dd>${esc(s.tool.name)} v${esc(s.tool.version)}</dd>
          <dt>Operator</dt><dd>${esc(s.tool.operator)} @ ${esc(s.tool.hostname)}</dd>
          <dt>Platform</dt><dd>${esc(s.tool.platform)}</dd>
          <dt>Started</dt><dd>${fmtTime(s.run.started_utc)}</dd>
          <dt>Finished</dt><dd>${fmtTime(s.run.finished_utc)}</dd>
        </dl>
      </div>
    </div>`;
}

/* ------------------------------------------------------------ coverage */

async function viewCoverage(el) {
  const collectors = await api("/api/coverage");
  const groups = {};
  collectors.forEach((c) => { (groups[c.category] ||= []).push(c); });

  const sections = Object.entries(groups).map(([category, items]) => `
    <div class="card" style="margin-bottom:14px">
      <div class="card-title">${esc(category.replace(/_/g, " ").toUpperCase())}</div>
      <div class="table-wrap" style="max-height:none;border:none">
        <table><thead><tr>
          <th>Collector</th><th>Region</th><th>Status</th><th>Artifacts</th><th>Detail</th>
        </tr></thead><tbody>
        ${items.flatMap((c) => c.results.map((r) => `
          <tr class="static-row">
            <td class="mono">${esc(c.name)}</td>
            <td class="mono dim">${esc(r.region)}</td>
            <td>${statusChip(r.status)}</td>
            <td class="mono">${(r.artifact_count || 0).toLocaleString()}</td>
            <td class="dim" title="${esc(r.detail)}">${esc((r.detail || "").slice(0, 90))}</td>
          </tr>`)).join("")}
        </tbody></table>
      </div>
    </div>`).join("");

  el.innerHTML = `
    <div class="page-title">Collection Coverage</div>
    <div class="page-sub">Defensible record of every source checked — collected, unavailable, or denied</div>
    ${sections}`;
}

/* ---------------------------------------------------------- cloudtrail */

async function viewCloudTrail(el) {
  if (!state.ctFacets) {
    state.ctFacets = await api("/api/cloudtrail/facets");
  }
  const facets = state.ctFacets;
  const f = state.ctFilters;

  el.innerHTML = `
    <div class="page-title">CloudTrail Timeline</div>
    <div class="page-sub">Deduplicated management, identity, KMS, Secrets, and SSM events across all regions</div>
    <div class="filter-bar">
      <div class="filter-stats" id="ctStats">
        <span class="stat-badge"><span class="stat-dot ok"></span>Total: ${facets.total.toLocaleString()}</span>
        <span class="stat-badge"><span class="stat-dot accent"></span>Matched: …</span>
      </div>
      <div class="filter-controls">
        <div class="search-box">
          <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
          <input type="text" id="ctSearch" placeholder="Search events…" value="${esc(f.search)}">
        </div>
        <div class="filter-dropdown">
          <button class="filter-btn ${f.eventNames.length ? "active" : ""}" type="button"
                  data-filter-btn="ctMenuEvents">
            <svg viewBox="0 0 24 24"><path d="M4 5h16M7 12h10M10 19h4"/></svg>
            ${esc(filterBtnLabel("Event Names", f.eventNames))}
          </button>
          ${renderFacetMenu("ctMenuEvents", facets.event_names, f.eventNames)}
        </div>
        <div class="filter-dropdown">
          <button class="filter-btn ${f.sources.length ? "active" : ""}" type="button"
                  data-filter-btn="ctMenuSources">
            <svg viewBox="0 0 24 24"><path d="M4 5h16M7 12h10M10 19h4"/></svg>
            ${esc(filterBtnLabel("Sources", f.sources))}
          </button>
          ${renderFacetMenu("ctMenuSources", facets.sources, f.sources)}
        </div>
        <div class="filter-dropdown">
          <button class="filter-btn ${f.regions.length ? "active" : ""}" type="button"
                  data-filter-btn="ctMenuRegions">
            <svg viewBox="0 0 24 24"><path d="M4 5h16M7 12h10M10 19h4"/></svg>
            ${esc(filterBtnLabel("Regions", f.regions))}
          </button>
          ${renderFacetMenu("ctMenuRegions", facets.regions, f.regions)}
        </div>
        <select id="ctSort" title="Sort by">
          <option value="time" ${f.sort === "time" ? "selected" : ""}>Time</option>
        </select>
        <select id="ctOrder" title="Sort order">
          <option value="desc" ${f.order === "desc" ? "selected" : ""}>Descending</option>
          <option value="asc" ${f.order === "asc" ? "selected" : ""}>Ascending</option>
        </select>
        <button class="btn" id="ctReset" type="button">Reset</button>
      </div>
      <div class="filter-advanced">
        <input type="text" id="ctUser" placeholder="User / ARN" value="${esc(f.user)}">
        <input type="text" id="ctIp" placeholder="Source IP" value="${esc(f.ip)}">
        <label class="filter-check">
          <input type="checkbox" id="ctErrors" ${f.errorsOnly ? "checked" : ""}>
          Failed calls only
        </label>
        <button class="btn primary" id="ctApply" type="button">Apply</button>
      </div>
    </div>
    <div id="ctTable"><div class="loading"><div class="spinner"></div>Querying events…</div></div>`;

  if (!state._ctMenuCloseBound) {
    state._ctMenuCloseBound = true;
    document.addEventListener("click", closeAllFilterMenus);
  }

  bindFacetMenu(el, "ctMenuEvents", "eventNames", (values) => {
    f.eventNames = values;
    f.offset = 0;
    viewCloudTrail(el);
  });
  bindFacetMenu(el, "ctMenuSources", "sources", (values) => {
    f.sources = values;
    f.offset = 0;
    viewCloudTrail(el);
  });
  bindFacetMenu(el, "ctMenuRegions", "regions", (values) => {
    f.regions = values;
    f.offset = 0;
    viewCloudTrail(el);
  });

  const applyFilters = () => {
    f.search = $("#ctSearch").value.trim();
    f.user = $("#ctUser").value.trim();
    f.ip = $("#ctIp").value.trim();
    f.errorsOnly = $("#ctErrors").checked;
    f.sort = $("#ctSort").value;
    f.order = $("#ctOrder").value;
    f.offset = 0;
    loadCtTable();
  };

  $("#ctApply").onclick = applyFilters;
  $("#ctSort").onchange = applyFilters;
  $("#ctOrder").onchange = applyFilters;
  $("#ctReset").onclick = () => {
    state.ctFilters = {
      search: "", eventNames: [], sources: [], regions: [],
      user: "", ip: "", errorsOnly: false,
      sort: "time", order: "desc", offset: 0,
    };
    viewCloudTrail(el);
  };
  $("#ctSearch").addEventListener("keydown", (event) => {
    if (event.key === "Enter") applyFilters();
  });
  $$(".filter-menu", el).forEach((menu) => {
    menu.addEventListener("click", (event) => event.stopPropagation());
  });

  await loadCtTable();

  async function loadCtTable() {
    const wrap = $("#ctTable");
    wrap.innerHTML = `<div class="loading"><div class="spinner"></div>Querying events…</div>`;
    const data = await api("/api/cloudtrail", ctQueryParams(f));
    $("#ctStats").innerHTML = `
      <span class="stat-badge"><span class="stat-dot ok"></span>Total: ${facets.total.toLocaleString()}</span>
      <span class="stat-badge"><span class="stat-dot accent"></span>Matched: ${data.total.toLocaleString()}</span>`;
    if (!data.events.length) {
      wrap.innerHTML = `<div class="table-wrap"><div class="empty">No events match the current filters.</div></div>`;
      return;
    }
    wrap.innerHTML = `
      <div class="table-wrap">
        <table><thead><tr>
          <th>Time (UTC)</th><th>Event</th><th>User</th><th>Source IP</th><th>Region</th><th>Service</th><th>Error</th>
        </tr></thead><tbody>
          ${data.events.map((ev) => `
            <tr data-idx="${ev.idx}">
              <td class="mono dim">${fmtTime(ev.time)}</td>
              <td><b>${esc(ev.name)}</b></td>
              <td class="mono" title="${esc(ev.user)}">${esc(ev.user) || "—"}</td>
              <td class="mono">${esc(ev.ip) || "—"}</td>
              <td class="mono dim">${esc(ev.region)}</td>
              <td class="dim">${esc(shortService(ev.source))}</td>
              <td>${ev.error ? `<span class="chip danger">${esc(ev.error)}</span>` : ""}</td>
            </tr>`).join("")}
        </tbody></table>
      </div>
      <div class="pager">
        <button class="btn" id="ctPrev" ${f.offset === 0 ? "disabled" : ""}>← Prev</button>
        <span>${(f.offset + 1).toLocaleString()}–${Math.min(f.offset + PAGE, data.total).toLocaleString()} of ${data.total.toLocaleString()}</span>
        <button class="btn" id="ctNext" ${f.offset + PAGE >= data.total ? "disabled" : ""}>Next →</button>
      </div>`;
    $("#ctPrev")?.addEventListener("click", () => { f.offset = Math.max(0, f.offset - PAGE); loadCtTable(); });
    $("#ctNext")?.addEventListener("click", () => { f.offset += PAGE; loadCtTable(); });
    $$("#ctTable tbody tr").forEach((row) => {
      row.onclick = async () => {
        const raw = await api(`/api/cloudtrail/${row.dataset.idx}`);
        openDrawer(raw.EventName || "CloudTrail Event",
          `<pre class="json">${highlightJson(raw)}</pre>`);
      };
    });
  }
}

/* ------------------------------------------------------------ findings */

async function viewFindings(el) {
  el.innerHTML = `
    <div class="page-title">Security Findings</div>
    <div class="page-sub">GuardDuty, Security Hub, Inspector, and Macie findings sorted by severity</div>
    <div class="toolbar">
      <div class="search-box">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input type="text" id="fSearch" placeholder="Search title, type, resource…" value="${esc(state.findingFilters.search)}">
      </div>
      <select id="fSource">
        <option value="">All sources</option>
        ${["GuardDuty", "SecurityHub", "Inspector", "Macie"].map((s) =>
          `<option ${state.findingFilters.source === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <select id="fSeverity">
        <option value="">All severities</option>
        ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((s) =>
          `<option ${state.findingFilters.severity === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <button class="btn primary" id="fApply">Apply</button>
    </div>
    <div id="fTable"><div class="loading"><div class="spinner"></div>Loading findings…</div></div>`;

  $("#fApply").onclick = () => {
    state.findingFilters.search = $("#fSearch").value.trim();
    state.findingFilters.source = $("#fSource").value;
    state.findingFilters.severity = $("#fSeverity").value;
    loadTable();
  };
  $("#fSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#fApply").click(); });
  await loadTable();

  async function loadTable() {
    const wrap = $("#fTable");
    const f = state.findingFilters;
    const data = await api("/api/findings", { search: f.search, source: f.source, severity: f.severity, limit: 500 });
    if (!data.findings.length) {
      wrap.innerHTML = `<div class="table-wrap"><div class="empty">No findings match the current filters.</div></div>`;
      return;
    }
    wrap.innerHTML = `
      <div class="table-wrap">
        <table><thead><tr>
          <th>Severity</th><th>Source</th><th>Title</th><th>Type</th><th>Resource</th><th>Region</th><th>Updated</th>
        </tr></thead><tbody>
          ${data.findings.map((fd) => `
            <tr data-idx="${fd.idx}">
              <td>${sevChip(fd.severity_label)}</td>
              <td><span class="chip accent">${esc(fd.source)}</span></td>
              <td title="${esc(fd.title)}"><b>${esc(fd.title)}</b></td>
              <td class="mono dim" title="${esc(fd.type)}">${esc(fd.type)}</td>
              <td class="dim">${esc(fd.resource) || "—"}</td>
              <td class="mono dim">${esc(fd.region)}</td>
              <td class="mono dim">${fmtTime(fd.time)}</td>
            </tr>`).join("")}
        </tbody></table>
      </div>
      <div class="pager"><span>${data.findings.length.toLocaleString()} of ${data.total.toLocaleString()} findings shown</span></div>`;
    $$("#fTable tbody tr").forEach((row) => {
      row.onclick = async () => {
        const raw = await api(`/api/findings/${row.dataset.idx}`);
        openDrawer(raw.Title || raw.title || "Finding",
          `<pre class="json">${highlightJson(raw)}</pre>`);
      };
    });
  }
}

/* ------------------------------------------------------------ identity */

async function viewIdentity(el) {
  el.innerHTML = `<div class="loading"><div class="spinner"></div>Loading identity data…</div>`;
  const iam = await api("/api/iam");
  const counts = iam.counts || {};
  const users = iam.users || [];
  const keys = iam.access_keys || [];

  const riskyUsers = users.filter((u) =>
    u.password_enabled === "true" && u.mfa_active !== "true").length;

  el.innerHTML = `
    <div class="page-title">Identity &amp; Access</div>
    <div class="page-sub">IAM snapshot and credential report at collection time</div>
    <div class="grid cols-4">
      <div class="card"><div class="stat-label">IAM Users</div><div class="stat-value">${counts.users ?? users.length}</div></div>
      <div class="card"><div class="stat-label">IAM Roles</div><div class="stat-value">${counts.roles ?? "—"}</div></div>
      <div class="card"><div class="stat-label">Access Keys</div><div class="stat-value">${keys.length}</div></div>
      <div class="card"><div class="stat-label">Console Users w/o MFA</div>
        <div class="stat-value" style="color:${riskyUsers ? "var(--danger)" : "var(--ok)"}">${riskyUsers}</div></div>
    </div>
    <div style="height:14px"></div>
    <div class="card" style="margin-bottom:14px">
      <div class="card-title">Credential Report
        <span class="chip neutral">${esc(fmtTime(iam.credential_report_generated))}</span></div>
      <div class="table-wrap" style="max-height:420px;border:none">
        <table><thead><tr>
          <th>User</th><th>Password</th><th>MFA</th><th>Password Last Used</th><th>Key 1 Last Used</th><th>Key 2 Last Used</th>
        </tr></thead><tbody>
        ${users.map((u) => {
          const noMfa = u.password_enabled === "true" && u.mfa_active !== "true";
          return `<tr class="static-row">
            <td class="mono"><b>${esc(u.user)}</b></td>
            <td>${u.password_enabled === "true" ? '<span class="chip warn">Enabled</span>' : '<span class="chip neutral">No</span>'}</td>
            <td>${u.mfa_active === "true" ? '<span class="chip ok">MFA</span>' : (noMfa ? '<span class="chip danger">NO MFA</span>' : '<span class="chip neutral">—</span>')}</td>
            <td class="mono dim">${esc(u.password_last_used || "—")}</td>
            <td class="mono dim">${esc(u.access_key_1_last_used_date || "—")}</td>
            <td class="mono dim">${esc(u.access_key_2_last_used_date || "—")}</td>
          </tr>`;
        }).join("") || `<tr><td colspan="6"><div class="empty">No credential report in package</div></td></tr>`}
        </tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Access Keys</div>
      <div class="table-wrap" style="max-height:380px;border:none">
        <table><thead><tr>
          <th>Key ID</th><th>User</th><th>Status</th><th>Created</th><th>Last Used</th><th>Service</th><th>Region</th>
        </tr></thead><tbody>
        ${keys.map((k) => {
          const lastUsed = k.LastUsed || {};
          return `<tr class="static-row">
            <td class="mono">${esc(k.AccessKeyId || "—")}</td>
            <td class="mono"><b>${esc(k.UserName || "—")}</b></td>
            <td>${k.Status === "Active" ? '<span class="chip ok">Active</span>' : '<span class="chip neutral">Inactive</span>'}</td>
            <td class="mono dim">${fmtTime(k.CreateDate)}</td>
            <td class="mono dim">${fmtTime(lastUsed.LastUsedDate)}</td>
            <td class="dim">${esc(lastUsed.ServiceName || "—")}</td>
            <td class="mono dim">${esc(lastUsed.Region || "—")}</td>
          </tr>`;
        }).join("") || `<tr><td colspan="7"><div class="empty">No access keys in package</div></td></tr>`}
        </tbody></table>
      </div>
    </div>`;
}

/* ------------------------------------------------------------- network */

async function viewNetwork(el) {
  const collectors = await api("/api/coverage");
  const network = collectors.filter((c) => c.category === "network");
  if (!network.length) {
    el.innerHTML = `<div class="page-title">Network Evidence</div>
      <div class="table-wrap"><div class="empty">No network collectors in this package
      (collected with an older tool version).</div></div>`;
    return;
  }
  el.innerHTML = `
    <div class="page-title">Network Evidence</div>
    <div class="page-sub">Flow logs, DNS queries, and edge access logs collected per region —
      click a row to open its artifacts in the file browser</div>
    <div class="table-wrap">
      <table><thead><tr>
        <th>Source</th><th>Region</th><th>Status</th><th>Records</th><th>Artifact Files</th><th>Detail</th>
      </tr></thead><tbody>
      ${network.flatMap((c) => c.results.map((r) => `
        <tr data-collector="${esc(c.name)}">
          <td class="mono"><b>${esc(c.name)}</b></td>
          <td class="mono dim">${esc(r.region)}</td>
          <td>${statusChip(r.status)}</td>
          <td class="mono">${(r.artifact_count || 0).toLocaleString()}</td>
          <td class="mono dim">${(r.files || []).length}</td>
          <td class="dim" title="${esc(r.detail)}">${esc((r.detail || "").slice(0, 80))}</td>
        </tr>`)).join("")}
      </tbody></table>
    </div>`;
  $$("#content tbody tr").forEach((row) => {
    row.onclick = () => {
      state.fileFilter = row.dataset.collector;
      location.hash = "#/files";
    };
  });
}

/* ------------------------------------------------------------ workloads */

async function viewWorkloads(el) {
  el.innerHTML = `<div class="loading"><div class="spinner"></div>Loading workload evidence…</div>`;
  const data = await api("/api/workload");
  const instances = data.ec2_instances || [];
  const shared = data.shared_snapshots || [];
  const collectors = data.collectors || [];

  if (!collectors.length && !instances.length) {
    el.innerHTML = `
      <div class="page-title">Workloads</div>
      <div class="table-wrap"><div class="empty">No workload collectors in this package.</div></div>`;
    return;
  }

  const riskySnapshots = shared.length;

  el.innerHTML = `
    <div class="page-title">Workloads</div>
    <div class="page-sub">Cloud-side EC2 inventory, EBS snapshot sharing, ECS/EKS, and RDS/Aurora (host OS forensics via Velociraptor)</div>
    <div class="grid cols-3">
      <div class="card"><div class="stat-label">EC2 Instances</div>
        <div class="stat-value">${instances.length.toLocaleString()}</div></div>
      <div class="card"><div class="stat-label">Shared Snapshots</div>
        <div class="stat-value" style="color:${riskySnapshots ? "var(--danger)" : "var(--ok)"}">${riskySnapshots}</div>
        <div class="stat-foot">EBS/RDS snapshots shared externally</div></div>
      <div class="card"><div class="stat-label">Containers / DBs</div>
        <div class="stat-value">${data.ecs_clusters || 0} / ${data.eks_clusters || 0} / ${(data.rds_instances || 0) + (data.rds_clusters || 0)}</div>
        <div class="stat-foot">ECS clusters · EKS clusters · RDS resources</div></div>
    </div>
    <div style="height:14px"></div>
    ${instances.length ? `
    <div class="card" style="margin-bottom:14px">
      <div class="card-title">EC2 Instances</div>
      <div class="table-wrap" style="max-height:360px;border:none">
        <table><thead><tr>
          <th>Instance</th><th>Region</th><th>State</th><th>Type</th><th>Platform</th><th>Private IP</th><th>User Data</th><th>Launch</th>
        </tr></thead><tbody>
        ${instances.map((i) => `
          <tr class="static-row">
            <td class="mono"><b>${esc(i.instance_id)}</b></td>
            <td class="mono dim">${esc(i.region)}</td>
            <td>${i.state === "running" ? '<span class="chip ok">running</span>' : `<span class="chip neutral">${esc(i.state)}</span>`}</td>
            <td class="mono dim">${esc(i.type)}</td>
            <td>${esc(i.platform)}</td>
            <td class="mono">${esc(i.private_ip) || "—"}</td>
            <td>${i.has_user_data ? '<span class="chip warn">present</span>' : '<span class="chip neutral">none</span>'}</td>
            <td class="mono dim">${fmtTime(i.launch_time)}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>
    </div>` : ""}
    ${shared.length ? `
    <div class="callout" style="margin-bottom:14px">
      <b>${shared.length} snapshot(s) shared externally</b> — review for data exfiltration:
      <ul>${shared.slice(0, 8).map((s) =>
        `<li><span class="mono">${esc(s.snapshot_id)}</span> [${esc(s.region)}]</li>`).join("")}
      ${shared.length > 8 ? `<li>… and ${shared.length - 8} more</li>` : ""}</ul>
    </div>` : ""}
    <div class="card">
      <div class="card-title">Workload Collectors</div>
      <div class="table-wrap" style="max-height:none;border:none">
        <table><thead><tr>
          <th>Collector</th><th>Region</th><th>Status</th><th>Artifacts</th><th>Detail</th>
        </tr></thead><tbody>
        ${collectors.flatMap((c) => c.results.map((r) => `
          <tr data-collector="${esc(c.name)}" style="cursor:pointer">
            <td class="mono"><b>${esc(c.name)}</b></td>
            <td class="mono dim">${esc(r.region)}</td>
            <td>${statusChip(r.status)}</td>
            <td class="mono">${(r.artifact_count || 0).toLocaleString()}</td>
            <td class="dim">${esc((r.detail || "").slice(0, 80))}</td>
          </tr>`)).join("")}
        </tbody></table>
      </div>
    </div>`;

  $$("#content tbody tr[data-collector]").forEach((row) => {
    row.onclick = () => {
      state.fileFilter = row.dataset.collector;
      location.hash = "#/files";
    };
  });
}

/* --------------------------------------------------------- application */

async function viewApplication(el) {
  el.innerHTML = `<div class="loading"><div class="spinner"></div>Loading application logs…</div>`;
  const data = await api("/api/application");
  const collectors = data.collectors || [];
  const status = collectors[0]?.results?.[0]?.status || "unknown";

  if (status === "skipped" || !data.configured) {
    el.innerHTML = `
      <div class="page-title">Application Logs</div>
      <div class="page-sub">Client-described application log locations (access, error, auth, API, transaction logs)</div>
      <div class="callout">
        <b>Not configured</b> — the client did not supply an <span class="mono">--app-config</span> file.
        A fill-in template was written to the package at
        <span class="mono">application/application_logs/app_config_template.json</span>.
        Re-run the collector with the client's log locations listed there.
      </div>
      <button class="btn primary" onclick="location.hash='#/files';state.fileFilter='application_logs';">Open template in File Browser</button>`;
    return;
  }

  el.innerHTML = `
    <div class="page-title">Application Logs</div>
    <div class="page-sub">${(data.total_records || 0).toLocaleString()} records collected from client-described locations</div>
    <div class="grid cols-2">
      <div class="card">
        <div class="card-title">CloudWatch Log Groups</div>
        <ul class="plain-list">${(data.cloudwatch_groups || []).map((g) =>
          `<li class="mono">${esc(g)}</li>`).join("") || "<li class='dim'>none configured</li>"}</ul>
      </div>
      <div class="card">
        <div class="card-title">S3 Locations</div>
        <ul class="plain-list">${(data.s3_locations || []).map((loc) =>
          `<li class="mono">${esc(typeof loc === "string" ? loc : loc.location || JSON.stringify(loc))}</li>`).join("")
          || "<li class='dim'>none configured</li>"}</ul>
      </div>
    </div>
    <div style="height:14px"></div>
    <button class="btn" onclick="location.hash='#/files';state.fileFilter='application_logs';">Browse raw artifacts</button>`;
}

/* ----------------------------------------------------------------- idp */

async function viewIdp(el) {
  el.innerHTML = `<div class="loading"><div class="spinner"></div>Loading identity provider logs…</div>`;
  const data = await api("/api/idp");
  const providers = data.providers || [];

  if (!providers.length) {
    el.innerHTML = `
      <div class="page-title">Identity Providers</div>
      <div class="table-wrap"><div class="empty">No IdP collectors in this package.</div></div>`;
    return;
  }

  const collected = providers.filter((p) => p.status === "collected").length;

  el.innerHTML = `
    <div class="page-title">Identity Providers</div>
    <div class="page-sub">Third-party IdP audit logs — Okta, Entra ID, Google Workspace, OneLogin, PingOne</div>
    <div class="grid cols-3">
      <div class="card"><div class="stat-label">Providers Checked</div>
        <div class="stat-value">${providers.length}</div></div>
      <div class="card"><div class="stat-label">Collected</div>
        <div class="stat-value">${collected}</div></div>
      <div class="card"><div class="stat-label">Total Events</div>
        <div class="stat-value">${(data.total_events || 0).toLocaleString()}</div></div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <div class="card-title">Provider Status</div>
      <div class="table-wrap" style="max-height:none;border:none">
        <table><thead><tr>
          <th>Provider</th><th>Status</th><th>Events</th><th>Action</th>
        </tr></thead><tbody>
        ${providers.map((p) => `
          <tr>
            <td><b>${esc(p.label)}</b><div class="mono dim">${esc(p.name)}</div></td>
            <td>${statusChip(p.status)}</td>
            <td class="mono">${p.event_count.toLocaleString()}</td>
            <td>${p.status === "collected"
              ? `<button class="btn" data-idp="${esc(p.name)}">Browse logs</button>`
              : `<span class="dim">config template in package</span>`}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>
    </div>`;

  $$("[data-idp]").forEach((btn) => {
    btn.onclick = () => {
      state.fileFilter = btn.dataset.idp;
      location.hash = "#/files";
    };
  });
}

/* --------------------------------------------------------------- files */

async function viewFiles(el) {
  if (!state.files) state.files = (await api("/api/files")).files;
  const files = state.files;

  const tree = {};
  files.forEach((f) => {
    const parts = f.path.split("/");
    let node = tree;
    parts.slice(0, -1).forEach((part) => { node = node[part] ||= {}; });
    (node.__files ||= []).push(f);
  });

  function renderTree(node, prefix = "") {
    let html = "";
    Object.keys(node).filter((k) => k !== "__files").sort().forEach((dir) => {
      const id = `${prefix}/${dir}`;
      html += `<div class="tree-dir" data-dir="${esc(id)}"><span class="arrow">▼</span>${esc(dir)}</div>
        <div class="tree-children" data-children="${esc(id)}">${renderTree(node[dir], id)}</div>`;
    });
    (node.__files || []).forEach((f) => {
      html += `<div class="tree-file" data-path="${esc(f.path)}" title="${esc(f.path)}">${esc(f.path.split("/").pop())}</div>`;
    });
    return html;
  }

  el.innerHTML = `
    <div class="page-title">File Browser</div>
    <div class="page-sub">${files.length.toLocaleString()} artifacts — every file SHA-256 hashed in the manifest</div>
    <div class="file-layout">
      <div class="file-tree">${renderTree(tree)}</div>
      <div class="file-view" id="fileView">
        <div class="empty">Select a file to inspect</div>
      </div>
    </div>`;

  $$(".tree-dir", el).forEach((dirEl) => {
    dirEl.onclick = () => {
      dirEl.classList.toggle("collapsed");
      $(`[data-children="${CSS.escape(dirEl.dataset.dir)}"]`, el)
        ?.classList.toggle("hidden");
    };
  });
  $$(".tree-file", el).forEach((fileEl) => {
    fileEl.onclick = () => openFile(fileEl.dataset.path, fileEl);
  });

  if (state.fileFilter) {
    const match = $$(".tree-file", el).find((n) =>
      n.dataset.path.includes(state.fileFilter));
    state.fileFilter = null;
    if (match) { match.scrollIntoView({ block: "center" }); match.click(); }
  }

  async function openFile(path, fileEl) {
    $$(".tree-file.active", el).forEach((n) => n.classList.remove("active"));
    fileEl?.classList.add("active");
    const view = $("#fileView");
    view.innerHTML = `<div class="loading"><div class="spinner"></div>Loading…</div>`;
    const data = await api("/api/file", { path });
    const meta = files.find((f) => f.path === path);
    let rendered;
    try { rendered = highlightJson(JSON.parse(data.content)); }
    catch { rendered = esc(data.content); }
    view.innerHTML = `
      <div class="file-view-head">
        <span>${esc(path)}</span>
        <span>${fmtBytes(data.size)}${data.truncated ? " · TRUNCATED VIEW" : ""}${meta?.sha256 ? ` · sha256 ${esc(meta.sha256.slice(0, 16))}…` : ""}</span>
      </div>
      <pre class="json">${rendered}</pre>`;
  }
}

/* ----------------------------------------------------- platform switch */

function renderPlatformSwitch() {
  const meta = PLATFORMS[state.platform];
  const icon = $("#platformIcon");
  icon.textContent = meta.short;
  icon.className = `platform-icon ${meta.cls}`;
  $("#platformName").textContent = meta.name;
  $$(".platform-option").forEach((opt) =>
    opt.classList.toggle("active", opt.dataset.platform === state.platform));
}

function initPlatformSwitch() {
  const wrap = $("#platformSwitch");
  const packageCloud = state.summary?.scope?.cloud || "aws";
  state.platform = PLATFORMS[packageCloud] ? packageCloud : "aws";

  $("#platformBtn").onclick = (e) => {
    e.stopPropagation();
    wrap.classList.toggle("open");
  };
  document.addEventListener("click", () => wrap.classList.remove("open"));
  $$(".platform-option").forEach((opt) => {
    opt.onclick = (e) => {
      e.stopPropagation();
      state.platform = opt.dataset.platform;
      wrap.classList.remove("open");
      renderPlatformSwitch();
      route();
    };
  });
  renderPlatformSwitch();
}

function viewPlatformPlaceholder(el, platform) {
  const meta = PLATFORMS[platform];
  const packageCloud = state.summary?.scope?.cloud || "aws";
  const reason = packageCloud === platform
    ? "This package was collected from this platform, but the viewer has no parsers for it yet."
    : `This evidence package was collected from <b>${esc(PLATFORMS[packageCloud].name)}</b>.
       ${esc(meta.name)} collectors are on the roadmap — the package format and this
       viewer are already designed to support them.`;
  el.innerHTML = `
    <div class="platform-placeholder">
      <span class="platform-icon ${meta.cls}">${meta.short}</span>
      <h2>${esc(meta.name)} — Coming Soon</h2>
      <p>${reason}</p>
      <p>Switch back to <b>Amazon Web Services</b> to explore the evidence in this package.</p>
    </div>`;
}

/* -------------------------------------------------------------- router */

const VIEWS = {
  overview: viewOverview,
  coverage: viewCoverage,
  cloudtrail: viewCloudTrail,
  findings: viewFindings,
  identity: viewIdentity,
  network: viewNetwork,
  workloads: viewWorkloads,
  application: viewApplication,
  idp: viewIdp,
  files: viewFiles,
};

async function route() {
  const view = (location.hash.replace("#/", "") || "overview").split("?")[0];
  const renderer = VIEWS[view] || viewOverview;
  $$(".nav-item").forEach((item) =>
    item.classList.toggle("active", item.dataset.view === view));
  const el = $("#content");
  closeDrawer();
  if (state.platform !== "aws") {
    viewPlatformPlaceholder(el, state.platform);
    return;
  }
  try {
    await renderer(el);
  } catch (err) {
    el.innerHTML = `<div class="table-wrap"><div class="empty">Error: ${esc(err.message)}</div></div>`;
  }
}

/* ----------------------------------------------------------- upload UI */

function setPackageLoaded(loaded) {
  document.body.classList.toggle("no-package", !loaded);
}

function showWelcomeScreen(errorMessage = "") {
  setPackageLoaded(false);
  const err = errorMessage
    ? `<div class="callout upload-error">${esc(errorMessage)}</div>` : "";
  $("#content").innerHTML = `
    <div class="welcome">
      <div class="welcome-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 4h6l2 3h8a1 1 0 011 1v11a1 1 0 01-1 1H4a1 1 0 01-1-1V5a1 1 0 011-1z"/>
          <path d="M12 11v6"/><path d="M9.5 13.5L12 11l2.5 2.5"/>
        </svg>
      </div>
      <h1 class="welcome-title">Open Evidence Package</h1>
      <p class="welcome-lead">
        Upload a collected evidence folder or ZIP file to begin investigation.
        You can also start the viewer with a path on the command line.
      </p>
      ${err}
      <div class="upload-actions">
        <button class="btn primary" type="button" id="btnUploadFolder">Select Folder</button>
        <button class="btn" type="button" id="btnUploadZip">Select ZIP File</button>
      </div>
      <p class="upload-hint">
        Folder upload expects the extracted package directory (must contain
        <span class="mono">manifest.json</span> at the root or one level down).
      </p>
    </div>`;
  $("#btnUploadFolder").onclick = () => $("#folderInput").click();
  $("#btnUploadZip").onclick = () => $("#zipInput").click();
  $("#topbarMeta").innerHTML = `<span class="meta-chip">No package loaded</span>`;
  $("#topbarActions").innerHTML = `
    <button class="btn primary" type="button" id="btnOpenPackageTop">Open Package</button>`;
  $("#btnOpenPackageTop").onclick = () => showUploadMenu();
}

function showUploadMenu() {
  const pickFolder = window.confirm(
    "Open an evidence package\n\nOK = select a folder\nCancel = select a ZIP file");
  if (pickFolder) $("#folderInput").click();
  else $("#zipInput").click();
}

function showUploadProgress(label) {
  $("#content").innerHTML = `
    <div class="loading upload-progress">
      <div class="spinner"></div>
      <div>
        <div>Uploading and indexing ${esc(label)}…</div>
        <div class="upload-progress-sub">Large packages may take a minute.</div>
      </div>
    </div>`;
}

async function uploadFiles(files, { isZip = false } = {}) {
  if (!files?.length) return;
  const label = isZip ? files[0].name : (files[0].webkitRelativePath || files[0].name).split("/")[0];
  showUploadProgress(label || "evidence package");

  const form = new FormData();
  if (isZip) {
    form.append("package", files[0], files[0].name);
  } else {
    for (const file of files) {
      form.append("files", file, file.webkitRelativePath || file.name);
    }
  }

  const res = await fetch("/api/upload", { method: "POST", body: form });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(payload.error || `${res.status} ${res.statusText}`);
  }

  state.summary = null;
  state.ctFacets = null;
  state.files = null;
  state.activeFile = null;
  state.ctFilters.offset = 0;
  state.findingFilters.offset = 0;
  state.packageLabel = payload.label || label;
  location.hash = "#/overview";
  await loadPackage();
}

function initUploadInputs() {
  $("#folderInput").onchange = async (event) => {
    const files = event.target.files;
    event.target.value = "";
    try {
      await uploadFiles(files, { isZip: false });
    } catch (err) {
      showWelcomeScreen(err.message);
    }
  };
  $("#zipInput").onchange = async (event) => {
    const files = event.target.files;
    event.target.value = "";
    try {
      await uploadFiles(files, { isZip: true });
    } catch (err) {
      showWelcomeScreen(err.message);
    }
  };
}

async function loadPackage() {
  state.summary = await api("/api/summary");
  setPackageLoaded(true);
  renderTopbar();
  initPlatformSwitch();
  if (!window.__viewerRouted) {
    window.addEventListener("hashchange", route);
    window.__viewerRouted = true;
  }
  route();
}

/* ---------------------------------------------------------------- init */

async function init() {
  $("#drawerClose").onclick = closeDrawer;
  $("#drawerBackdrop").onclick = closeDrawer;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  initUploadInputs();

  let status;
  try {
    status = await api("/api/status");
  } catch (err) {
    $("#content").innerHTML = `<div class="table-wrap"><div class="empty">Could not reach viewer: ${esc(err.message)}</div></div>`;
    return;
  }

  if (!status.loaded) {
    showWelcomeScreen();
    return;
  }

  state.packageLabel = status.label || null;
  try {
    await loadPackage();
  } catch (err) {
    showWelcomeScreen(err.message);
  }
}

init();
