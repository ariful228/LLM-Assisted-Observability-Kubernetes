/* AI Kubernetes Observability & Security - simple vanilla JS SPA */

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.status === 204 ? null : res.json();
}

const state = { view: "dashboard", incidents: [], approvals: [] };

// ---------- navigation ----------
document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.view === "detail") return;
    showView(btn.dataset.view);
  });
});

function showView(view, incident = null) {
  state.view = view;
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  if (view === "detail" && incident) {
    $("#view-detail").classList.add("active");
    renderDetail(incident);
  } else {
    const section = $("#view-" + view);
    if (section) section.classList.add("active");
  }
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  if (view === "dashboard") refresh();
  if (view === "workflow") typeof WorkflowSim !== "undefined" && WorkflowSim.refresh();
  if (view === "incidents") loadIncidents();
  if (view === "security") loadSecurity();
  if (view === "approvals") loadApprovals();
  if (view === "tools") loadTools();
  if (view === "knowledge") loadKnowledge();
  if (view === "logs") loadLogs();
  if (view === "status") loadStatus();
}

// ---------- shared ----------
async function loadMode() {
  try { const s = await api("/api/status"); $("#mode-pill").textContent = s.components.kubernetes.mode || "n/a"; } catch (_) {}
}

function severityTag(sev) {
  const c = ({ critical: "critical", high: "high", medium: "medium", low: "low" })[sev] || "low";
  return `<span class="tag ${c}">${esc(sev)}</span>`;
}

// ---------- dashboard ----------
async function refresh() {
  await loadMode();
  const [incs, stats, secStats, secFindings] = await Promise.all([
    api("/api/incidents"),
    api("/api/evaluation/stats"),
    api("/api/security/stats").catch(() => null),
    api("/api/security/findings").catch(() => null),
  ]);
  state.incidents = incs.incidents;
  const all = incs.incidents;
  const open = all.filter((i) => ["DETECTED", "INVESTIGATING", "AWAITING_APPROVAL", "APPROVED", "EXECUTING"].includes(i.status));
  const pending = all.filter((i) => i.approval_status === "PENDING");
  const ai = all.filter((i) => i.diagnosis && (i.diagnosis.summary || i.diagnosis.cause));
  const verified = all.filter((i) => i.verification_status === "PASSED").length;
  const failed = all.filter((i) => i.verification_status === "FAILED").length;
  $("#approval-badge").textContent = pending.length;

  const cards = [
    ["Total Incidents", stats.total_incidents],
    ["Active", open.length],
    ["Pending Approvals", pending.length],
    ["Auto Remediated", stats.autos],
    ["Human Approved", stats.approved],
    ["AI Investigations", ai.length],
    ["Verification Failed", stats.verification_failed],
  ];
  $("#dashboard-cards").innerHTML = cards
    .map(([l, v]) => `<div class="card"><div class="value">${v}</div><div class="label">${l}</div></div>`)
    .join("");

  const filter = (n) => all.slice(0, n);
  $("#dashboard-incidents tbody").innerHTML = all.slice(0, 10)
    .map((i) => {
      const pd = i.policy_decision || {};
      return `<tr onclick="openDetail('${i.incident_id}')">
        <td>${esc(i.incident_id)}</td>
        <td>${esc(i.incident_type)}</td>
        <td>${severityTag(i.severity)}</td>
        <td>${esc(i.status)}</td>
        <td>${esc(pd.action || "-")}</td>
        <td>${esc(i.verification_status || "-")}</td>
        <td>${new Date(i.detected_at).toLocaleString()}</td>
      </tr>`;
    }).join("");
  renderDashSecurity(secStats, secFindings);
  renderDashVerification(stats, all, verified, failed);
  renderDashSecEvents(secFindings);
  await renderCluster();
}

function renderDashSecurity(secStats, secFindings) {
  const target = $("#dash-security");
  if (!secStats) { target.innerHTML = `<p class="muted">security unavailable</p>`; return; }
  const s = secStats;
  const waiting = s.by_status && (s.by_status.AWAITING_APPROVAL || 0);
  const remediated = s.by_status && (s.by_status.REMEDIATED || 0);
  const cards = [
    ["Findings", s.total],
    ["Critical", s.by_severity.critical || 0],
    ["High", s.by_severity.high || 0],
    ["Remediated", remediated],
    ["Awaiting approval", waiting],
  ];
  target.innerHTML = cards.map(([l, v]) => `<div class="card"><div class="value">${v}</div><div class="label">${l}</div></div>`).join("");
}

function renderDashVerification(stats, all, verified, failed) {
  const target = $("#dash-verification");
  const auto = stats.autos || 0;
  const approved = stats.approved || 0;
  const rejected = stats.rejected || 0;
  const cards = [
    ["Auto Remediations", auto],
    ["Human Approved", approved],
    ["Rejected", rejected],
    ["Incidents Verified (PASSED)", verified],
    ["Verification Failed", failed],
    ["Open (awaiting / verification failed)", all.filter((i) => i.status === "AWAITING_APPROVAL" || i.status === "VERIFICATION_FAILED").length],
  ];
  target.innerHTML = cards.map(([l, v]) => `<div class="card"><div class="value">${v}</div><div class="label">${l}</div></div>`).join("");
}

function renderDashSecEvents(secFindings) {
  const target = $("#dash-sec-events");
  if (!secFindings) { target.innerHTML = `<p class="muted">security unavailable</p>`; return; }
  const list = (secFindings.findings || []).slice(0, 6);
  target.innerHTML = list.length
    ? list.map((f) => `
      <div class="sec-event">
        <div class="se-row">
          ${layerTag(f.layer)} ${severityTag(f.severity)} ${statusTag(f.status)} ${f.simulated ? `<span class="tag sim">SIM</span>` : ""}
          <span class="se-time">${new Date(f.detected_at).toLocaleString()}</span>
        </div>
        <div class="se-msg">${esc(f.title)}</div>
        <div class="se-sub"><code>${esc(f.recommended_action || "-")}</code> · verify ${esc(f.verification_status)}</div>
      </div>`).join("")
    : `<p class="muted">no security events</p>`;
}

async function renderCluster() {
  try {
    const c = await api("/api/cluster");
    $("#cluster-overview").innerHTML = `
      <div class="cards">
        <div class="card"><div class="value">${c.nodes.length}</div><div class="label">Nodes</div></div>
        <div class="card"><div class="value">${c.pod_count}</div><div class="label">Pods</div></div>
        <div class="card"><div class="value">${c.running_pods}</div><div class="label">Running</div></div>
        <div class="card"><div class="value">${c.failed_pods}</div><div class="label">Not healthy</div></div>
      </div>
      <table class="table"><thead><tr><th>Deployment</th><th>Replicas</th><th>Ready</th><th>Mode</th></tr></thead>
      <tbody>${c.deployments.map((d) => `<tr><td>${esc(d.name)}</td><td>${d.replicas}</td><td>${d.ready}/${d.available}</td><td>${esc(c.mode)}</td></tr>`).join("")}</tbody></table>`;
  } catch (err) { $("#cluster-overview").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
}

// ---------- incidents ----------
function renderRows(incidents) {
  return incidents.map((i) => {
    const pd = i.policy_decision || {};
    return `<tr onclick="showView('detail', ${JSON.stringify(i).replace(/"/g, "&quot;")})">
      <td>${esc(i.incident_id)}</td>
      <td>${esc(i.incident_type)}</td>
      <td>${severityTag(i.severity)}</td>
      <td>${esc(i.status)}</td>
      <td>${esc(pd.action || "-")}</td>
      <td>${new Date(i.detected_at).toLocaleString()}</td>
    </tr>`;
  }).join("");
}

async function loadIncidents() {
  let incs = state.incidents;
  try { incs = (await api("/api/incidents")).incidents; state.incidents = incs; } catch (_) {}
  const ft = $("#filter-type").value.trim().toLowerCase();
  const fs = $("#filter-status").value.trim().toLowerCase();
  if (ft) incs = incs.filter((i) => i.incident_type.includes(ft));
  if (fs) incs = incs.filter((i) => i.status.toLowerCase().includes(fs));
  $("#incident-table tbody").innerHTML = renderRows(incs);
}

$("#btn-refresh").addEventListener("click", loadIncidents);

// ---------- detail ----------
function renderDetail(inc) {
  const pd = inc.policy_decision || {};
  const ra = inc.recommended_action || {};
  const diag = inc.diagnosis || {};
  const exec = inc.execution_result || {};
  const vr = inc.verification_result || {};

  const approvalBox =
    inc.approval_status === "PENDING"
      ? `<div class="approval-panel">
          <h3>Action Required</h3>
          <div class="detail-grid">
            <div><b>Action</b></div><div>${esc(ra.action || "-")}</div>
            <div><b>Target</b></div><div>${esc(inc.namespace)}/${esc(inc.resource)}</div>
            <div><b>Params</b></div><div><pre class="code-block">${esc(JSON.stringify(ra.params || {}, null, 2))}</pre></div>
            <div><b>Reason</b></div><div>${esc(pd.reason || "")}</div>
            <div><b>Risk</b></div><div>${severityTag(inc.risk_level)}</div>
            <div><b>Expected result</b></div><div>${esc(ra.expected_result || "")}</div>
          </div>
          <div class="actions">
            <button class="approve" onclick="resolveApproval('${inc.incident_id}','approve')">Approve</button>
            <button class="reject" onclick="resolveApproval('${inc.incident_id}','reject')">Reject</button>
          </div>
        </div>`
      : "";

  const timeline = (inc.timeline || [])
    .map((t) => `<li><span class="ts">${esc(t.ts.slice(11, 19))}</span> <b>${esc(t.step)}</b> — ${esc(t.detail)}</li>`)
    .join("");

  const evidence = (inc.evidence || [])
    .slice()
    .reverse()
    .map((e) => `<details class="evidence-item">
        <summary>${esc(e.category)} · ${esc(e.source)} · ${esc(e.summary)}</summary>
        <pre>${esc(JSON.stringify(e.data ?? {}, null, 2))}</pre>
      </details>`)
    .join("");

  const rag = (inc.rag_sources || [])
    .map((s) => `<div class="doc-card"><b>${esc(s.document)}</b> <span class="tag">${esc(s.backend)}</span> <span class="muted">score ${s.score}</span><br/>${esc(s.excerpt)}</div>`)
    .join("");

  const checks = (vr.checks || []).map((c) => `<li>${c.passed ? "✅" : "❌"} ${esc(c.name)} → ${esc(JSON.stringify(c.actual ?? ""))}</li>`).join("");

  $("#incident-detail").innerHTML = `
    <div class="row">
      <h2 style="margin:0">${esc(inc.incident_id)} · ${esc(inc.incident_type)}</h2>
      ${severityTag(inc.severity)} <span class="tag">${esc(inc.status)}</span>
    </div>
    ${approvalBox}
    <div class="grid-2">
      <div class="detail-section">
        <h3>Policy Decision</h3>
        <p>Decision: <b>${esc(pd.decision || "-")}</b> · Rule <code>${esc(pd.rule_id || "-")}</code></p>
        <p class="muted">${esc(pd.reason || "")}</p>
        <h3>Execution</h3>
        <p>Status: <b>${esc(inc.execution_status)}</b> · Tool: <code>${esc(exec.tool || "-")}</code></p>
        <p class="muted">${esc(exec.error || "")}</p>
        <pre class="code-block">${esc(JSON.stringify(exec.output ?? {}, null, 2))}</pre>
        <h3>Verification</h3>
        <p>Status: <b>${esc(inc.verification_status)}</b></p>
        <ul>${checks || `<li class="muted">${esc(vr.detail || "no checks")}</li>`}</ul>
      </div>
      <div class="detail-section">
        <h3>AI Diagnosis</h3>
        <p><b>${esc(diag.summary || "")}</b></p>
        <p>${esc(diag.cause || "")}</p>
        <p class="muted">confidence ${diag.confidence ?? "-"} · risk ${esc(diag.risk_level || "-")}</p>
        <h3>RAG Sources</h3>
        ${rag || `<p class="muted">no knowledge sources matched</p>`}
      </div>
    </div>
    <div class="detail-section">
      <h3>Timeline</h3>
      <ul class="timeline">${timeline || "<li>empty</li>"}</ul>
    </div>
    <div class="detail-section">
      <h3>Evidence</h3>
      <p class="muted">Raw evidence is always shown — never hidden behind the LLM summary.</p>
      ${evidence || "<p class='muted'>no evidence</p>"}
    </div>
  `;
}

async function resolveApproval(id, decision) {
  const reason = decision === "reject" ? prompt("Reason for rejection:") || "" : "";
  try {
    const updated = await api(`/api/incidents/${id}/approval`, {
      method: "POST",
      body: JSON.stringify({ decision, reason, approved_by: "webui-user" }),
    });
    renderDetail(updated);
    loadApprovals();
    state.incidents = (await api("/api/incidents")).incidents;
  } catch (err) { alert(err.message); }
}

$("#btn-back").addEventListener("click", () => showView("incidents"));
document.querySelectorAll("main").forEach(() => {});

// ---------- approvals ----------
async function loadApprovals() {
  try {
    const a = await api("/api/approvals");
    $("#approval-badge").textContent = a.count;
    $("#approval-list").innerHTML = a.approvals.length
      ? a.approvals.map((ap) => `
        <div class="approval-panel">
          <div class="row">
            <b>${esc(ap.incident_id)}</b> ${esc(ap.incident_type)} ${severityTag(ap.severity)} ${esc(ap.resource)}
          </div>
          <p>Action: <b>${esc(ap.recommended_action?.action || "-")}</b> · Risk: ${severityTag(ap.risk_level)}</p>
          <p class="muted">${esc(ap.reason || "")}</p>
          <div class="actions">
            <button class="approve" onclick="resolveApproval('${ap.incident_id}','approve')">Approve</button>
            <button class="reject" onclick="resolveApproval('${ap.incident_id}','reject')">Reject</button>
            <button class="small" onclick="openDetail('${ap.incident_id}')">View incident</button>
          </div>
        </div>`).join("")
      : `<p class="muted">No pending approvals.</p>`;
  } catch (err) { $("#approval-list").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
}

async function openDetail(id) {
  try { const inc = await api(`/api/incidents/${id}`); showView("detail", inc); } catch (err) { alert(err.message); }
}

// ---------- tools ----------
async function loadTools() {
  try {
    const t = await api("/api/mcp/tools");
    $("#tool-list").innerHTML = t.tools
      .map((to) => `
        <div class="tool-card">
          <div><span class="name">${esc(to.name)}</span> <span class="kind">${esc(to.kind)}${to.requires_policy ? " · policy-gated" : ""}</span></div>
          <div class="muted">${esc(to.description)}</div>
          <code class="muted">${esc(JSON.stringify(to.inputSchema || {}))}</code>
        </div>`)
      .join("");
  } catch (err) { $("#tool-list").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
}

$("#btn-check-unsafe").addEventListener("click", async () => {
  try { $("#unsafe-result").textContent = JSON.stringify(await api("/api/mcp/no-unsafe-tools"), null, 2); }
  catch (err) { $("#unsafe-result").textContent = err.message; }
});

// ---------- knowledge ----------
async function loadKnowledge() {
  try {
    const k = await api("/api/knowledge");
    $("#knowledge-docs").innerHTML = k.documents
      .map((d) => `<div class="doc-card"><b>${esc(d.path)}</b> <span class="tag">${esc(d.category)}</span><br/>${esc(d.excerpt)}</div>`)
      .join("") || "<p class='muted'>empty</p>";
  } catch (err) { $("#knowledge-docs").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
  loadRagDbInfo();
}

async function loadRagDbInfo() {
  try {
    const info = await api("/api/knowledge/db/info");
    if (!info.backends) { $("#rag-db-info").innerHTML = ""; return; }
    $("#rag-db-info").innerHTML = Object.values(info.backends).map((b) => {
      const ok = !!b.available;
      const bad = b.error ? `<br/><span class="muted">${esc(b.error)}</span>` : "";
      return `<div class="status-comp"><span class="dot${ok ? "" : " off"}"></span>
        <div><b>${esc(b.backend)}</b> <span class="muted">${ok ? "up" : "down"}</span>
        <br/><span class="muted">chunks ${b.chunks ?? "-"} · model ${esc(b.embedding_model ?? "-")}${b.dim ? " · dim " + b.dim : ""} · indexed ${esc(b.last_indexed ?? "-")}</span>${bad}</div></div>`;
    }).join("");
    const active = (info.active || []).join(", ") || "none";
    const head = `<div class="status-comp"><b>Active backends</b><span class="muted">${esc(active)} · store=${esc(info.store_mode)} · ${info.documents} docs / ${info.chunks} chunks</span></div>`;
    $("#rag-db-info").insertAdjacentHTML("afterbegin", head);
  } catch (err) {
    $("#rag-db-info").innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

async function reindexRagDb() {
  const btn = $("#btn-rag-reindex");
  btn.disabled = true; btn.textContent = "Re-indexing…";
  try {
    const r = await api("/api/knowledge/db/reindex", { method: "POST" });
    $("#rag-results").innerHTML = `<div class="doc-card"><b>RAG re-indexed</b><br/><pre class="muted">${esc(JSON.stringify(r.summary, null, 2))}</pre></div>`;
    loadRagDbInfo();
  } catch (err) {
    $("#rag-results").innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  } finally { btn.disabled = false; btn.textContent = "Re-index knowledge → RAG DBs"; }
}

$("#btn-rag-refresh").addEventListener("click", loadRagDbInfo);
$("#btn-rag-reindex").addEventListener("click", reindexRagDb);

$("#btn-rag").addEventListener("click", async () => {
  const q = $("#rag-query").value.trim();
  if (!q) return;
  try {
    const r = await api("/api/knowledge/search", { method: "POST", body: JSON.stringify({ query: q, top_k: 5 }) });
    $("#rag-results").innerHTML = r.sources.length
      ? r.sources.map((s) => `<div class="doc-card"><b>${esc(s.document)}</b> #${esc(s.chunk)}
          <span class="tag">${esc(s.backend)}</span> <span class="muted">score ${s.score}</span><br/>${esc(s.excerpt)}</div>`).join("")
      : `<p class="muted">no matches</p>`;
  } catch (err) { $("#rag-results").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
});

// ---------- application logs ----------
async function loadLogFacets() {
  try {
    const f = await api("/api/logs/facets");
    fillLogSelect("#log-namespace", f.namespaces || [], "all namespaces");
    fillLogSelect("#log-pod", f.pods || [], "all pods");
    fillLogSelect("#log-container", f.containers || [], "all containers");
  } catch (_) {}
}

function fillLogSelect(sel, values, placeholder) {
  const cur = $(sel).value;
  $(sel).innerHTML = `<option value="">${placeholder}</option>` +
    [...new Set(values)].map((v) => `<option>${esc(v)}</option>`).join("");
  if (values.includes(cur)) $(sel).value = cur;
}

function logLevelTag(level) {
  const cls = level === "ERROR" ? "critical" : level === "WARN" ? "medium" : "low";
  return `<span class="tag ${cls}">${esc(level)}</span>`;
}

async function loadLogs() {
  try {
    const params = new URLSearchParams({ size: "200" });
    const ns = $("#log-namespace").value, pod = $("#log-pod").value,
      cont = $("#log-container").value, lvl = $("#log-level").value,
      kw = $("#log-keyword").value.trim();
    if (ns) params.set("namespace", ns);
    if (pod) params.set("pod", pod);
    if (cont) params.set("container", cont);
    if (lvl) params.set("level", lvl);
    if (kw) params.set("keyword", kw);
    const since = $("#log-since").value, until = $("#log-until").value;
    if (since) params.set("since", new Date(since).toISOString());
    if (until) params.set("until", new Date(until).toISOString());

    const r = await api("/api/logs?" + params.toString());
    $("#log-count").textContent = `${r.count} hit${r.count === 1 ? "" : "s"} · index ${r.index}`;
    $("#log-table tbody").innerHTML = r.hits.length
      ? r.hits.map((h) => `
        <tr>
          <td class="log-ts">${esc(new Date(h.timestamp).toLocaleString())}</td>
          <td>${esc(h.namespace)}</td>
          <td>${esc(h.pod)}</td>
          <td>${esc(h.container)}</td>
          <td>${logLevelTag(h.level)}</td>
          <td class="log-msg">${esc(h.message)}</td>
        </tr>`).join("")
      : `<tr><td colspan="6" class="muted">no matching logs</td></tr>`;
  } catch (err) {
    $("#log-table tbody").innerHTML = `<tr><td colspan="6" class="muted">${esc(err.message)}</td></tr>`;
    $("#log-count").textContent = "";
  }
}

function resetLogFilters() {
  ["#log-namespace", "#log-pod", "#log-container", "#log-level"].forEach((s) => { $(s).value = ""; });
  $("#log-keyword").value = "";
  $("#log-since").value = ""; $("#log-until").value = "";
  loadLogs();
}

$("#btn-log-apply").addEventListener("click", loadLogs);
$("#btn-log-reset").addEventListener("click", resetLogFilters);
$("#log-namespace").addEventListener("change", () => { loadLogFacets(); loadLogs(); });
$("#log-pod").addEventListener("change", loadLogs);
$("#log-container").addEventListener("change", loadLogs);
$("#log-level").addEventListener("change", loadLogs);
$("#log-keyword").addEventListener("keydown", (e) => { if (e.key === "Enter") loadLogs(); });

// ---------- status ----------
async function loadStatus() {
  try {
    const s = await api("/api/status");
    $("#component-status").innerHTML = Object.entries(s.components)
      .map(([name, c]) => {
        const ok = c.available || (!c.configured && name !== "kubernetes");
        const dot = c.configured ? (c.available ? "" : " off") : " warn";
        return `<div class="status-comp"><span class="dot${dot}"></span><b>${esc(name)}</b>
          <span class="muted">${c.configured ? "configured" : "not configured"}${c.available ? " · available" : ""}${c.mode ? " · " + esc(c.mode) : ""}${c.provider ? " · " + esc(c.provider) : ""}</span></div>`;
      })
      .join("");
  } catch (err) { $("#component-status").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
  try { $("#evaluation-summary").textContent = JSON.stringify(await api("/api/evaluation/stats"), null, 2); }
  catch (err) { $("#evaluation-summary").textContent = err.message; }
}

$("#btn-detect").addEventListener("click", async () => {
  $("#btn-detect").disabled = true;
  try {
    const r = await api("/api/incidents/detect", { method: "POST" });
    alert(`Detection created ${r.count} incident(s).`);
    showView("incidents"); loadIncidents();
  } catch (err) { alert(err.message); }
  finally { $("#btn-detect").disabled = false; }
});

// ---------- security findings ----------
const securityState = { findings: [], layers: [], domains: [] };

function layerTag(layer) {
  const cls = ({ application: "app", container: "cnt", node_cloud: "node", kubernetes_cluster: "k8s" })[layer] || "";
  return `<span class="tag layer ${cls}">${esc(layer)}</span>`;
}
function statusTag(st) {
  const cls = st === "AWAITING_APPROVAL" ? "wait" : st === "REMEDIATED" ? "ok" : st === "VERIFICATION_FAILED" ? "fail" : "";
  return `<span class="tag ${cls}">${esc(st)}</span>`;
}

async function loadSecurity() {
  try {
    const [layers, findings] = await Promise.all([api("/api/security/layers"), api("/api/security/findings")]);
    securityState.findings = findings.findings;
    const totalSim = findings.findings.filter((f) => f.simulated).length;
    $("#sec-cards").innerHTML = layers.layers.map((l) => `
      <div class="card sec-card ${l.layer}">
        <div class="label">${esc(l.layer)} <span class="muted">layer</span></div>
        <div class="value">${l.total}</div>
        <div class="mini">
          ${l.critical ? `<span class="crit">${l.critical} crit</span>` : ""}
          ${l.high ? `<span class="hi">${l.high} high</span>` : ""}
          ${l.medium ? `<span>${l.medium} med</span>` : ""}
          ${l.low ? `<span>${l.low} low</span>` : ""}
          · <span class="ok">${l.remediated} remediated</span> · <span class="wait">${l.waiting} waiting</span>
        </div>
      </div>`).join("") +
      `<div class="card"><div class="label">Findings</div><div class="value">${layers.total}</div><div class="mini">${totalSim} SIMULATED</div></div>`;
  } catch (err) { $("#sec-cards").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
  loadFindingsTable();
  loadLab();
}

async function loadFindingsTable() {
  try {
    const layers = await api("/api/security/layers");
    const domains = (await api("/api/security/stats")).domains || [];
    const sel = $("#sec-domain");
    sel.innerHTML = `<option value="">all domains</option>` + domains.map((d) => `<option>${esc(d)}</option>`).join("");
    const layer = $("#sec-layer").value, status = $("#sec-status").value, sev = $("#sec-severity").value, dom = sel.value;
    const q = new URLSearchParams();
    if (layer) q.set("layer", layer);
    if (status) q.set("status", status);
    if (sev) q.set("severity", sev);
    if (dom) q.set("domain", dom);
    const path = "/api/security/findings" + (q.toString() ? "?" + q : "");
    const findings = (await api(path)).findings;
    securityState.findings = findings;
    $("#sec-table tbody").innerHTML = findings.length
      ? findings.map((f) => `
        <tr onclick="toggleFindingDetail('${f.finding_id}')">
          <td>${esc(f.finding_id)}</td>
          <td>${layerTag(f.layer)}</td>
          <td>${esc(f.domain || "-")}</td>
          <td>${esc(f.title)} ${f.simulated ? `<span class="tag sim">SIMULATED</span>` : ""}</td>
          <td>${severityTag(f.severity)}</td>
          <td>${statusTag(f.status)}</td>
          <td><code class="muted">${esc(f.recommended_action || "-")}</code></td>
          <td>${esc(f.verification_status)}</td>
          <td>${f.status === "AWAITING_APPROVAL"
            ? `<button class="approve" onclick="event.stopPropagation();resolveFinding('${f.finding_id}','approve')">✓</button>
               <button class="reject" onclick="event.stopPropagation();resolveFinding('${f.finding_id}','reject')">✕</button>`
            : `<span class="muted">—</span>`}</td>
        </tr>`).join("")
      : `<tr><td colspan="9" class="muted">no findings match the filters</td></tr>`;
  } catch (err) { $("#sec-table tbody").innerHTML = `<tr><td colspan="9" class="muted">${esc(err.message)}</td></tr>`; }
}

async function toggleFindingDetail(id) {
  const target = $("#finding-detail");
  try {
    const f = await api(`/api/security/findings/${id}`);
    if (target.dataset.id === id) { target.innerHTML = ""; delete target.dataset.id; return; }
    target.dataset.id = id;
    const checks = (f.verification_checks || []).map((c) => `<li>${c.passed ? "✅" : "❌"} ${esc(c.name)} → <span class="muted">${esc(JSON.stringify(c.actual ?? ""))}</span> — ${esc(c.detail || "")}</li>`).join("");
    const decisionBox = f.status === "AWAITING_APPROVAL" ? `
      <div class="actions">
        <button class="approve" onclick="resolveFinding('${f.finding_id}','approve')">Approve remediation</button>
        <button class="reject" onclick="resolveFinding('${f.finding_id}','reject')">Reject</button>
      </div>` : "";
    target.innerHTML = `
      <div class="detail-section">
        <div class="row"><h3 style="margin:0">${esc(f.finding_id)}</h3> ${layerTag(f.layer)} ${statusTag(f.status)} ${severityTag(f.severity)} ${f.simulated ? `<span class="tag sim">SIMULATED</span>` : ""}</div>
        <p><b>${esc(f.title)}</b></p>
        <div class="detail-grid">
          <div><b>Issue</b></div><div>${esc(f.issue)}</div>
          <div><b>Affected Resource</b></div><div>${esc(f.affected_resource || "-")}</div>
          <div><b>Root Cause</b></div><div>${esc(f.root_cause || "-")}</div>
          <div><b>Recommended Solution</b></div><div>${esc(f.recommended_solution || "-")}</div>
          <div><b>Policy Decision</b></div><div>${esc(f.decision)}${f.approval_required ? " · <span class=\"wait\">approval required</span>" : " · <span class=\"ok\">auto</span>"}</div>
          <div><b>Remediation</b></div><div><code>${esc(f.recommended_action || "-")}</code> · status <b>${esc(f.remediation_status)}</b></div>
          <div><b>Verification</b></div><div>${esc(f.verification_status)}</div>
          <div><b>Source</b></div><div>${esc(f.source)}</div>
        </div>
        <h3>Verification checks</h3>
        <ul class="timeline">${checks || "<li class='muted'>not verified yet</li>"}</ul>
        <h3>Evidence</h3>
        <ul class="timeline">${(f.evidence || []).map((e) => `<li>${esc(e.summary)} <span class="muted">(${esc(e.source)})</span></li>`).join("") || "<li class='muted'>no evidence</li>"}</ul>
        <h3>Timeline</h3>
        <ul class="timeline">${(f.timeline || []).map((t) => `<li><span class="ts">${esc((t.ts || "").slice(11, 19))}</span> <b>${esc(t.step)}</b> — ${esc(t.detail)}</li>`).join("") || "<li class='muted'>empty</li>"}</ul>
        ${decisionBox}
      </div>`;
  } catch (err) { target.innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
}

async function resolveFinding(id, decision) {
  const reason = decision === "reject" ? prompt("Reason for rejection:") || "" : "";
  try {
    await api(`/api/security/findings/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, reason, approved_by: "webui-user" }),
    });
    await loadFindingsTable();
    if (id === ($("#finding-detail").dataset.id || null)) $("#finding-detail").innerHTML = "";
  } catch (err) { alert(err.message); }
}

async function loadLab() {
  try {
    const catalog = await api("/api/security/lab");
    $("#lab-scenarios").innerHTML = catalog.scenarios.length
      ? catalog.scenarios.map((s) => `
        <div class="lab-card ${s.layer}">
          <div class="lab-head">${esc(s.title)}</div>
          ${layerTag(s.layer)} <span class="muted">${s.decision_hint === "AUTO" ? "auto" : "approval"}</span>
          <div><button class="small primary" data-lab="${s.key}" onclick="runLabScenario('${s.key}')">Run scenario</button></div>
        </div>`).join("")
      : `<p class="muted">no lab scenarios</p>`;
  } catch (err) { $("#lab-scenarios").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
}

async function runLabScenario(key) {
  try {
    const f = await api(`/api/security/lab/run/${key}`, { method: "POST" });
    $("#lab-scenarios").innerHTML = "";
    loadLab();
    await loadSecurity();
    const detail = $("#finding-detail");
    detail.innerHTML = `<div class="detail-section"><p><b>Lab scenario “${esc(key)}” created:</b> <code>${esc(f.finding_id)}</code> → status <b>${esc(f.status)}</b> · decision <b>${esc(f.decision)}</b> · verification <b>${esc(f.verification_status)}</b></p><p class="muted">${esc(f.recommended_solution)}</p></div>`;
  } catch (err) { alert(err.message); }
}

$("#btn-sec-refresh").addEventListener("click", loadFindingsTable);
["#sec-layer", "#sec-status", "#sec-severity"].forEach((sel) => $(sel).addEventListener("change", loadFindingsTable));
$("#sec-domain").addEventListener("change", loadFindingsTable);

// bootstrap
(async function init() {
  try {
    state.incidents = (await api("/api/incidents")).incidents;
  } catch (_) {}
  refresh();
})();