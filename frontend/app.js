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
  if (view === "dashboard") {
    window.scrollTo({ top: 0 });
    refresh();
  }
  if (view === "workflow") typeof WorkflowSim !== "undefined" && WorkflowSim.refresh();
  if (view === "incidents") loadIncidents();
  if (view === "security") loadSecurity();
  if (view === "approvals") loadApprovals();
  if (view === "tools") loadTools();
  if (view === "knowledge") loadKnowledge();
  if (view === "logs") loadLogs();
  if (view === "status") loadStatus();
}

// ---------- dashboard category nav ----------
document.querySelectorAll("#cat-nav a").forEach((link) => {
  link.addEventListener("click", (e) => {
    const id = link.getAttribute("href").slice(1);
    const target = document.getElementById(id);
    if (!target) return;
    e.preventDefault();
    target.scrollIntoView({ behavior: "smooth", block: "start" });
    document.querySelectorAll("#cat-nav a").forEach((a) => a.classList.toggle("active", a === link));
  });
});

// ---------- shared ----------
async function loadMode() {
  try { const s = await api("/api/status"); $("#mode-pill").textContent = s.components.kubernetes.mode || "n/a"; } catch (_) {}
}

function severityTag(sev) {
  const c = ({ critical: "critical", high: "high", medium: "medium", low: "low" })[sev] || "low";
  return `<span class="tag ${c}">${esc(sev)}</span>`;
}

// ---------- dashboard ----------
// Incident types grouped by dashboard category.
const SEC_TYPES = new Set(["falco_security", "suspicious_rbac"]);
const UTIL_TYPES = new Set(["high_cpu", "high_memory", "oom_killed"]);

const SIM_BASE = "/static/simulator.html";

const SIM_STAGES = [
  { key: "preflight", n: 1, icon: "🧰", label: "Preflight & local stack" },
  { key: "kube", n: 2, icon: "🧊", label: "Local kind cluster" },
  { key: "seed", n: 3, icon: "🌱", label: "RAG knowledge seed" },
  { key: "detect", n: 4, icon: "📡", label: "Detection & ingest" },
  { key: "investigate", n: 5, icon: "🕵️", label: "LangGraph investigate" },
  { key: "rag", n: 6, icon: "🔎", label: "RAG retrieve + diagnose" },
  { key: "policy", n: 7, icon: "🛡", label: "Plan + policy gate" },
  { key: "approval", n: 8, icon: "⚖", label: "Human approval" },
  { key: "execute", n: 9, icon: "🛠", label: "MCP execute + verify" },
  { key: "finalize", n: 10, icon: "🏁", label: "Finalize & trace" },
];

const SIM_MAPS = [
  { id: "stack", icon: "🧱", label: "Local stack" },
  { id: "langmap", icon: "🕸", label: "LangGraph pipeline" },
  { id: "rag", icon: "🔎", label: "Fused RAG" },
  { id: "gates", icon: "🛡", label: "Policy & approval gates" },
  { id: "mcp", icon: "🛠", label: "MCP execution" },
  { id: "scenarios", icon: "📚", label: "Scenario registry" },
  { id: "detectflow", icon: "📡", label: "Detection flow" },
  { id: "tech", icon: "🧰", label: "Technology inventory" },
  { id: "llm", icon: "🤖", label: "Where the LLM is used" },
];

const STACK_LINKS = {
  prometheus: "http://localhost:9090",
  grafana: "http://localhost:3001",
  opensearch: "http://localhost:9200",
  langfuse: "http://localhost:3000",
  kubernetes: null,
};

function simStageHref(key) { return `${SIM_BASE}#stage=${key}`; }
function simMapHref(id) { return `${SIM_BASE}#${id}`; }

function renderSimulatorLinks() {
  $("#sim-stages").innerHTML = SIM_STAGES.map(
    (s) => `<a class="sim-link" href="${simStageHref(s.key)}" target="_blank">
      <span class="sim-n">${String(s.n).padStart(2, "0")}</span>
      <span class="sim-ico">${s.icon}</span>
      <span class="sim-lbl">${esc(s.label)}</span>
      <span class="sim-go">↗</span>
    </a>`
  ).join("");
  $("#sim-maps").innerHTML = SIM_MAPS.map(
    (m) => `<a class="sim-link sim-link-map" href="${simMapHref(m.id)}" target="_blank">
      <span class="sim-ico">${m.icon}</span>
      <span class="sim-lbl">${esc(m.label)}</span>
      <span class="sim-go">↗</span>
    </a>`
  ).join("");
}

function bar(value, max, tone) {
  const pct = Math.max(0, Math.min(100, (value / (max || 1)) * 100));
  return `<div class="bar"><i class="bar-fill ${tone}" style="width:${pct.toFixed(1)}%"></i></div>`;
}

function pctTone(v, warn, crit) {
  if (v == null) return "";
  if (v >= crit) return "tone-danger";
  if (v >= warn) return "tone-warn";
  return "tone-ok";
}

async function refresh() {
  await loadMode();
  const [incs, stats, secStats, secFindings, cluster, util, status] = await Promise.all([
    api("/api/incidents"),
    api("/api/evaluation/stats"),
    api("/api/security/stats").catch(() => null),
    api("/api/security/findings").catch(() => null),
    api("/api/cluster").catch(() => null),
    api("/api/utilization").catch(() => null),
    api("/api/status").catch(() => null),
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
    ["🧰", "Total Incidents", stats.total_incidents, ""],
    ["🔥", "Active", open.length, "tone-danger"],
    ["⚖", "Pending Approvals", pending.length, "tone-warn"],
    ["🤖", "Auto Remediated", stats.autos, "tone-ok"],
    ["👤", "Human Approved", stats.approved, "tone-ok"],
    ["🧠", "AI Investigations", ai.length, "tone-violet"],
    ["❌", "Verification Failed", stats.verification_failed, "tone-danger"],
  ];
  $("#dashboard-cards").innerHTML = cards
    .map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`)
    .join("");

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

  renderDashSecurity(secStats, secFindings, all);
  renderDashUtilization(util, all);
  renderDashOs(secFindings, all, cluster);
  renderDashCluster(cluster);
  renderDashVerification(stats, all, verified, failed);
  renderDashStack(status);
  renderSimulatorLinks();
}

function renderDashSecurity(secStats, secFindings, incidents) {
  const target = $("#dash-security");
  if (!secStats) { target.innerHTML = `<p class="muted">security unavailable</p>`; return; }
  const s = secStats;
  const waiting = s.by_status && (s.by_status.AWAITING_APPROVAL || 0);
  const remediated = s.by_status && (s.by_status.REMEDIATED || 0);
  const failed = s.by_status && (s.by_status.VERIFICATION_FAILED || 0);
  const secIncidents = incidents.filter((i) => SEC_TYPES.has(i.incident_type)).length;
  const cards = [
    ["🛡", "Findings", s.total, "tone-violet"],
    ["⛔", "Critical", s.by_severity.critical || 0, "tone-danger"],
    ["⚠️", "High", s.by_severity.high || 0, "tone-warn"],
    ["✅", "Remediated", remediated, "tone-ok"],
    ["⏳", "Awaiting approval", waiting, "tone-warn"],
    ["🧪", "Security incidents", secIncidents, "tone-violet"],
    ["❌", "Verification failed", failed, failed ? "tone-danger" : "tone-ok"],
  ];
  target.innerHTML = cards.map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`).join("");

  const layers = (s.by_layer || {});
  const layerTotal = Object.values(layers).reduce((a, b) => a + (b.total || 0), 0) || 1;
  $("#dash-sec-layers").innerHTML = Object.entries(layers).map(([name, info]) => {
    const tone = info.critical ? "tone-danger" : info.high ? "tone-warn" : "tone-ok";
    return `<div class="bar-row">
      <div class="bar-row-head">${layerTag(name)}<span class="muted">${info.total} finding${info.total === 1 ? "" : "s"}</span></div>
      ${bar(info.total, layerTotal, tone)}
      <div class="bar-row-foot muted">${info.critical || 0} critical · ${info.high || 0} high · ${info.remediated || 0} remediated</div>
    </div>`;
  }).join("") || `<p class="muted">no layers reported</p>`;

  const counts = {};
  for (const f of secFindings.findings || []) {
    const d = f.domain || "unspecified";
    counts[d] = (counts[d] || 0) + 1;
  }
  const domains = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  $("#dash-sec-domains").innerHTML = domains.length
    ? domains.map(([d, n]) => `<div class="chip-row"><span class="chip-static">${esc(d)}</span><b>${n}</b></div>`).join("")
    : `<p class="muted">no domains reported</p>`;

  const openFindings = (secFindings.findings || []).filter(
    (f) => !["REMEDIATED", "CLOSED"].includes(f.status)
  );
  $("#dash-sec-open").innerHTML = openFindings.length
    ? openFindings.slice(0, 6).map((f) => findingEvent(f)).join("")
    : `<p class="muted">no open findings</p>`;
  renderDashSecEvents(secFindings);
}

function findingEvent(f) {
  return `<div class="sec-event ${esc(f.severity)}">
    <div class="se-row">
      ${layerTag(f.layer)} ${severityTag(f.severity)} ${statusTag(f.status)}
      <span class="se-time">${new Date(f.detected_at).toLocaleString()}</span>
    </div>
    <div class="se-msg">${esc(f.title)}</div>
    <div class="se-sub"><code>${esc(f.recommended_action || "-")}</code> · verify ${esc(f.verification_status)}</div>
  </div>`;
}

function renderDashSecEvents(secFindings) {
  const target = $("#dash-sec-events");
  if (!secFindings) { target.innerHTML = `<p class="muted">security unavailable</p>`; return; }
  const list = (secFindings.findings || []).slice(0, 6);
  target.innerHTML = list.length
    ? list.map((f) => `
      <div class="sec-event ${esc(f.severity)}">
        <div class="se-row">
          ${layerTag(f.layer)} ${severityTag(f.severity)} ${statusTag(f.status)} ${f.simulated ? `<span class="tag sim">SIM</span>` : ""}
          <span class="se-time">${new Date(f.detected_at).toLocaleString()}</span>
        </div>
        <div class="se-msg">${esc(f.title)}</div>
        <div class="se-sub"><code>${esc(f.recommended_action || "-")}</code> · verify ${esc(f.verification_status)}</div>
      </div>`).join("")
    : `<p class="muted">no security events</p>`;
}

function renderDashUtilization(util, incidents) {
  const utilIncidents = incidents.filter((i) => UTIL_TYPES.has(i.incident_type));
  const cpuN = utilIncidents.filter((i) => i.incident_type === "high_cpu").length;
  const memN = utilIncidents.filter((i) => i.incident_type !== "high_cpu").length;
  const scaled = incidents.filter((i) => (i.policy_decision || {}).action === "scale_deployment").length;
  const cpuAvg = util ? util.cpu_percent_avg : null;
  const memAvg = util ? util.memory_percent_avg : null;

  const cards = [
    ["🔥", "CPU pressure", cpuAvg == null ? "—" : `${cpuAvg}%`, pctTone(cpuAvg, 70, 85)],
    ["🧠", "Memory pressure", memAvg == null ? "—" : `${memAvg}%`, pctTone(memAvg, 70, 85)],
    ["⏱", "CPU incidents", cpuN, cpuN ? "tone-warn" : "tone-ok"],
    ["💥", "Memory / OOM incidents", memN, memN ? "tone-danger" : "tone-ok"],
    ["📈", "Auto-scaled", scaled, scaled ? "tone-ok" : ""],
    ["🎯", "CPU above threshold", util ? util.cpu_pressure : 0, util && util.cpu_pressure ? "tone-warn" : "tone-ok"],
    ["🧯", "Memory above threshold", util ? util.memory_pressure : 0, util && util.memory_pressure ? "tone-warn" : "tone-ok"],
  ];
  $("#dash-utilization").innerHTML = cards
    .map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`)
    .join("");

  const items = (util && util.items) || [];
  $("#dash-util-bars").innerHTML = items.length
    ? items.map((it) => `
      <div class="bar-row">
        <div class="bar-row-head"><b>${esc(it.deployment)}</b><span class="muted">cpu ${fmtPct(it.cpu_percent)} · mem ${fmtPct(it.memory_percent)}</span></div>
        ${bar(it.cpu_percent || 0, 100, pctTone(it.cpu_percent, 70, 85))}
        ${bar(it.memory_percent || 0, 100, pctTone(it.memory_percent, 70, 85))}
      </div>`).join("") +
      `<p class="muted" style="margin-top:8px">metrics: ${util.source} · ${esc(util.namespace)}</p>`
    : `<p class="muted">utilization metrics unavailable</p>`;

  $("#dash-util-workloads").innerHTML = items.length
    ? items.map((it) => {
      const converged = it.replicas === it.available;
      return `<div class="sec-event ${converged ? "" : "high"}">
        <div class="se-row"><b>${esc(it.deployment)}</b>
          <span class="tag ${converged ? "low" : "high"}">${it.ready}/${it.available} ready</span>
          <span class="se-time">${it.replicas} replica${it.replicas === 1 ? "" : "s"}</span>
        </div>
        <div class="se-sub">cpu ${fmtPct(it.cpu_percent)} · memory ${fmtPct(it.memory_percent)}</div>
      </div>`;
    }).join("")
    : `<p class="muted">no workloads reported</p>`;
}

function fmtPct(v) {
  return v == null ? "—" : `${v}%`;
}

function renderDashOs(secFindings, incidents, cluster) {
  const findings = ((secFindings && secFindings.findings) || []).filter((f) => f.layer === "node_cloud");
  const certIncidents = incidents.filter((i) => i.incident_type === "certificate_expiry");
  const certRemediated = certIncidents.filter((i) => i.verification_status === "PASSED").length;
  const nodes = (cluster && cluster.nodes) || [];
  const hardened = findings.filter((f) => ["REMEDIATED", "CLOSED"].includes(f.status)).length;

  const cards = [
    ["🖥", "Nodes", nodes.length, nodes.length ? "tone-ok" : "tone-warn"],
    ["🛡", "Node / OS findings", findings.length, findings.length ? "tone-warn" : "tone-ok"],
    ["✅", "Hardened", hardened, "tone-ok"],
    ["🔐", "Cert expiries", certIncidents.length, certIncidents.length ? "tone-warn" : "tone-ok"],
    ["📜", "Certs renewed", certRemediated, "tone-ok"],
    ["🐧", "Kubelet hardening", findings.filter((f) => f.domain === "Kubelet").length, ""],
    ["⏳", "Awaiting approval", findings.filter((f) => f.status === "AWAITING_APPROVAL").length, "tone-warn"],
  ];
  $("#dash-os").innerHTML = cards
    .map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`)
    .join("");

  $("#dash-os-nodes").innerHTML = nodes.length
    ? nodes.map((n) => `<div class="sec-event ${n.status === "Ready" ? "" : "high"}">
        <div class="se-row"><b>${esc(n.name)}</b>
          <span class="tag ${n.status === "Ready" ? "low" : "high"}">${esc(n.status)}</span>
          <span class="se-time">${esc(n.role || "worker")}</span>
        </div>
      </div>`).join("")
    : `<p class="muted">no nodes reported</p>`;

  $("#dash-os-findings").innerHTML = findings.length
    ? findings.slice(0, 6).map((f) => findingEvent(f)).join("")
    : `<p class="muted">no node/OS findings</p>`;
}

function renderDashCluster(cluster) {
  const target = $("#dash-cluster-cards");
  if (!cluster || cluster.error) {
    target.innerHTML = `<p class="muted">cluster unavailable</p>`;
    $("#cluster-overview").innerHTML = `<p class="muted">${esc((cluster && cluster.error) || "unavailable")}</p>`;
    return;
  }
  const single = cluster.nodes.length === 1;
  const desired = cluster.deployments.reduce((a, d) => a + (d.replicas || 0), 0);
  const available = cluster.deployments.reduce((a, d) => a + (d.available || 0), 0);
  const restarts = (cluster.pods || []).reduce((a, p) => a + (p.restarts || 0), 0);
  const cards = [
    ["🧊", "Nodes", cluster.nodes.length, "tone-ok"],
    ["📦", "Pods", cluster.pod_count, ""],
    ["▶️", "Running", cluster.running_pods, "tone-ok"],
    ["❗", "Not healthy", cluster.failed_pods, cluster.failed_pods ? "tone-danger" : "tone-ok"],
    ["🎚", "Replicas ready", `${available}/${desired}`, available === desired ? "tone-ok" : "tone-warn"],
    ["🔁", "Container restarts", restarts, restarts ? "tone-warn" : "tone-ok"],
    ["🛰", "Mode", cluster.mode, "tone-violet"],
  ];
  target.innerHTML = cards
    .map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`)
    .join("");

  $("#cluster-overview").innerHTML = `
    <div style="overflow-x:auto"><table class="table"><thead><tr><th>Deployment</th><th>Replicas</th><th>Ready</th><th>Available</th><th>Image</th></tr></thead>
      <tbody>${cluster.deployments.map((d) => `<tr>
        <td>${esc(d.name)}</td>
        <td>${d.replicas}</td>
        <td>${d.ready}</td>
        <td>${d.available}</td>
        <td class="muted">${esc(d.image || "-")}</td>
      </tr>`).join("")}</tbody></table></div>
    <div class="note-block">
      🧊 <b>kind cluster “ai-observability-local”</b> runs as a single node
      (<code>kubernetes/kind/kind-cluster.yaml</code>${single ? " — one control-plane, no workers" : ` — ${cluster.nodes.length} nodes`}).
      Add worker lines to that file to make it multi-node.
    </div>`;
}

function renderDashVerification(stats, all, verified, failed) {
  const target = $("#dash-verification");
  const auto = stats.autos || 0;
  const approved = stats.approved || 0;
  const rejected = stats.rejected || 0;
  const cards = [
    ["🤖", "Auto Remediations", auto, "tone-ok"],
    ["👤", "Human Approved", approved, "tone-ok"],
    ["🚫", "Rejected", rejected, rejected ? "tone-danger" : ""],
    ["✅", "Incidents Verified (PASSED)", verified, "tone-ok"],
    ["❌", "Verification Failed", failed, failed ? "tone-danger" : "tone-ok"],
    ["⏳", "Open (awaiting / failed)", all.filter((i) => i.status === "AWAITING_APPROVAL" || i.status === "VERIFICATION_FAILED").length, "tone-warn"],
  ];
  target.innerHTML = cards.map(([ic, l, v, tone]) => `<div class="card ${tone}"><div class="ico">${ic}</div><div class="value">${v}</div><div class="label">${l}</div></div>`).join("");
}

function renderDashStack(status) {
  const target = $("#dash-stack");
  const comps = (status && status.components) || {};
  target.innerHTML = Object.entries(comps).map(([name, c]) => {
    const up = c.available;
    const dot = c.configured ? (up ? "" : " off") : " warn";
    const link = STACK_LINKS[name];
    const label = link
      ? `<a href="${link}" target="_blank" rel="noopener">${esc(name)} ↗</a>`
      : esc(name);
    const detail = [
      c.configured ? "configured" : "not configured",
      c.available ? "available" : "unavailable",
      c.mode ? c.mode : "",
      c.provider ? c.provider : "",
    ].filter(Boolean).join(" · ");
    return `<div class="status-comp"><span class="dot${dot}"></span>
      <div><b>${label}</b><br/><span class="muted">${esc(detail)}</span></div></div>`;
  }).join("") || `<p class="muted">status unavailable</p>`;
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