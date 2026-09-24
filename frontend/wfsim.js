/* Workflow Simulator — replays an incident through the LangGraph pipeline with
 * moving animation. The token travels node to node; passed nodes stay "done",
 * the current node pulses; the console streams step text as evidence zips by.
 *
 * Sources of truth:
 *   backend/api/workflow.py -> /api/workflow/pipeline, /api/workflow/animate/{id}
 *   incident timeline events (ordered, mapped to nodes server-side)
 */

/* global api, esc */

const WorkflowSim = (() => {
  const MODES = {
    classify:        { label: "Classify",        sub: "type + severity" },
    collect_evidence: { label: "Collect Evidence", sub: "prometheus · k8s · falco · audit" },
    correlate:       { label: "Correlate",       sub: "cross-source timeline" },
    rag_retrieve:    { label: "RAG Retrieve",    sub: "pgvector + opensearch + tfidf" },
    diagnose:        { label: "Diagnose",        sub: "LLM proposal ↓" },
    assess_risk:     { label: "Assess Risk",     sub: "LLM risk rating" },
    plan_remediation:{ label: "Plan",            sub: "proposed action + params" },
    policy_check:    { label: "Policy Check",    sub: "authoritative (fail-closed)" },
    approval:        { label: "Human Approval",  sub: "Approve / Reject" },
    execute:         { label: "Execute",         sub: "validate → allowlist → policy → authorize → run → audit → verify" },
    verify:          { label: "Verify",          sub: "post-action checks" },
    finalize:        { label: "Finalize",        sub: "store + metrics + notify + langfuse trace" },
  };

  const DEMO_STEPS = [
    { node: "classify", step: "detected", detail: "high_cpu sustained on cpu-demo for 5m" },
    { node: "classify", step: "classified", detail: "high_cpu · severity=high · namespace=ai-observability-demo" },
    { node: "collect_evidence", step: "evidence_collected", detail: "8 items: prometheus cpu 88–96%, pod state, events" },
    { node: "correlate", step: "correlation_finished", detail: "cpu spike starts 3m before rollout events" },
    { node: "rag_retrieve", step: "rag", detail: "fused tfidf 1.0 · pgvector 1.2 · opensearch 1.1 → retrieved 3 chunks (sustained-high-cpu)" },
    { node: "diagnose", step: "diagnosis", detail: "load exceeds capacity; scale out recommended" },
    { node: "assess_risk", step: "risk_assessment", detail: "risk=low · confidence=0.87" },
    { node: "plan_remediation", step: "remediation_planned", detail: "scale_deployment cpu-demo 2→3" },
    { node: "policy_check", step: "policy", detail: "AUTO · rule=P-01 · allowlist OK · delta=1" },
    { node: "execute", step: "mcp.scale_deployment", detail: "validated → authorized → executed → audit logged" },
    { node: "verify", step: "verify", detail: "availableReplicas=3 · all Ready · PASSED" },
    { node: "finalize", step: "finalize", detail: "REMEDIATED · latency 412ms · traced in Langfuse (local :3000)" },
  ];

  const state = {
    inited: false,
    incidents: [],
    incidentId: null,
    nodes: [],
    steps: [],
    idx: 0,
    playing: false,
    timer: null,
    speed: 450,
    fetched: null, // {incident, nodes, steps}
  };

  const $ = (s) => document.querySelector(s);

  function el(tag, cls, html) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html !== undefined) n.innerHTML = html;
    return n;
  }

  function init() {
    if (state.inited) return;
    state.inited = true;
    $("#wf-play").addEventListener("click", play);
    $("#wf-pause").addEventListener("click", pause);
    $("#wf-reset").addEventListener("click", reset);
    $("#wf-incident").addEventListener("change", () => { loadData($("#wf-incident").value); });
    $("#wf-speed").addEventListener("change", () => { state.speed = Number($("#wf-speed").value); });
    const track = $("#wf-track");
    track.appendChild($("#wf-token"));
  }

  async function refresh() {
    init();
    try {
      const r = await api("/api/incidents");
      state.incidents = r.incidents || [];
    } catch (err) { state.incidents = []; }

    const sel = $("#wf-incident");
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(new Option("Built-in demo (no incidents needed)", "__demo__"));
    state.incidents.forEach((i) => {
      sel.appendChild(new Option(`${i.incident_id} · ${i.incident_type} · ${i.status}`, i.incident_id));
    });
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
    else if (state.incidents.length) sel.value = state.incidents[0].incident_id;
    else sel.value = "__demo__";

    $("#wf-empty").classList.toggle("visible", state.incidents.length === 0);
    reset();
  }

  function reset() {
    pause();
    loadData($("#wf-incident").value);
  }

  async function loadData(incidentId) {
    state.playing = false;
    $("#wf-token").classList.add("hidden");
    if (!incidentId || incidentId === "__demo__") {
      state.fetched = { incident: null, nodes: DEMO_STEPS.map((s) => s.node), steps: DEMO_STEPS };
    } else {
      try {
        const d = await api(`/api/workflow/animate/${encodeURIComponent(incidentId)}`);
        state.fetched = d;
      } catch (err) {
        state.fetched = { incident: null, nodes: DEMO_STEPS.map((s) => s.node), steps: DEMO_STEPS };
      }
    }
    const { incident, nodes, steps } = state.fetched;
    if (nodes && nodes.length >= 2) {
      state.nodes = nodes;
      state.steps = steps;
      state.incidentId = incidentId;
      renderTrack(nodes);
      renderSummary(incident);
      $("#wf-log").innerHTML = "";
      state.idx = 0;
      play();
    }
  }

  function renderTrack(nodes) {
    const track = $("#wf-track");
    track.innerHTML = "";
    nodes.forEach((node, i) => {
      const n = el("div", "wf-node", "");
      n.dataset.node = node;
      const m = MODES[node] || { label: node, sub: "" };
      n.appendChild(el("div", "box", `${esc(m.label)}<small>${esc(m.sub || node)}</small>`));
      track.appendChild(n);
      if (i < nodes.length - 1) track.appendChild(el("div", "wf-arrow"));
    });
  }

  function renderSummary(incident) {
    const s = $("#wf-summary");
    if (!incident) {
      s.innerHTML = `<div class="k">Demo incident</div>
        <div class="verdict ok">high_cpu → AUTO → REMEDIATED</div>
        <p>Replay of scenario #1: sustained high CPU is the only policy-approved AUTO action (P-01).</p>`;
      return;
    }
    const pd = incident.policy_decision || {};
    const ra = incident.recommended_action || {};
    const okStatus = incident.status === "REMEDIATED" || incident.status === "CLOSED";
    const verdictCls = okStatus ? "ok" : "bad";
    s.innerHTML = `
      <div class="k">${esc(incident.incident_id)} · ${esc(incident.incident_type)}</div>
      <div class="verdict ${verdictCls}">${esc(incident.status)}</div>
      <table class="table">
        <tr><td class="k">Severity / Risk</td><td>${esc(incident.severity)} / ${esc(incident.risk_level || "-")}</td></tr>
        <tr><td class="k">Resource</td><td>${esc(incident.namespace)}/${esc(incident.resource || "-")}</td></tr>
        <tr><td class="k">Policy</td><td>${esc(pd.decision || "-")} · ${esc(pd.rule_id || "")}</td></tr>
        <tr><td class="k">Action</td><td>${esc((ra.action || "-"))}</td></tr>
        <tr><td class="k">Execution</td><td>${esc(incident.execution_status)}</td></tr>
        <tr><td class="k">Verification</td><td>${esc(incident.verification_status)}</td></tr>
        <tr><td class="k">Approval</td><td>${esc(incident.approval_status)}${incident.approved_by ? " by " + esc(incident.approved_by) : ""}</td></tr>
        <tr><td class="k">RAG sources</td><td>${(incident.rag_sources || []).length}</td></tr>
      </table>
      <p class="muted">${esc(pd.reason || "")}</p>`;
  }

  function play() {
    if (state.playing) return;
    if (!state.steps.length) return;
    state.playing = true;
    step();
  }

  function step() {
    if (!state.playing) return;
    if (state.idx >= state.steps.length) {
      state.playing = false;
      return;
    }
    const stepData = state.steps[state.idx];
    const nodeIdx = state.nodes.indexOf(stepData.node);
    activate(nodeIdx, stepData);
    logLine(stepData);
    if (state.idx >= state.steps.length - 1) state.playing = false;
    else state.timer = setTimeout(step, state.speed);
  }

  function pause() {
    state.playing = false;
    clearTimeout(state.timer);
  }

  function activate(nodeIdx, stepData) {
    const nodes = [...$("#wf-track").querySelectorAll(".wf-node")];
    nodes.forEach((n, i) => {
      n.classList.toggle("done", i < nodeIdx);
      n.classList.toggle("active", i === nodeIdx);
      n.classList.toggle("denied", i === nodeIdx && stepData.node === "approval" && /reject/i.test(stepData.step || stepData.detail || ""));
    });
    const arrows = $("#wf-track").querySelectorAll(".wf-arrow");
    arrows.forEach((a, i) => a.classList.toggle("lit", i < nodeIdx));
    if (nodeIdx >= 0) moveTokenTo(nodes[nodeIdx]);
  }

  function moveTokenTo(nodeEl) {
    const track = $("#wf-track");
    const token = $("#wf-token");
    const tr = track.getBoundingClientRect();
    const nr = nodeEl.getBoundingClientRect();
    const cx = nr.left + nr.width / 2 - tr.left;
    const cy = nr.top + nr.height / 2 - tr.top;
    token.style.left = `${cx - 7}px`;
    token.style.top = `${cy - 7}px`;
    token.classList.remove("hidden");
  }

  function logLine(stepData) {
    const log = $("#wf-log");
    const line = el("div", "log-line");
    const m = MODES[stepData.node] || { label: stepData.node };
    line.innerHTML = `<span class="node-tag">${esc(m.label)}</span> ${esc(stepData.step || "")} — ${esc(stepData.detail || "")}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  return { init, refresh };
})();