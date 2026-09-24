from backend.services import simulation, store
from backend.workflows.graph import reset_graphs


def test_health_and_status(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/api/status").json()
    comps = r["components"]
    assert "kubernetes" in comps
    assert "prometheus" in comps
    assert "llm" in comps
    assert "opensearch" in comps


def test_detect_creates_and_runs_incidents(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    r = client.post("/api/incidents/detect")
    assert r.status_code == 201
    body = r.json()
    assert body["count"] == 7
    pending = [i for i in body["detected"] if i["policy_decision"]["decision"] != "AUTO"]
    auto = [i for i in body["detected"] if i["policy_decision"]["decision"] == "AUTO"]
    assert len(auto) == 1
    assert auto[0]["incident_type"] == "high_cpu"
    assert auto[0]["status"] == "REMEDIATED"
    assert all(i["status"] == "AWAITING_APPROVAL" for i in pending)


def test_approval_via_api(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    client.post("/api/incidents/detect")
    pend = client.get("/api/approvals").json()
    assert pend["count"] == 6
    target = pend["approvals"][0]
    r = client.post(
        f"/api/incidents/{target['incident_id']}/approval",
        json={"decision": "approve", "approved_by": "tester"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "REMEDIATED"
    assert body["verification_status"] == "PASSED"


def test_reject_via_api(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    client.post("/api/incidents/detect")
    target = client.get("/api/approvals").json()["approvals"][1]
    r = client.post(
        f"/api/incidents/{target['incident_id']}/approval",
        json={"decision": "reject", "approved_by": "tester", "reason": "not a real problem"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "REJECTED"


def test_approving_non_pending_is_409(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    client.post("/api/incidents/detect")
    target = client.get("/api/approvals").json()["approvals"][0]
    client.post(f"/api/incidents/{target['incident_id']}/approval", json={"decision": "approve", "approved_by": "tester"})
    r = client.post(f"/api/incidents/{target['incident_id']}/approval", json={"decision": "approve", "approved_by": "tester"})
    assert r.status_code == 409


def test_mcp_tools_endpoints(client):
    tools = client.get("/api/mcp/tools").json()["tools"]
    assert len(tools) >= 15
    names = {t["name"] for t in tools}
    assert all(s in names for s in ("scale_deployment", "get_pods", "query_prometheus"))
    assert client.get("/api/mcp/no-unsafe-tools").json()["pass"] is True


def test_mcp_invoke_requires_namespace_optional(client):
    r = client.post("/api/mcp/invoke/get_pods", json={})
    assert r.status_code == 200
    assert r.json()["result"] == "ok"


def test_mcp_action_invoke_is_forbidden_without_workflow(client):
    r = client.post("/api/mcp/invoke/scale_deployment", json={"deployment": "cpu-demo", "desired_replicas": 3})
    assert r.status_code == 403


def test_knowledge_search_returns_sources(client):
    r = client.post("/api/knowledge/search", json={"query": "CrashLoopBackOff restart", "top_k": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] > 0
    docs = {s["document"] for s in body["sources"]}
    assert any("crashloopbackoff" in d or "runbooks" in d for d in docs)


def test_knowledge_db_info(client):
    r = client.get("/api/knowledge/db/info")
    assert r.status_code == 200
    info = r.json()
    assert "pgvector" in info["backends"]
    assert "opensearch" in info["backends"]
    assert "tfidf" in info["backends"]
    assert info["documents"] >= 0 and info["chunks"] >= 0
    assert isinstance(info["active"], list)


def test_knowledge_db_reindex(client):
    r = client.post("/api/knowledge/db/reindex")
    assert r.status_code == 200
    body = r.json()
    assert body["reindexed"] is True
    assert "tfidf" in body["summary"]
    assert body["info"]["chunks"] == body["summary"]["tfidf"]["chunks"]


def test_cluster_endpoint(client):
    c = client.get("/api/cluster").json()
    assert c["nodes"] and c["nodes"][0]["name"]
    assert c["pod_count"] >= 5
    assert c["deployments"]


def test_metrics_endpoint_exported(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    client.post("/api/incidents/detect")
    text = client.get("/metrics").text
    assert "app_incidents_detected_total" in text
    assert 'incident_type="high_cpu"' in text


def test_evaluation_stats_shape(client):
    stats = client.get("/api/evaluation/stats").json()
    for key in ("total_incidents", "autos", "approval_required", "approved", "rejected", "remediated", "verification_failed", "by_type", "detection_avg_ms", "resolution_avg_seconds"):
        assert key in stats


def test_workflow_pipeline_lists_twelve_nodes(client):
    nodes = client.get("/api/workflow/pipeline").json()["nodes"]
    assert nodes == [
        "classify", "collect_evidence", "correlate", "rag_retrieve", "diagnose",
        "assess_risk", "plan_remediation", "policy_check", "approval",
        "execute", "verify", "finalize",
    ]


def test_workflow_animate_unknown_incident_is_404(client):
    assert client.get("/api/workflow/animate/inc-99999").status_code == 404


def test_workflow_animate_topology_order(client):
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    client.post("/api/incidents/detect")
    incidents = client.get("/api/incidents").json()["incidents"]

    auto = next(i for i in incidents if i["incident_type"] == "high_cpu")
    d = client.get(f"/api/workflow/animate/{auto['incident_id']}").json()
    assert d["nodes"] == [
        "classify", "collect_evidence", "correlate", "rag_retrieve", "diagnose",
        "assess_risk", "plan_remediation", "policy_check", "execute", "verify", "finalize",
    ]
    step_nodes = [s["node"] for s in d["steps"]]
    assert "approval" not in step_nodes
    assert step_nodes.index("policy_check") < step_nodes.index("execute") < step_nodes.index("finalize")
    assert any(s["step"] == "mcp.scale_deployment" for s in d["steps"])

    pending = next(i for i in incidents if i["incident_type"] == "falco_security")
    d2 = client.get(f"/api/workflow/animate/{pending['incident_id']}").json()
    step_nodes2 = [s["node"] for s in d2["steps"]]
    assert step_nodes2.index("policy_check") < step_nodes2.index("approval")
    assert d2["steps"][-1]["step"] == "approval"
    assert d2["steps"][-1]["detail"].startswith("waiting")

    approve = client.post(
        f"/api/incidents/{pending['incident_id']}/approval",
        json={"decision": "approve", "approved_by": "tester"},
    )
    assert approve.status_code == 200
    d3 = client.get(f"/api/workflow/animate/{pending['incident_id']}").json()
    step_nodes3 = [s["node"] for s in d3["steps"]]
    assert step_nodes3.index("approval") < step_nodes3.index("finalize")
    assert d3["steps"][-1]["step"] == "finalize"
    assert d3["incident"]["status"] == "REMEDIATED"


def test_security_layers_and_stats(client):
    from backend.services import security

    security.reset_findings()
    r = client.get("/api/security/layers").json()
    assert r["total"] >= 7
    layer_names = {l["layer"] for l in r["layers"]}
    assert layer_names == {"application", "container", "node_cloud", "kubernetes_cluster"}
    s = client.get("/api/security/stats").json()
    assert s["by_severity"]["high"] > 0
    assert s["by_layer"]["kubernetes_cluster"]["total"] >= 1


def test_security_findings_list_and_detail(client):
    from backend.services import security

    security.reset_findings()
    body = client.get("/api/security/findings").json()
    assert body["count"] >= 7
    f = client.get(f"/api/security/findings/{body['findings'][0]['finding_id']}").json()
    for key in (
        "issue", "severity", "evidence", "affected_resource", "root_cause",
        "recommended_solution", "recommended_action", "remediation_status",
        "verification_status", "simulated",
    ):
        assert key in f
    assert f["simulated"] is True


def test_security_finding_decision_via_api(client):
    from backend.services import security

    security.reset_findings()
    pend = client.get("/api/security/pending").json()
    assert pend["count"] > 0
    target = pend["findings"][0]
    r = client.post(
        f"/api/security/findings/{target['finding_id']}/decision",
        json={"decision": "approve", "approved_by": "tester"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "REMEDIATED"
    assert r.json()["verification_status"] == "PASSED"


def test_security_finding_decision_conflict_is_409(client):
    from backend.services import security

    security.reset_findings()
    target = client.get("/api/security/pending").json()["findings"][0]
    client.post(
        f"/api/security/findings/{target['finding_id']}/decision",
        json={"decision": "approve", "approved_by": "tester"},
    )
    r = client.post(
        f"/api/security/findings/{target['finding_id']}/decision",
        json={"decision": "approve", "approved_by": "tester"},
    )
    assert r.status_code == 409


def test_security_finding_create_via_api(client):
    from backend.services import security

    security.reset_findings()
    r = client.post(
        "/api/security/findings",
        json={
            "title": "lab privileged pod",
            "issue": "privileged pod injected by lab",
            "severity": "high",
            "layer": "container",
            "domain": "Privileged",
            "affected_resource": "Pod/lab-x",
            "root_cause": "manifest",
            "recommended_solution": "drop flags",
            "recommended_action": "apply_security_config",
            "action_params": {"config": "drop-privileged", "target": "lab-x", "namespace": "ai-observability-demo"},
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["simulated"] is True
    assert body["approval_required"] is True


def test_mcp_has_apply_security_config_tool(client):
    names = {t["name"] for t in client.get("/api/mcp/tools").json()["tools"]}
    assert "apply_security_config" in names