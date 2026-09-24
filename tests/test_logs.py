from backend.services import simulation
from backend.services.opensearch import get_opensearch


def test_log_facets_populated(client):
    simulation.reset_simulation()
    facets = client.get("/api/logs/facets").json()
    assert facets["index"] == "kubernetes-logs"
    for key in ("namespaces", "pods", "containers", "levels"):
        assert facets[key], f"expected at least one {key}"
    assert "ai-observability-demo" in facets["namespaces"]
    assert "INFO" in facets["levels"]


def test_logs_query_returns_hits(client):
    simulation.reset_simulation()
    body = client.get("/api/logs", params={"size": 20}).json()
    assert body["count"] >= 5
    assert body["index"] == "kubernetes-logs"
    first = body["hits"][0]
    for key in ("timestamp", "namespace", "pod", "container", "level", "message"):
        assert key in first


def test_logs_filter_by_level_and_keyword(client):
    simulation.reset_simulation()
    err = client.get("/api/logs", params={"level": "ERROR"}).json()
    assert err["count"] > 0
    assert all(h["level"].upper() == "ERROR" for h in err["hits"])

    kw = client.get("/api/logs", params={"keyword": "config file not found"}).json()
    assert kw["count"] > 0
    assert all("config file not found" in (h["message"] or "") for h in kw["hits"])


def test_logs_filter_by_namespace_and_unknown_pod(client):
    simulation.reset_simulation()
    ns = client.get("/api/logs", params={"namespace": "ai-observability-demo"}).json()
    assert ns["count"] > 0
    none = client.get("/api/logs", params={"pod": "does-not-exist"}).json()
    assert none["count"] == 0 and none["hits"] == []


def test_simulated_logs_reflect_restart():
    from backend.services import kube

    simulation.reset_simulation()
    os = get_opensearch()
    before = os.query_logs(pod=None, size=500)
    assert any("CrashLoopBackOff" in e.get("message", "") for e in before)
    assert any("OOMKilled" in e.get("message", "") for e in before)

    simulation.simulate_restart()
    after = os.query_logs(pod=None, size=500)
    assert not any("CrashLoopBackOff" in e.get("message", "") for e in after)
    assert not any("OOMKilled" in e.get("message", "") for e in after)
    assert any("healthcheck passed" in e.get("message", "") for e in after)