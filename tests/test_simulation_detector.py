from backend.services import simulation
from backend.services.detector import detect


def test_detector_emits_all_scenarios():
    simulation.reset_simulation()
    incidents = detect()
    types = {i.incident_type.value for i in incidents}
    assert types == {
        "high_cpu",
        "high_memory",
        "oom_killed",
        "crashloop_backoff",
        "certificate_expiry",
        "falco_security",
        "suspicious_rbac",
    }


def test_detector_incidents_have_resource_and_trigger():
    by_type = {i.incident_type.value: i for i in detect()}
    assert by_type["high_cpu"].resource == "cpu-demo"
    assert by_type["high_cpu"].trigger["source"] == "prometheus"
    assert by_type["crashloop_backoff"].resource == "crash-demo"
    assert by_type["falco_security"].trigger["source"] == "falco"
    assert by_type["suspicious_rbac"].trigger["source"] == "kubernetes-audit"


def test_simulation_scale_and_restart_are_stateful():
    simulation.reset_simulation()
    before = next(d for d in simulation.kube_deployments("ai-observability-demo") if d["name"] == "cpu-demo")
    assert before["replicas"] == 2
    simulation.simulate_scale("cpu-demo", desired=3, current=2)
    after = next(d for d in simulation.kube_deployments("ai-observability-demo") if d["name"] == "cpu-demo")
    assert after["replicas"] == 3
    assert any(p["deployment"] == "cpu-demo" for p in simulation.kube_pods("ai-observability-demo"))


def test_certificate_renew_updates_state():
    simulation.reset_simulation()
    status = simulation.certificate_status()
    assert status["days_remaining"] < 30
    assert status["chain_valid"] is True
    result = simulation.simulate_renew_certificate()
    assert result["days_remaining"] == 365.0
    assert simulation.certificate_status()["days_remaining"] >= 350