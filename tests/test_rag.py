from backend.services import rag


def _fresh_index():
    return rag.rebuild_index()


def test_index_loads_knowledge_docs():
    idx = _fresh_index()
    assert len(idx.chunks) > 0


def test_retrieval_returns_relevant_docs():
    idx = _fresh_index()
    hits = idx.search("how do I fix a CrashLoopBackOff workload restart")
    assert len(hits) >= 1
    assert any("crashloopbackoff" in h.document for h in hits)


def test_retrieval_cpu():
    idx = _fresh_index()
    hits = idx.search("cpu throttling scaling deployment replicas")
    assert len(hits) >= 1
    assert any("sustained-high-cpu" in h.document for h in hits)


def test_unrelated_query_returns_low_scores():
    idx = _fresh_index()
    hits = idx.search("zzzqx non-existent topic about pizza recipes")
    assert all(h.score < 20 for h in hits)


def test_rag_sources_attached_to_incident_workflow():
    from backend.services import simulation, store
    from backend.workflows.graph import reset_graphs, run_workflow
    from backend.models.incident import Incident, IncidentStatus, IncidentType, Severity

    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    s = store.get_store()
    inc = Incident(
        incident_id=s.next_incident_id(),
        incident_type=IncidentType.HIGH_CPU,
        severity=Severity.HIGH,
        status=IncidentStatus.DETECTED,
        resource="cpu-demo",
        classification="high cpu",
    )
    s.create(inc)
    done = run_workflow(inc.incident_id)
    assert len(done.rag_sources) >= 1
    assert any("sustained-high-cpu" in r.document for r in done.rag_sources)


def test_rag_sources_carry_backend_label():
    idx = _fresh_index()
    hits = idx.search("how do I fix a CrashLoopBackOff workload restart")
    assert len(hits) >= 1
    for h in hits:
        # the source of every hit is explicit — never a fabricated backend
        assert h.backend in {"tfidf", "pgvector", "opensearch"}
    assert any(h.backend == "tfidf" for h in hits)