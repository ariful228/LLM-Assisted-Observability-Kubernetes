import os
import sys

# Hermetic tests: always run against the simulated cluster / metric sources and
# the in-process TF-IDF RAG index, no matter whether the local stack (Prometheus,
# OpenSearch, pgvector, kind) happens to be up and reachable. These are set
# BEFORE any module imports Settings, so every get_settings() call sees them.
os.environ["EXTERNAL_MODE"] = "simulate"
os.environ["PROMETHEUS_URL"] = ""
os.environ["RAG_STORE"] = "tfidf"
os.environ["LANGFUSE_ENABLED"] = "false"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_environment():
    """Fresh simulated cluster + incident store for every test."""
    from backend.services import simulation, store
    from backend.workflows.graph import reset_graphs

    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    yield
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as c:
        yield c