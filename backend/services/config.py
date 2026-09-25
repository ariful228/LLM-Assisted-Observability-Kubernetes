"""Application configuration.

All secrets and endpoints are read from environment variables (see .env.example).
No secrets are ever hardcoded here.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "LLM-Assisted Observability for Kubernetes"
    environment: str = "demo"
    log_level: str = "INFO"

    # Runtime behaviour -------------------------------------------------
    # auto      -> use live integrations, fall back to simulation when unavailable
    # simulated -> never touch external systems, use the built-in simulation
    # live      -> require live integrations (fail closed otherwise)
    external_mode: str = "auto"

    data_dir: str = "data"
    knowledge_dir: str = "knowledge"
    cluster_name: str = "demo-cluster"
    namespace: str = "ai-observability-demo"
    timezone: str = "UTC"

    # Prometheus --------------------------------------------------------
    prometheus_url: str = ""

    # OpenSearch --------------------------------------------------------
    opensearch_url: str = ""
    opensearch_username: str = ""
    opensearch_password: str = ""
    opensearch_index_logs: str = "kubernetes-logs"
    opensearch_index_audit: str = "kubernetes-audit"
    opensearch_index_falco: str = "falco-events"
    opensearch_index_incidents: str = "ai-observability-incidents"

    # Kubernetes --------------------------------------------------------
    kubernetes_in_cluster: bool = False
    kubeconfig_path: str = ""

    # Grafana -----------------------------------------------------------
    grafana_url: str = ""

    # RAG knowledge store (managed locally like case-aiops)
    # auto      -> use whatever DB is reachable (pgvector → opensearch → tfidf)
    # pgvector  -> vector + tsvector hybrid, requires the local pgvector service
    # opensearch-> BM25 over knowledge-chunks index, requires local OpenSearch
    # tfidf     -> pure-python index over knowledge/**/*.md (always available)
    rag_store: str = "auto"
    pgvector_url: str = ""  # default: postgresql://rag:rag@localhost:5434/rag
    # optional local embedder, e.g. "ollama:nomic-embed-text"; "" -> built-in
    pgvector_embedding_model: str = ""
    opensearch_index_knowledge: str = "knowledge-chunks"

    # Slack (notification only) -----------------------------------------
    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_channel: str = ""

    # Langfuse ----------------------------------------------------------
    langfuse_host: str = ""
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_enabled: bool = False

    # LLM ---------------------------------------------------------------
    # mock (offline/demo), openai (OpenAI-compatible), ollama (local)
    llm_provider: str = "mock"
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 60.0
    llm_temperature: float = 0.2

    # Certificate monitoring --------------------------------------------
    cert_path: str = ""  # path to a PEM cert file to monitor (optional)

    # Policy / remediation safety ---------------------------------------
    # Namespaces the policy engine allows action on ("" = derived from settings.namespace)
    allowed_namespaces: list[str] = []
    # Deployments the policy engine allows scaling/restarting
    allowed_deployments: list[str] = []
    # Max replica delta for a single automatic scale action
    max_autoscale_delta: int = 3
    # Max replicas allowed as the result of an automatic scale action
    max_autoscale_replicas: int = 10
    # Default action timeout (seconds) for MCP action tools
    action_timeout_seconds: int = 30
    # ClusterRoleBindings the engine is allowed to roll back
    allowed_rbac_subjects: list[str] = []

    # Evaluation --------------------------------------------------------
    evaluation_collect: bool = True
    evaluation_export_dir: str = "data/evaluation"

    # Detection thresholds (mirrors the Grafana alert rules) ------------
    cpu_threshold_percent: float = 80.0
    cpu_sustain_minutes: int = 5
    memory_threshold_percent: float = 85.0
    cert_expiry_days_threshold: int = 7

    # Timeout resilience ------------------------------------------------
    default_timeout_seconds: float = 30.0

    # Frontend ----------------------------------------------------------
    frontend_dir: str = "frontend"
    frontend_base_url: str = "http://localhost:8199"

    def frontend_url(self, path: str = "") -> str:
        base = self.frontend_base_url.rstrip("/")
        return f"{base}/{path.lstrip('/')}"

    def allowed_namespace_list(self) -> list[str]:
        return list(self.allowed_namespaces) or [self.namespace, "default", "kube-system"]

    def pgvector_url_value(self) -> str:
        return self.pgvector_url or "postgresql://rag:rag@localhost:5434/rag"

    def allowed_deployment_list(self) -> list[str]:
        return list(self.allowed_deployments) or [
            "demo-app",
            "cpu-demo",
            "memory-demo",
            "crash-demo",
            "cert-demo",
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()