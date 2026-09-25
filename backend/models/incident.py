"""Incident data model (see spec section 14).

Kept simple and extensible. Every field is JSON-serialisable.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_serializer


class IncidentType(str, Enum):
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    OOM_KILLED = "oom_killed"
    CRASH_LOOP_BACK_OFF = "crashloop_backoff"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    FALCO_SECURITY = "falco_security"
    SUSPICIOUS_RBAC = "suspicious_rbac"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    REMEDIATED = "REMEDIATED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    FAILED = "FAILED"
    NO_ACTION = "NO_ACTION"
    CLOSED = "CLOSED"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecisionType(str, Enum):
    AUTO = "AUTO"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    NO_ACTION = "NO_ACTION"
    BLOCKED = "BLOCKED"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class VerificationStatus(str, Enum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"


class MetricPoint(BaseModel):
    t: datetime
    v: float


class EvidenceItem(BaseModel):
    category: str = Field(description="e.g. prometheus, logs, events, audit, falco")
    source: str = Field(description="human/API readable provenance")
    summary: str = ""
    data: Optional[Any] = None
    collected_at: datetime = Field(default_factory=lambda: _utcnow())

    @field_serializer("collected_at")
    def _ser(self, v: datetime) -> str:
        return v.isoformat()


class TimelineEvent(BaseModel):
    ts: datetime
    step: str
    detail: str = ""

    @field_serializer("ts")
    def _ser(self, v: datetime) -> str:
        return v.isoformat()


class RagSource(BaseModel):
    document: str
    chunk: str
    excerpt: str
    score: float = 0.0
    backend: str = "tfidf"  # which RAG backend produced this hit (pgvector/opensearch/tfidf)


class Diagnosis(BaseModel):
    summary: str
    cause: str
    evidence_summary: str = ""
    recommended_action: str = ""
    here: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    expected_result: str = ""
    confidence: float = 0.0
    explanation: str = ""


class RecommendedAction(BaseModel):
    action: str = ""  # MCP action tool name
    params: dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    risk: RiskLevel = RiskLevel.LOW
    expected_result: str = ""
    reason: str = ""


class PolicyDecision(BaseModel):
    decision: PolicyDecisionType = PolicyDecisionType.NO_ACTION
    rule_id: str = ""
    reason: str = ""
    action: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)
    auto_allowed: bool = False
    made_by: str = "policy_engine"


class VerificationResult(BaseModel):
    status: VerificationStatus = VerificationStatus.PENDING
    checks: list[dict[str, Any]] = Field(default_factory=list)
    detail: str = ""


class ExecutionResult(BaseModel):
    status: ExecutionStatus = ExecutionStatus.PENDING
    tool: str = ""
    output: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    verification: Optional["VerificationResult"] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_serializer("started_at", "finished_at")
    def _ser(self, v: Optional[datetime]) -> Optional[str]:
        return v.isoformat() if v is not None else None


class Incident(BaseModel):
    incident_id: str
    incident_type: IncidentType = IncidentType.UNKNOWN
    severity: Severity = Severity.HIGH
    status: IncidentStatus = IncidentStatus.DETECTED

    cluster: str = ""
    namespace: str = ""
    resource: str = ""

    detected_at: datetime = Field(default_factory=lambda: _utcnow())

    trigger: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    metrics: dict[str, list[MetricPoint]] = Field(default_factory=dict)

    classification: str = ""
    rag_sources: list[RagSource] = Field(default_factory=list)
    diagnosis: Optional[Diagnosis] = None

    recommended_action: Optional[RecommendedAction] = None
    risk_level: RiskLevel = RiskLevel.LOW

    policy_decision: Optional[PolicyDecision] = None

    approval_required: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    approved_by: str = ""
    approved_at: Optional[datetime] = None
    approval_reason: str = ""

    execution_status: ExecutionStatus = ExecutionStatus.PENDING
    execution_result: Optional[ExecutionResult] = None

    verification_status: VerificationStatus = VerificationStatus.PENDING
    verification_result: Optional[VerificationResult] = None

    resolution_time_seconds: Optional[float] = None
    latency: dict[str, float] = Field(default_factory=dict)

    created_at: datetime = Field(default_factory=lambda: _utcnow())
    updated_at: datetime = Field(default_factory=lambda: _utcnow())

    @field_serializer("detected_at", "created_at", "updated_at", "approved_at")
    def _ser(self, v: Optional[datetime]) -> Optional[str]:
        return v.isoformat() if v is not None else None

    def add_to_timeline(self, step: str, detail: str = ""):
        self.timeline.append(TimelineEvent(ts=_utcnow(), step=step, detail=detail))

    def touch(self):
        self.updated_at = _utcnow()


def _utcnow():
    from backend.services.chrono import now

    return now()


# ---------------------------------------------------------------------------
# API helper schemas
# ---------------------------------------------------------------------------


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"]
    approved_by: str = "webui-user"
    reason: str = ""


class SimulateIncidentRequest(BaseModel):
    incident_type: IncidentType
    namespace: Optional[str] = None
    resource: Optional[str] = None
    severity: Optional[Severity] = None
    trigger_details: dict[str, Any] = Field(default_factory=dict)


class RagQueryRequest(BaseModel):
    query: str
    top_k: int = 4
    filters: list[str] = Field(default_factory=list)


class KnowledgeDoc(BaseModel):
    id: str
    path: str
    category: str
    title: str
    excerpt: str


# ---------------------------------------------------------------------------
# Security findings (coverage across the four layers)
# ---------------------------------------------------------------------------


class SecurityLayer(str, Enum):
    """Framing used for the four-layer security model."""

    APPLICATION = "application"
    CONTAINER = "container"
    NODE_CLOUD = "node_cloud"
    KUBERNETES_CLUSTER = "kubernetes_cluster"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    DETECTED = "DETECTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    REMEDIATED = "REMEDIATED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CLOSED = "CLOSED"


class SecurityFinding(BaseModel):
    """A security finding with the full per-finding structure (spec §9):

    Issue · Severity · Evidence · Affected Resource · Root Cause ·
    Recommended Solution · Auto/Approval Required · Remediation Status ·
    Verification Status. Simulated copies carry ``simulated=True``.
    """

    finding_id: str
    title: str
    issue: str
    severity: Severity = Severity.MEDIUM
    layer: SecurityLayer = SecurityLayer.APPLICATION
    status: FindingStatus = FindingStatus.OPEN

    domain: str = ""                # e.g. AppArmor, RBAC, Seccomp, NetworkPolicy
    evidence: list[EvidenceItem] = Field(default_factory=list)
    affected_resource: str = ""
    root_cause: str = ""
    recommended_solution: str = ""

    recommended_action: str = ""     # MCP action tool name
    action_params: dict[str, Any] = Field(default_factory=dict)
    decision: PolicyDecisionType = PolicyDecisionType.NO_ACTION
    approval_required: bool = False

    remediation_status: str = "not_started"   # not_started | in_progress | complete
    verification_status: VerificationStatus = VerificationStatus.PENDING
    verification_checks: list[dict[str, Any]] = Field(default_factory=list)

    simulated: bool = True
    source: str = "simulated-scan"

    timeline: list[TimelineEvent] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: _utcnow())
    created_at: datetime = Field(default_factory=lambda: _utcnow())
    updated_at: datetime = Field(default_factory=lambda: _utcnow())

    @field_serializer("detected_at", "created_at", "updated_at")
    def _ser(self, v: Optional[datetime]) -> Optional[str]:
        return v.isoformat() if v is not None else None

    def add_to_timeline(self, step: str, detail: str = ""):
        self.timeline.append(TimelineEvent(ts=_utcnow(), step=step, detail=detail))

    def touch(self):
        self.updated_at = _utcnow()


class SecurityFindingRequest(BaseModel):
    """Inject a finding (used by the Security Test Lab)."""

    title: str
    issue: str
    severity: Severity = Severity.MEDIUM
    layer: SecurityLayer = SecurityLayer.APPLICATION
    domain: str = ""
    affected_resource: str = ""
    root_cause: str = ""
    recommended_solution: str = ""
    recommended_action: str = ""
    action_params: dict[str, Any] = Field(default_factory=dict)


class FindingApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"]
    approved_by: str = "webui-user"
    reason: str = ""