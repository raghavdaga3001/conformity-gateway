import os
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field

from app.agent.state import ConformityAgentState, SecurityFlags
from app.agent.graph import conformity_agent
from app.gateway.sanitizers import IngressSanitizer
from app.gateway.canary import CanarySentinel
from app.gateway.ood_filter import LatentOODFilter
from app.telemetry.audit_logger import ComplianceAuditLogger
from app.telemetry.drift_monitor import StatisticalDriftMonitor
from app.database.vector_store import vector_store

# Shared runtime singletons
ood_filter = LatentOODFilter(ridge_epsilon=1e-3)
audit_logger = ComplianceAuditLogger(log_path="audit_records.jsonl")
drift_monitor = StatisticalDriftMonitor()

ENTERPRISE_ID_CORPUS = [
    "What are the capital reserve requirements for retail banking?",
    "Explain Swiss FINMA liquidity ratio circular guidelines.",
    "How do credit lines get authorized for institutional clients?",
    "Details on corporate debt rebalancing policies and limits.",
    "Corporate governance procedures for high-risk lending decisions.",
    "What is the statutory requirement for counterparty liquidity?",
    "UK regulatory capital reserve requirement is strictly 12.5%.",
    "Credit line override requires dual-officer sign-off under risk policies."
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm latent OOD covariance matrix on enterprise baseline
    ood_filter.fit_in_distribution(ENTERPRISE_ID_CORPUS)
    drift_monitor.register_baseline("ood_distance", [14.2, 16.1, 15.8, 14.9, 17.0, 15.3, 16.5])
    
    # Pre-seed sample vectors if database is empty
    vector_store.seed_initial_enterprise_records([
        {"content": "UK regulatory capital reserve requirement is strictly 12.5%.", "tenant_id": "tenant_uk"},
        {"content": "Swiss liquidity ratio under FINMA circular 2023 is 100%.", "tenant_id": "tenant_swiss"},
        {"content": "Frankfurt corporate compliance mandates non-root container executions.", "tenant_id": "tenant_eu"}
    ])
    yield

app = FastAPI(
    title="Conformity-Gateway",
    version="1.0.0",
    description="High-Assurance AI Gateway conforming to EU AI Act Articles 12 & 15",
    lifespan=lifespan
)

# ---------------------------------------------------------------------------
# API Schemas
# ---------------------------------------------------------------------------

class InferenceRequest(BaseModel):
    query: str = Field(..., example="What is the capital reserve ratio?")
    tenant_id: str = Field(..., example="tenant_uk")

class InferenceResponse(BaseModel):
    response: str
    tenant_id: str
    user_id: str
    ood_score: float
    circuit_breaker_tripped: bool
    audit_digest: str
    execution_trace: List[Dict[str, Any]]

# ---------------------------------------------------------------------------
# Mock Session Authentication Middleware (Simulates Verified JWT Claims)
# ---------------------------------------------------------------------------

def get_current_user_claims(
    x_user_id: Optional[str] = Header(default="analyst_default_99"),
    x_user_role: Optional[str] = Header(default="compliance_officer")
) -> Dict[str, str]:
    return {"user_id": x_user_id, "user_role": x_user_role}

# ---------------------------------------------------------------------------
# Protected Gateway Route
# ---------------------------------------------------------------------------

@app.post("/v1/chat/conformity", response_model=InferenceResponse)
async def process_governed_query(
    payload: InferenceRequest,
    claims: Dict[str, str] = Depends(get_current_user_claims)
):
    raw_query = payload.query
    tenant_id = payload.tenant_id
    user_id = claims["user_id"]
    user_role = claims["user_role"]

    # 1. Ingress Sanitization & Cipher/Breakout Inspection
    sanitized_query, sanitize_report = IngressSanitizer.inspect_and_decode(raw_query)

    # 2. Latent OOD Anomaly Screener (Rejects Adversarial Feature Voids)
    is_rejected, ood_score = ood_filter.evaluate_query(raw_query, threshold=30.0)

    sec_flags = SecurityFlags(
        ood_score=ood_score,
        ood_rejected=is_rejected,
        delimiter_tampering=sanitize_report["delimiter_tampering"]
    )

    if is_rejected:
        # Trip immediate circuit breaker before reaching LLM inference
        fallback_msg = (
            f"[CIRCUIT BREAKER: OOD DETECTED]: Query rejected. Latent anomaly distance "
            f"({ood_score:.2f}) exceeded boundary threshold (30.00)."
        )
        audit_record = audit_logger.log_inference_event(
            tenant_id=tenant_id,
            user_id=user_id,
            user_role=user_role,
            raw_query=raw_query,
            sanitization_report=sanitize_report,
            ood_score=ood_score,
            ood_rejected=True,
            canary_token="NONE",
            canary_leak_detected=False,
            requires_human_oversight=True,
            execution_trace=[{"step": "ingress_gate", "action": "blocked_ood"}],
            final_output=fallback_msg
        )
        return InferenceResponse(
            response=fallback_msg,
            tenant_id=tenant_id,
            user_id=user_id,
            ood_score=ood_score,
            circuit_breaker_tripped=True,
            audit_digest=audit_record.cryptographic_digest,
            execution_trace=[{"step": "ingress_gate", "action": "blocked_ood"}]
        )

    # 3. Dynamic Canary Sentinel Generation
    canary = CanarySentinel.generate_token()
    sec_flags.canary_injected = canary

    # 4. Invoke Governed LangGraph Cyclical State Machine
    initial_state: ConformityAgentState = {
        "raw_query": raw_query,
        "sanitized_query": sanitized_query,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "user_role": user_role,
        "canary_token": canary,
        "security_flags": sec_flags,
        "documents": [],
        "generation": "",
        "iteration_count": 0,
        "needs_rewrite": False,
        "execution_trace": []
    }

    final_state = conformity_agent.invoke(initial_state)

    # 5. Egress Validation & Canary Tripwire Inspection
    raw_generation = final_state.get("generation", "")
    leak_detected, safe_output = CanarySentinel.inspect_egress(raw_generation, canary)
    sec_flags.canary_leak_detected = leak_detected

    # 6. Immutable Event & Compliance Audit Serialization (EU AI Act Article 12)
    audit_record = audit_logger.log_inference_event(
        tenant_id=tenant_id,
        user_id=user_id,
        user_role=user_role,
        raw_query=raw_query,
        sanitization_report=sanitize_report,
        ood_score=ood_score,
        ood_rejected=False,
        canary_token=canary,
        canary_leak_detected=leak_detected,
        requires_human_oversight=leak_detected,
        execution_trace=final_state.get("execution_trace", []),
        final_output=safe_output
    )

    return InferenceResponse(
        response=safe_output,
        tenant_id=tenant_id,
        user_id=user_id,
        ood_score=ood_score,
        circuit_breaker_tripped=leak_detected,
        audit_digest=audit_record.cryptographic_digest,
        execution_trace=final_state.get("execution_trace", [])
    )

@app.get("/healthz")
async def health_check():
    return {"status": "HEALTHY", "ood_calibrated": ood_filter.is_fitted}