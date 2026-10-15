from typing import TypedDict, List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic Schemas for Structured Model Evaluators
# ---------------------------------------------------------------------------

class GradeDocument(BaseModel):
    """Binary evaluation of chunk relevance against the user intent."""
    binary_score: Literal["yes", "no"] = Field(
        ...,
        description="Whether the document contains semantic overlap or answers the query ('yes' or 'no')."
    )
    reasoning: str = Field(
        ...,
        description="Concise justification for the grading verdict."
    )


class GradeHallucination(BaseModel):
    """Binary evaluation assessing answer ground truth against retrieved context."""
    binary_score: Literal["yes", "no"] = Field(
        ...,
        description="Whether the candidate generation is strictly supported by reference context ('yes' or 'no')."
    )
    reasoning: str = Field(
        ...,
        description="Explanation detailing factual support or ungrounded claims."
    )


class SecurityFlags(BaseModel):
    """Runtime threat-detection metadata logged during the inference lifecycle."""
    ood_score: float = 0.0
    ood_rejected: bool = False
    canary_injected: Optional[str] = None
    canary_leak_detected: bool = False
    delimiter_tampering: bool = False
    requires_human_oversight: bool = False


# ---------------------------------------------------------------------------
# Unified Agent State (LangGraph Core Memory)
# ---------------------------------------------------------------------------

class ConformityAgentState(TypedDict):
    # User Request & Identity Claims
    raw_query: str
    sanitized_query: str
    tenant_id: str
    user_id: str
    user_role: str
    
    # Internal Security Metadata
    canary_token: str
    security_flags: SecurityFlags

    # Context & Reasoning Flow
    documents: List[str]
    generation: str
    iteration_count: int
    needs_rewrite: bool
    
    # Traceability & EU AI Act Article 12 Telemetry
    execution_trace: List[Dict[str, Any]]