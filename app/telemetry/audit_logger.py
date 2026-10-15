import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

LOG_FILE = "audit_records.jsonl"

class AuditRecord(BaseModel):
    timestamp_utc: str
    tenant_id: str
    user_id: str
    user_role: str
    raw_query_hash: str
    sanitization_report: Dict[str, Any]
    ood_score: float
    ood_rejected: bool
    canary_token: str
    canary_leak_detected: bool
    requires_human_oversight: bool
    execution_trace: List[Dict[str, Any]]
    final_output_snippet: str
    cryptographic_digest: str = Field(
        ...,
        description="SHA-256 hash chaining all record fields for tamper evidence."
    )

class ComplianceAuditLogger:
    """
    Emits structured, non-repudiation audit trails conforming to EU AI Act Article 12.
    """

    def __init__(self, log_path: str = LOG_FILE):
        self.log_path = log_path

    @staticmethod
    def _compute_digest(payload: Dict[str, Any]) -> str:
        """Calculates deterministic SHA-256 digest over normalized JSON payload."""
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def log_inference_event(
        self,
        tenant_id: str,
        user_id: str,
        user_role: str,
        raw_query: str,
        sanitization_report: Dict[str, Any],
        ood_score: float,
        ood_rejected: bool,
        canary_token: str,
        canary_leak_detected: bool,
        requires_human_oversight: bool,
        execution_trace: List[Dict[str, Any]],
        final_output: str
    ) -> AuditRecord:
        now_utc = datetime.now(timezone.utc).isoformat()
        query_hash = hashlib.sha256(raw_query.encode("utf-8")).hexdigest()

        # Build raw record for hashing
        record_content = {
            "timestamp_utc": now_utc,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "user_role": user_role,
            "raw_query_hash": query_hash,
            "sanitization_report": sanitization_report,
            "ood_score": round(ood_score, 4),
            "ood_rejected": ood_rejected,
            "canary_token": canary_token,
            "canary_leak_detected": canary_leak_detected,
            "requires_human_oversight": requires_human_oversight,
            "execution_trace": execution_trace,
            "final_output_snippet": final_output[:120] if final_output else ""
        }

        # Calculate cryptographic hash
        digest = self._compute_digest(record_content)
        record_content["cryptographic_digest"] = digest

        audit_record = AuditRecord(**record_content)

        # Append to append-only WORM log
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(audit_record.model_dump_json() + "\n")

        return audit_record