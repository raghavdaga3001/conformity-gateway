from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class WireTransferRequest(BaseModel):
    """
    Public Tool Schema exposed to the LLM.
    SECURITY INVARIANT: The LLM controls ONLY the destination and amount.
    Sender account, tenant identity, and authorization scope are stripped
    from model access to mitigate Confused Deputy / BOLA attacks.
    """
    beneficiary_iban: str = Field(..., description="Target destination account or IBAN.")
    amount: float = Field(..., description="Transfer amount in GBP.")
    reference: str = Field(default="Settlement", description="Payment reference memo.")


class ToolExecutionResult(BaseModel):
    success: bool
    requires_hitl: bool
    message: str
    transaction_id: Optional[str] = None


class SecureBankingToolKit:
    """
    Enforces Zero-Trust Parameter Binding & Human-in-the-Loop (HITL) Thresholds.
    """
    HITL_THRESHOLD = 5000.0  # Actions > £5,000 mandate asynchronous human 2FA sign-off

    @staticmethod
    def execute_wire_transfer(
        params: WireTransferRequest,
        session_user_id: str,
        session_tenant_id: str
    ) -> ToolExecutionResult:
        if params.amount <= 0:
            return ToolExecutionResult(
                success=False,
                requires_hitl=False,
                message="Transaction rejected: Amount must be strictly positive."
            )

        # High-value transaction boundary check (EU AI Act Article 14 Human Oversight)
        if params.amount > SecureBankingToolKit.HITL_THRESHOLD:
            return ToolExecutionResult(
                success=False,
                requires_hitl=True,
                message=(
                    f"Threshold exceeded: Transfer of £{params.amount:,.2f} requires human approval. "
                    f"Asynchronous 2FA authorization ticket queued for verified user [{session_user_id}]."
                )
            )

        # Parameter binding: Sender is hardwired from verified session context
        tx_id = f"TX-{session_tenant_id[:4].upper()}-{int(params.amount * 100)}"
        return ToolExecutionResult(
            success=True,
            requires_hitl=False,
            transaction_id=tx_id,
            message=(
                f"Successfully settled £{params.amount:,.2f} from authenticated account "
                f"[{session_user_id}] to [{params.beneficiary_iban}]. Ref: {tx_id}"
            )
        )