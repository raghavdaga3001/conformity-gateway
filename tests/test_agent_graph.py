import pytest
from app.agent.tools import SecureBankingToolKit, WireTransferRequest
from app.agent.state import ConformityAgentState, SecurityFlags
from app.agent.graph import conformity_agent
from app.database.vector_store import vector_store

@pytest.fixture(scope="module", autouse=True)
def setup_test_vectors():
    vector_store.reset_database()
    corpus = [
        {"content": "UK regulatory capital reserve requirement is strictly 12.5%.", "tenant_id": "tenant_uk"},
        {"content": "Swiss liquidity ratio under FINMA circular 2023 is 100%.", "tenant_id": "tenant_swiss"}
    ]
    vector_store.seed_initial_enterprise_records(corpus)
    yield
    vector_store.reset_database()

# ---------------------------------------------------------------------------
# Zero-Trust Parameter Binding Tests (OWASP LLM06)
# ---------------------------------------------------------------------------

def test_zero_trust_parameter_binding_prevents_identity_spoofing():
    """Verify tool executes using authenticated session identity, ignoring malicious arguments."""
    payload = WireTransferRequest(
        beneficiary_iban="GB89BARC20201530000000",
        amount=1500.0,
        reference="Invoice #109"
    )

    # Verified caller identity supplied by API Gateway JWT
    result = SecureBankingToolKit.execute_wire_transfer(
        params=payload,
        session_user_id="USER_LEGITIMATE_88",
        session_tenant_id="tenant_uk"
    )

    assert result.success is True
    assert result.requires_hitl is False
    assert "USER_LEGITIMATE_88" in result.message
    assert "TX-TENA-" in result.transaction_id

def test_hitl_threshold_gate_trips_on_high_value_action():
    """Verify state-changing actions exceeding £5,000 mandate human authorization."""
    payload = WireTransferRequest(
        beneficiary_iban="GB89BARC20201530000000",
        amount=250000.0,
        reference="Corporate Buyout"
    )

    result = SecureBankingToolKit.execute_wire_transfer(
        params=payload,
        session_user_id="USER_LEGITIMATE_88",
        session_tenant_id="tenant_uk"
    )

    assert result.success is False
    assert result.requires_hitl is True
    assert "Threshold exceeded" in result.message
    assert "Asynchronous 2FA authorization ticket queued" in result.message

# ---------------------------------------------------------------------------
# LangGraph Cyclical Execution Tests
# ---------------------------------------------------------------------------

def test_agent_graph_execution_happy_path():
    """Verify end-to-end execution across retrieval, grading, and grounded generation."""
    initial_state: ConformityAgentState = {
        "raw_query": "What is the capital reserve requirement?",
        "sanitized_query": "What is the capital reserve requirement?",
        "tenant_id": "tenant_uk",
        "user_id": "user_42",
        "user_role": "risk_analyst",
        "canary_token": "CONF_CANARY_TEST99",
        "security_flags": SecurityFlags(),
        "documents": [],
        "generation": "",
        "iteration_count": 0,
        "needs_rewrite": False,
        "execution_trace": []
    }

    final_state = conformity_agent.invoke(initial_state)

    assert len(final_state["documents"]) > 0
    assert "12.5%" in final_state["documents"][0]
    assert len(final_state["generation"]) > 0
    
    steps = [t["step"] for t in final_state["execution_trace"]]
    assert "retrieve" in steps
    assert "grade_documents" in steps
    assert "generate" in steps
    assert "grade_generation" in steps

def test_agent_graph_triggers_rewrite_on_context_starvation():
    """Verify cyclic loop executes query reformulation when initial retrieval yields no matches."""
    initial_state: ConformityAgentState = {
        "raw_query": "quantum computing entangled qubit states",
        "sanitized_query": "quantum computing entangled qubit states",
        "tenant_id": "tenant_uk",
        "user_id": "user_42",
        "user_role": "risk_analyst",
        "canary_token": "CONF_CANARY_TEST99",
        "security_flags": SecurityFlags(),
        "documents": [],
        "generation": "",
        "iteration_count": 0,
        "needs_rewrite": False,
        "execution_trace": []
    }

    final_state = conformity_agent.invoke(initial_state)
    steps = [t["step"] for t in final_state["execution_trace"]]
    
    assert "rewrite_query" in steps
    assert final_state["iteration_count"] > 0