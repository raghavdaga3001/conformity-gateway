import pytest
from app.agent.state import ConformityAgentState, SecurityFlags, GradeDocument
from app.database.vector_store import PartitionedVectorStore

@pytest.fixture(scope="module")
def seeded_store():
    store = PartitionedVectorStore(persist_dir="./test_chroma_db")
    store.reset_database()
    
    # Seed cross-tenant records
    corpus = [
        {"content": "Bank of England reserve ratio requirement is 12.5%.", "tenant_id": "tenant_uk"},
        {"content": "Credit line override requires dual-officer sign-off.", "tenant_id": "tenant_uk"},
        {"content": "FINMA circular 2023/1 specifies Swiss liquidity rules.", "tenant_id": "tenant_swiss"},
        {"content": "Frankfurt data center security policies require non-root UID 10001.", "tenant_id": "tenant_eu"}
    ]
    store.seed_initial_enterprise_records(corpus)
    yield store
    store.reset_database()

def test_pre_retrieval_isolation_prevents_tenant_bleed(seeded_store):
    """Assert a Swiss tenant query physically cannot return UK or EU documents."""
    query = "What are the liquidity and reserve requirements?"
    docs = seeded_store.retrieve_tenant_documents(query=query, tenant_id="tenant_swiss", k=3)
    
    assert len(docs) > 0
    for doc in docs:
        assert doc.metadata["tenant_id"] == "tenant_swiss"
        assert "Bank of England" not in doc.page_content
        assert "FINMA" in doc.page_content

def test_pydantic_schema_enforcement():
    """Verify evaluator models reject arbitrary non-binary scores."""
    valid = GradeDocument(binary_score="yes", reasoning="Contains relevant financial ratio.")
    assert valid.binary_score == "yes"

    with pytest.raises(Exception):
        GradeDocument(binary_score="maybe", reasoning="Uncertain match.")

def test_security_flags_initialization():
    """Verify security metadata initializes with zero-trust defaults."""
    flags = SecurityFlags()
    assert flags.ood_rejected is False
    assert flags.canary_leak_detected is False
    assert flags.requires_human_oversight is False