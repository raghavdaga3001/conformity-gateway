import os
from typing import List, Dict, Any
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

DB_DIR = "./chroma_db"
COLLECTION_NAME = "conformity_records"

def get_embedding_model() -> HuggingFaceEmbeddings:
    """Returns local sentence-transformer embedding model running on CPU."""
    return HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"}
    )

class PartitionedVectorStore:
    """Multi-tenant ChromaDB interface enforcing pre-retrieval metadata partitioning."""

    def __init__(self, persist_dir: str = DB_DIR, collection_name: str = COLLECTION_NAME):
        self.persist_dir = persist_dir
        self.collection_name = collection_name
        self.embeddings = get_embedding_model()
        self.db: Chroma = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings
        )

    def seed_initial_enterprise_records(self, records: List[Dict[str, Any]]):
        """Seeds records tagged with explicit tenant_id and access_tier metadata."""
        docs = []
        for r in records:
            docs.append(Document(
                page_content=r["content"],
                metadata={
                    "tenant_id": r["tenant_id"],
                    "access_tier": r.get("access_tier", "standard"),
                    "doc_id": r.get("doc_id", "doc_generic")
                }
            ))
        
        self.db.add_documents(docs)

    def retrieve_tenant_documents(self, query: str, tenant_id: str, k: int = 2) -> List[Document]:
        """
        Executes similarity search with mandatory pre-retrieval tenant isolation.
        The underlying query filter is bounded to the client's tenant namespace.
        """
        retriever = self.db.as_retriever(
            search_type="similarity",
            search_kwargs={
                "k": k,
                "filter": {"tenant_id": tenant_id}  # Enforced pre-retrieval partition
            }
        )
        return retriever.invoke(query)

    def reset_database(self):
        """Cleans collection contents via Chroma API without invalidating the SQLite connection."""
        try:
            self.db.delete_collection()
        except Exception:
            pass

        self.db = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_dir,
            embedding_function=self.embeddings
        )

# Global Store Instance
vector_store = PartitionedVectorStore()