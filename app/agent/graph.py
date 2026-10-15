from langgraph.graph import StateGraph, END
from app.agent.state import ConformityAgentState
from app.agent.nodes import (
    retrieve_node,
    grade_documents_node,
    rewrite_query_node,
    generate_node,
    grade_generation_node
)

MAX_RETRIES = 2

def route_after_grading(state: ConformityAgentState) -> str:
    """Routes to rewrite if context is starved and retry budget remains."""
    if state["needs_rewrite"]:
        if state.get("iteration_count", 0) < MAX_RETRIES:
            return "rewrite_query"
        return "generate"  # Proceed to generate safe refusal if budget exhausted
    return "generate"


def compile_governed_graph():
    """Compiles the cyclic state machine with guarded conditional recovery edges."""
    workflow = StateGraph(ConformityAgentState)

    # Register Nodes
    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("grade_documents", grade_documents_node)
    workflow.add_node("rewrite_query", rewrite_query_node)
    workflow.add_node("generate", generate_node)
    workflow.add_node("grade_generation", grade_generation_node)

    # Establish Transitions
    workflow.set_entry_point("retrieve")
    workflow.add_edge("retrieve", "grade_documents")
    
    workflow.add_conditional_edges(
        "grade_documents",
        route_after_grading,
        {
            "rewrite_query": "rewrite_query",
            "generate": "generate"
        }
    )
    
    workflow.add_edge("rewrite_query", "retrieve")
    workflow.add_edge("generate", "grade_generation")
    workflow.add_edge("grade_generation", END)

    return workflow.compile()

# Global Compiled Graph
conformity_agent = compile_governed_graph()