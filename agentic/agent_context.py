"""
Per-request agent context.

These ContextVars are set by the agent runtime (orchestrator / websocket
endpoint / fireteam) at the start of each turn so that tools can read user
and project identity from any depth of call stack without threading args.

Lives in its own module (instead of in tools.py) so that lightweight callers
- workspace_fs, job_runner, output_offload, and unit tests for those modules -
can import the contextvars without pulling in langchain / MCP / neo4j as a
side effect of importing tools.
"""
from contextvars import ContextVar
from typing import Optional

current_user_id: ContextVar[str] = ContextVar("current_user_id", default="")
current_project_id: ContextVar[str] = ContextVar("current_project_id", default="")
current_phase: ContextVar[str] = ContextVar("current_phase", default="informational")
current_graph_view_cypher: ContextVar[Optional[str]] = ContextVar(
    "current_graph_view_cypher", default=None,
)


def set_tenant_context(user_id: str, project_id: str) -> None:
    """Set the current user and project context for tool execution."""
    current_user_id.set(user_id)
    current_project_id.set(project_id)


def set_phase_context(phase: str) -> None:
    """Set the current phase context for tool restrictions."""
    current_phase.set(phase)


def set_graph_view_context(cypher: Optional[str]) -> None:
    """Set the active graph view Cypher for scoped queries."""
    current_graph_view_cypher.set(cypher)


def get_graph_view_context() -> Optional[str]:
    """Get the active graph view Cypher template."""
    return current_graph_view_cypher.get()


def get_phase_context() -> str:
    """Get the current phase context."""
    return current_phase.get()
