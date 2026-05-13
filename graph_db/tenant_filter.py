"""
Tenant-scoping helpers for Cypher queries.

Single source of truth for:
- Inline (user_id, project_id) injection into every node pattern.
- Read-only enforcement (write-clause and write-procedure detection).

Imported by both the agent (agentic.tools.Neo4jToolManager) and the
kali-sandbox CLI (mcp/servers/redagraph.py).
"""

import re
from typing import Optional

_WRITE_CLAUSE_RE = re.compile(
    r'\b(CREATE|MERGE|DELETE|DETACH\s+DELETE|SET|REMOVE|DROP|ALTER|'
    r'LOAD\s+CSV|START\s+DATABASE|STOP\s+DATABASE|GRANT|DENY|REVOKE|'
    r'ENABLE\s+SERVER|DEALLOCATE|REALLOCATE|TERMINATE)\b',
    re.IGNORECASE,
)

_WRITE_PROCEDURE_RE = re.compile(
    r'\bCALL\s+(apoc\.(create|merge|refactor|periodic|trigger|schema)|'
    r'apoc\.cypher\.(runWrite|doIt)|dbms\.)\b',
    re.IGNORECASE,
)

_NODE_PATTERN_RE = re.compile(r'\((\w+):(\w+)(?:\s*\{([^}]*)\})?\)')

TENANT_PARAMS = {"tenant_user_id", "tenant_project_id"}


def find_disallowed_write_operation(cypher: str) -> Optional[str]:
    """Return a disallowed write clause/procedure name, or None for read-only Cypher."""
    proc_match = _WRITE_PROCEDURE_RE.search(cypher)
    if proc_match:
        return proc_match.group(1)

    match = _WRITE_CLAUSE_RE.search(cypher)
    if match:
        return re.sub(r'\s+', ' ', match.group(1).upper())

    return None


def inject_tenant_filter(cypher: str, user_id: str, project_id: str) -> str:
    """
    Inject mandatory user_id and project_id filters into a Cypher query.

    Adds tenant properties directly into each node pattern as inline property
    filters. This ensures filters are always in scope regardless of WITH clauses
    or query structure.

    Example:
        MATCH (d:Domain {name: "example.com"})
    becomes:
        MATCH (d:Domain {name: "example.com", user_id: $tenant_user_id, project_id: $tenant_project_id})

    The caller must pass the parameters {"tenant_user_id": user_id,
    "tenant_project_id": project_id} when executing the returned query.
    """
    tenant_props = "user_id: $tenant_user_id, project_id: $tenant_project_id"

    def add_tenant_to_node(match: re.Match) -> str:
        var_name = match.group(1)
        label = match.group(2)
        existing_props_content = match.group(3)

        if existing_props_content is not None:
            existing_props_content = existing_props_content.strip()
            if existing_props_content:
                new_props = f"{{{existing_props_content}, {tenant_props}}}"
            else:
                new_props = f"{{{tenant_props}}}"
            return f"({var_name}:{label} {new_props})"
        return f"({var_name}:{label} {{{tenant_props}}})"

    return _NODE_PATTERN_RE.sub(add_tenant_to_node, cypher)
