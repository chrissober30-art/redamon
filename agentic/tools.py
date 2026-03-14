"""
RedAmon Agent Tools

MCP tools and Neo4j graph query tool definitions.
Includes phase-aware tool management.
"""

import os
import re
import asyncio
import logging
from typing import List, Optional, Dict, Callable, Awaitable, TYPE_CHECKING
from contextvars import ContextVar

import httpx
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_neo4j import Neo4jGraph

from project_settings import get_setting, is_tool_allowed_in_phase
from prompts import TEXT_TO_CYPHER_SYSTEM

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

# =============================================================================
# CONTEXT VARIABLES
# =============================================================================

# Context variables to pass user_id and project_id to tools
current_user_id: ContextVar[str] = ContextVar('current_user_id', default='')
current_project_id: ContextVar[str] = ContextVar('current_project_id', default='')
current_phase: ContextVar[str] = ContextVar('current_phase', default='informational')


def set_tenant_context(user_id: str, project_id: str) -> None:
    """Set the current user and project context for tool execution."""
    current_user_id.set(user_id)
    current_project_id.set(project_id)


def set_phase_context(phase: str) -> None:
    """Set the current phase context for tool restrictions."""
    current_phase.set(phase)


def get_phase_context() -> str:
    """Get the current phase context."""
    return current_phase.get()


# =============================================================================
# MCP TOOLS MANAGER
# =============================================================================

class MCPToolsManager:
    """Manages MCP (Model Context Protocol) tool connections."""

    def __init__(
        self,
        network_recon_url: str = None,
        nmap_url: str = None,
        metasploit_url: str = None,
        nuclei_url: str = None,
    ):
        self.network_recon_url = network_recon_url or os.environ.get('MCP_NETWORK_RECON_URL', 'http://host.docker.internal:8000/sse')
        self.nmap_url = nmap_url or os.environ.get('MCP_NMAP_URL', 'http://host.docker.internal:8004/sse')
        self.metasploit_url = metasploit_url or os.environ.get('MCP_METASPLOIT_URL', 'http://host.docker.internal:8003/sse')
        self.nuclei_url = nuclei_url or os.environ.get('MCP_NUCLEI_URL', 'http://host.docker.internal:8002/sse')
        self.client: Optional[MultiServerMCPClient] = None
        self._tools_cache: Dict[str, any] = {}

    async def get_tools(self, max_retries: int = 5, retry_delay: float = 10.0) -> List:
        """
        Connect to MCP servers and load tools with retry logic.

        MCP servers (kali-sandbox) may still be starting up when the agent
        initializes. Retries with exponential backoff to handle this race condition.

        Returns:
            List of MCP tools available for use
        """
        logger.info("Connecting to MCP servers...")

        mcp_servers = {}

        # Timeout settings (in seconds):
        # - timeout: HTTP connection timeout (default 5s)
        # - sse_read_timeout: How long to wait for SSE events (default 300s = 5 min)
        # Metasploit needs longer timeouts for brute force attacks (30 min for large wordlists)
        server_configs = [
            ("network_recon", self.network_recon_url, 60, 1800),  # curl+naabu+hydra+command, 30 min read (hydra needs up to 30 min)
            ("nmap", self.nmap_url, 60, 600),                     # 10 min read
            ("metasploit", self.metasploit_url, 60, 1800),        # 30 min read
            ("nuclei", self.nuclei_url, 60, 600),                 # 10 min read
        ]

        for server_name, url, timeout, sse_read_timeout in server_configs:
            try:
                logger.info(f"Connecting to MCP {server_name} server at {url}")
                mcp_servers[server_name] = {
                    "url": url,
                    "transport": "sse",
                    "timeout": timeout,
                    "sse_read_timeout": sse_read_timeout,
                }
            except Exception as e:
                logger.warning(f"Failed to configure MCP server {server_name}: {e}")

        if not mcp_servers:
            logger.warning("No MCP servers configured")
            return []

        # Retry connection with backoff — MCP servers may still be starting
        for attempt in range(1, max_retries + 1):
            try:
                self.client = MultiServerMCPClient(mcp_servers)
                mcp_tools = await self.client.get_tools()

                all_tools = []
                # Cache tools by name for easy access
                for tool in mcp_tools:
                    tool_name = getattr(tool, 'name', str(tool))
                    self._tools_cache[tool_name] = tool
                    all_tools.append(tool)

                logger.info(f"Loaded {len(all_tools)} tools from MCP servers: {list(self._tools_cache.keys())}")
                return all_tools

            except Exception as e:
                if attempt < max_retries:
                    wait = retry_delay * attempt
                    logger.warning(
                        f"MCP connection attempt {attempt}/{max_retries} failed: {e}. "
                        f"Retrying in {wait:.0f}s..."
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(f"Failed to connect to MCP servers after {max_retries} attempts: {e}")
                    logger.warning("Continuing without MCP tools")
                    return []

    def get_tool_by_name(self, name: str) -> Optional[any]:
        """Get a specific tool by name."""
        return self._tools_cache.get(name)

    def get_available_tools_for_phase(self, phase: str) -> List:
        """Get tools that are allowed in the current phase."""
        return [
            tool for name, tool in self._tools_cache.items()
            if is_tool_allowed_in_phase(name, phase)
        ]


# =============================================================================
# NEO4J TOOL MANAGER
# =============================================================================

class Neo4jToolManager:
    """Manages Neo4j graph query tool with tenant filtering."""

    def __init__(self, uri: str, user: str, password: str, llm: "BaseChatModel"):
        self.uri = uri
        self.user = user
        self.password = password
        self.llm = llm
        self.graph: Optional[Neo4jGraph] = None

    def _inject_tenant_filter(self, cypher: str, user_id: str, project_id: str) -> str:
        """
        Inject mandatory user_id and project_id filters into a Cypher query.

        This ensures all queries are scoped to the current user's project,
        preventing cross-tenant data access.

        Strategy: Add tenant properties directly into each node pattern as inline
        property filters. This ensures filters are always in scope regardless of
        WITH clauses or query structure.

        Example:
            MATCH (d:Domain {name: "example.com"})
        becomes:
            MATCH (d:Domain {name: "example.com", user_id: $tenant_user_id, project_id: $tenant_project_id})

        Args:
            cypher: The AI-generated Cypher query
            user_id: Current user's ID
            project_id: Current project's ID

        Returns:
            Modified Cypher query with tenant filters applied
        """
        tenant_props = "user_id: $tenant_user_id, project_id: $tenant_project_id"

        def add_tenant_to_node(match: re.Match) -> str:
            """Add tenant properties to a node pattern."""
            var_name = match.group(1)
            label = match.group(2)
            existing_props_content = match.group(3)  # Content INSIDE braces (without braces), or None

            if existing_props_content is not None:
                # Has existing properties - merge with tenant props
                existing_props_content = existing_props_content.strip()
                if existing_props_content:
                    # Append tenant props after existing ones
                    new_props = f"{{{existing_props_content}, {tenant_props}}}"
                else:
                    new_props = f"{{{tenant_props}}}"
                return f"({var_name}:{label} {new_props})"
            else:
                # No existing properties, add them
                return f"({var_name}:{label} {{{tenant_props}}})"

        # Pattern matches: (variable:Label) or (variable:Label {props})
        # Captures: 1=variable, 2=label, 3=optional content INSIDE braces (without braces)
        # Uses a non-greedy match for the props content
        node_pattern = r'\((\w+):(\w+)(?:\s*\{([^}]*)\})?\)'

        result = re.sub(node_pattern, add_tenant_to_node, cypher)

        return result

    async def _generate_cypher(
        self,
        question: str,
        previous_error: str = None,
        previous_cypher: str = None
    ) -> str:
        """
        Use LLM to generate a Cypher query from natural language.

        Args:
            question: Natural language question about the data
            previous_error: Optional error message from a previous failed attempt
            previous_cypher: Optional previous Cypher query that failed

        Returns:
            Generated Cypher query string
        """
        if self.llm is None:
            raise RuntimeError(
                "Graph query LLM is not initialized. "
                "This usually means project settings have not been loaded yet. "
                "Please try again or check that the agent model is configured."
            )

        schema = self.graph.get_schema

        # Build the prompt with optional error context for retries
        error_context = ""
        if previous_error and previous_cypher:
            error_context = f"""

## Previous Attempt Failed
The previous query failed with an error. Please fix the issue.

Failed Query:
{previous_cypher}

Error Message:
{previous_error}

Common fixes:
- Check relationship direction syntax: use <-[:REL]- not [:REL]<-
- Ensure node labels and property names match the schema
- Verify relationship types exist in the schema
"""

        prompt = f"""{TEXT_TO_CYPHER_SYSTEM}

## Current Database Schema
{schema}
{error_context}
## Important Rules
- Generate ONLY the Cypher query, no explanations
- Do NOT include user_id or project_id filters - they will be added automatically
- Do NOT use any parameters (like $target, $domain, etc.) - use literal values or no filters
- If the question doesn't specify a target, query ALL matching data
- Always use LIMIT to restrict results

User Question: {question}

Cypher Query:"""

        response = await self.llm.ainvoke(prompt)
        from orchestrator_helpers.json_utils import normalize_content
        cypher = normalize_content(response.content).strip()

        # Clean up the response - remove markdown code blocks if present
        if cypher.startswith("```"):
            lines = cypher.split("\n")
            cypher = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return cypher.strip()

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return the Neo4j text-to-cypher tool.

        Returns:
            The query_graph tool function, or None if setup fails
        """
        logger.info(f"Setting up Neo4j connection to {self.uri}")

        try:
            self.graph = Neo4jGraph(
                url=self.uri,
                username=self.user,
                password=self.password
            )

            # Store reference to self for use in the tool closure
            manager = self

            @tool
            async def query_graph(question: str) -> str:
                """
                Query the Neo4j graph database using natural language.

                Use this tool to retrieve reconnaissance data such as:
                - Domains, subdomains, and their relationships
                - IP addresses and their associated ports/services
                - Technologies detected on targets
                - Vulnerabilities and CVEs found
                - Any other security reconnaissance data

                This is the PRIMARY source of truth for target information.
                Always query the graph FIRST before using other tools.

                Args:
                    question: Natural language question about the data

                Returns:
                    Query results as a string
                """
                # Get current user/project from context
                user_id = current_user_id.get()
                project_id = current_project_id.get()

                if not user_id or not project_id:
                    return "Error: Missing user_id or project_id context"

                logger.info(f"[{user_id}/{project_id}] Generating Cypher for: {question[:50]}...")

                last_error = None
                last_cypher = None

                for attempt in range(get_setting('CYPHER_MAX_RETRIES', 3)):
                    try:
                        # Step 1: Generate Cypher from natural language (with error context on retry)
                        if attempt == 0:
                            cypher = await manager._generate_cypher(question)
                        else:
                            logger.info(f"[{user_id}/{project_id}] Retry {attempt}/{get_setting('CYPHER_MAX_RETRIES', 3) - 1}: Regenerating Cypher...")
                            cypher = await manager._generate_cypher(
                                question,
                                previous_error=last_error,
                                previous_cypher=last_cypher
                            )

                        logger.info(f"[{user_id}/{project_id}] Generated Cypher (attempt {attempt + 1}): {cypher}")

                        # Step 2: Inject mandatory tenant filters
                        filtered_cypher = manager._inject_tenant_filter(cypher, user_id, project_id)
                        logger.info(f"[{user_id}/{project_id}] Filtered Cypher: {filtered_cypher}")

                        # Step 3: Execute the filtered query
                        result = manager.graph.query(
                            filtered_cypher,
                            params={
                                "tenant_user_id": user_id,
                                "tenant_project_id": project_id
                            }
                        )

                        if not result:
                            return "No results found"

                        return str(result)

                    except Exception as e:
                        error_msg = str(e)
                        logger.warning(f"[{user_id}/{project_id}] Query attempt {attempt + 1} failed: {error_msg}")
                        last_error = error_msg
                        last_cypher = cypher if 'cypher' in locals() else None

                        # If this is the last attempt, return the error
                        if attempt == get_setting('CYPHER_MAX_RETRIES', 3) - 1:
                            logger.error(f"[{user_id}/{project_id}] All {get_setting('CYPHER_MAX_RETRIES', 3)} attempts failed")
                            return f"Error querying graph after {get_setting('CYPHER_MAX_RETRIES', 3)} attempts: {error_msg}"

                return "Error: Unexpected end of retry loop"

            logger.info("Neo4j graph query tool configured with tenant filtering")
            return query_graph

        except Exception as e:
            logger.error(f"Failed to set up Neo4j: {e}")
            logger.warning("Continuing without graph query tool")
            return None


# =============================================================================
# WEB SEARCH TOOL MANAGER
# =============================================================================

class WebSearchToolManager:
    """Manages Tavily web search tool for CVE research and exploit lookups."""

    def __init__(self, api_key: str = None, max_results: int = 5):
        self.api_key = api_key or ''
        self.max_results = max_results

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return the Tavily web search tool.

        Returns:
            The web_search tool function, or None if Tavily API key is not configured.
        """
        if not self.api_key:
            logger.warning(
                "Tavily API key not configured - web_search tool will not be available. "
                "Set it in Global Settings (http://localhost:3000/settings)."
            )
            return None

        manager = self

        @tool
        async def web_search(query: str) -> str:
            """
            Search the web for security research information.

            Use this tool to research:
            - CVE details, severity, affected versions, and patch information
            - Exploit techniques, PoC code, and attack vectors
            - Service/technology version-specific vulnerabilities
            - Security advisories and vendor bulletins
            - Metasploit module documentation and usage

            This is a SECONDARY source - always check query_graph FIRST
            for project-specific reconnaissance data.

            Args:
                query: Search query string (e.g., "CVE-2021-41773 exploit PoC")

            Returns:
                Search results with titles, URLs, and content snippets
            """
            try:
                from langchain_tavily import TavilySearch

                tavily_tool = TavilySearch(
                    max_results=manager.max_results,
                    topic="general",
                    search_depth="advanced",
                    api_key=manager.api_key,
                )

                results = await tavily_tool.ainvoke({"query": query})

                if isinstance(results, str):
                    return results

                if isinstance(results, list):
                    formatted = []
                    for i, result in enumerate(results, 1):
                        title = result.get("title", "No title")
                        url = result.get("url", "")
                        content = result.get("content", "")
                        formatted.append(
                            f"[{i}] {title}\n    URL: {url}\n    {content}"
                        )
                    return "\n\n".join(formatted) if formatted else "No results found"

                return str(results)

            except ImportError:
                return "Error: langchain-tavily package not installed. Run: pip install langchain-tavily"
            except Exception as e:
                logger.error(f"Web search failed: {e}")
                return f"Web search error: {str(e)}"

        logger.info("Tavily web search tool configured")
        return web_search


# =============================================================================
# GOOGLE DORK TOOL MANAGER (via SerpAPI)
# =============================================================================

SERPAPI_BASE = "https://serpapi.com/search"


class GoogleDorkToolManager:
    """Manages Google dork search tool via SerpAPI for OSINT reconnaissance."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or ''

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return the Google dork search tool.

        Returns:
            The google_dork tool function, or None if SerpAPI key is not configured.
        """
        if not self.api_key:
            logger.warning(
                "SerpAPI key not configured - google_dork tool will not be available. "
                "Set it in Global Settings (http://localhost:3000/settings)."
            )
            return None

        manager = self

        @tool
        async def google_dork(query: str) -> str:
            """
            Search Google using advanced dork operators for OSINT reconnaissance.

            Use this tool to find:
            - Exposed files on target domains (filetype:sql, filetype:env, filetype:bak)
            - Admin panels and login pages (inurl:admin, inurl:login)
            - Directory listings (intitle:"index of")
            - Sensitive data leaks (intext:password, intext:"sql syntax")

            This is passive OSINT — no packets are sent to the target.

            Args:
                query: Google dork query (e.g., "site:example.com filetype:pdf")

            Returns:
                Search results with titles, URLs, and snippets
            """
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(
                        SERPAPI_BASE,
                        params={
                            "engine": "google",
                            "api_key": manager.api_key,
                            "q": query,
                            "num": 10,
                            "nfpr": 1,      # Disable auto-correct to preserve dork syntax
                            "filter": 0,    # Disable similar results filter
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()

                # Check for API-level errors
                if "error" in data:
                    return f"Google dork error: {data['error']}"

                items = data.get("organic_results", [])
                if not items:
                    return f"No results found for: {query}"

                # Get total results count
                search_info = data.get("search_information", {})
                total = search_info.get("total_results", "?")

                formatted = []
                for item in items:
                    pos = item.get("position", "?")
                    title = item.get("title", "No title")
                    link = item.get("link", "")
                    snippet = item.get("snippet", "")
                    displayed_link = item.get("displayed_link", "")

                    entry = f"[{pos}] {title}\n    URL: {link}"
                    if displayed_link:
                        entry += f"\n    Display: {displayed_link}"
                    if snippet:
                        entry += f"\n    {snippet}"
                    formatted.append(entry)

                header = f"Google dork results ({total} total, showing {len(items)}):\n"
                return header + "\n\n".join(formatted)

            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                if status == 401:
                    return "SerpAPI error: Invalid API key. Check Global Settings."
                elif status == 429:
                    return "SerpAPI error: Rate limit exceeded (free: 250/month, 50/hour)."
                return f"SerpAPI error: HTTP {status}"
            except Exception as e:
                logger.error(f"Google dork search failed: {e}")
                return f"Google dork error: {str(e)}"

        logger.info("Google dork search tool configured (via SerpAPI)")
        return google_dork


# =============================================================================
# SHODAN TOOL MANAGER
# =============================================================================

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanToolManager:
    """Manages unified Shodan OSINT tool for internet-wide reconnaissance."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or ''

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return unified Shodan tool with 5 actions.

        Returns:
            The shodan tool, or None if Shodan API key is not configured.
        """
        if not self.api_key:
            logger.warning(
                "Shodan API key not configured - shodan tool will not be available. "
                "Set it in Global Settings (http://localhost:3000/settings)."
            )
            return None

        manager = self

        @tool
        async def shodan(action: str, query: str = "", ip: str = "", domain: str = "") -> str:
            """
            Unified Shodan OSINT tool for internet-wide reconnaissance.

            Actions:
            - search: Search Shodan for devices/services (requires paid key)
            - host: Get detailed info for a specific IP
            - dns_reverse: Reverse DNS lookup for an IP
            - dns_domain: Get DNS records and subdomains for a domain (requires paid key)
            - count: Count matching hosts without full search

            Args:
                action: One of "search", "host", "dns_reverse", "dns_domain", "count"
                query: Shodan search query (for search and count actions)
                ip: Target IP address (for host and dns_reverse actions)
                domain: Target domain (for dns_domain action)

            Returns:
                Formatted results from the Shodan API
            """
            if action == "search":
                return await _action_search(manager.api_key, query)
            elif action == "host":
                return await _action_host(manager.api_key, ip)
            elif action == "dns_reverse":
                return await _action_dns_reverse(manager.api_key, ip)
            elif action == "dns_domain":
                return await _action_dns_domain(manager.api_key, domain)
            elif action == "count":
                return await _action_count(manager.api_key, query)
            else:
                return (
                    f"Error: Unknown action '{action}'. "
                    "Valid actions: search, host, dns_reverse, dns_domain, count"
                )

        logger.info("Shodan OSINT tool configured (5 actions)")
        return shodan


async def _action_search(api_key: str, query: str) -> str:
    """Search Shodan for internet-connected devices."""
    if not query:
        return "Error: 'query' parameter is required for action='search'"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/shodan/host/search",
                params={"key": api_key, "query": query},
            )
            resp.raise_for_status()
            data = resp.json()

        total = data.get("total", 0)
        matches = data.get("matches", [])

        if not matches:
            return f"No Shodan results for query: {query} (total: {total})"

        lines = [f"Shodan search: {total} total results (showing {len(matches)})"]
        lines.append("")

        for i, match in enumerate(matches[:20], 1):
            ip = match.get("ip_str", "?")
            port = match.get("port", "?")
            org = match.get("org", "")
            product = match.get("product", "")
            version = match.get("version", "")
            hostnames = match.get("hostnames", [])
            vulns = list(match.get("vulns", {}).keys()) if match.get("vulns") else []
            transport = match.get("transport", "tcp")

            svc = f"{product} {version}".strip() if product else ""
            host_line = f"[{i}] {ip}:{port}/{transport}"
            if org:
                host_line += f"  org={org}"
            if hostnames:
                host_line += f"  hosts={','.join(hostnames[:3])}"
            if svc:
                host_line += f"  svc={svc}"
            if vulns:
                host_line += f"  vulns={','.join(vulns[:5])}"

            lines.append(host_line)

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return _handle_http_error(e, "search")
    except Exception as e:
        logger.error(f"Shodan search failed: {e}")
        return f"Shodan search error: {str(e)}"


async def _action_host(api_key: str, ip: str) -> str:
    """Get detailed Shodan information for a specific IP address."""
    if not ip:
        return "Error: 'ip' parameter is required for action='host'"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/shodan/host/{ip}",
                params={"key": api_key},
            )
            resp.raise_for_status()
            data = resp.json()

        lines = [f"Shodan Host: {data.get('ip_str', ip)}"]

        hostnames = data.get("hostnames", [])
        if hostnames:
            lines.append(f"Hostnames: {', '.join(hostnames)}")

        os_info = data.get("os")
        if os_info:
            lines.append(f"OS: {os_info}")

        org = data.get("org", "")
        isp = data.get("isp", "")
        if org:
            lines.append(f"Org: {org}")
        if isp and isp != org:
            lines.append(f"ISP: {isp}")

        country = data.get("country_name", "")
        city = data.get("city", "")
        if country:
            loc = country
            if city:
                loc = f"{city}, {country}"
            lines.append(f"Location: {loc}")

        ports = data.get("ports", [])
        if ports:
            lines.append(f"Open ports: {', '.join(str(p) for p in sorted(ports))}")

        vulns = data.get("vulns", [])
        if vulns:
            lines.append(f"Vulnerabilities ({len(vulns)}): {', '.join(vulns[:15])}")
            if len(vulns) > 15:
                lines.append(f"  ... and {len(vulns) - 15} more")

        # Per-service details
        services = data.get("data", [])
        if services:
            lines.append("")
            lines.append(f"Services ({len(services)}):")
            for svc in services[:15]:
                port = svc.get("port", "?")
                transport = svc.get("transport", "tcp")
                product = svc.get("product", "")
                version = svc.get("version", "")
                svc_name = f"{product} {version}".strip() if product else ""

                svc_line = f"  {port}/{transport}"
                if svc_name:
                    svc_line += f"  {svc_name}"

                # Banner snippet (first 200 chars)
                banner = svc.get("data", "").strip()
                if banner:
                    snippet = banner[:200].replace("\n", " | ")
                    svc_line += f"  banner: {snippet}"

                lines.append(svc_line)

            if len(services) > 15:
                lines.append(f"  ... and {len(services) - 15} more services")

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return f"Shodan: No information available for IP {ip}"
        return _handle_http_error(e, "host")
    except Exception as e:
        logger.error(f"Shodan host info failed: {e}")
        return f"Shodan host info error: {str(e)}"


async def _action_dns_reverse(api_key: str, ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    if not ip:
        return "Error: 'ip' parameter is required for action='dns_reverse'"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/dns/reverse",
                params={"key": api_key, "ips": ip},
            )
            resp.raise_for_status()
            data = resp.json()

        hostnames = data.get(ip, [])
        if not hostnames:
            return f"No reverse DNS records for {ip}"

        lines = [f"Reverse DNS for {ip}:"]
        for hostname in hostnames:
            lines.append(f"  {hostname}")
        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return _handle_http_error(e, "dns_reverse")
    except Exception as e:
        logger.error(f"Shodan DNS reverse failed: {e}")
        return f"Shodan DNS reverse error: {str(e)}"


async def _action_dns_domain(api_key: str, domain: str) -> str:
    """Get DNS records and subdomains for a domain."""
    if not domain:
        return "Error: 'domain' parameter is required for action='dns_domain'"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/dns/domain/{domain}",
                params={"key": api_key},
            )
            resp.raise_for_status()
            data = resp.json()

        lines = [f"DNS for {domain}:"]

        subdomains = data.get("subdomains", [])
        if subdomains:
            lines.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains[:30])}")
            if len(subdomains) > 30:
                lines.append(f"  ... and {len(subdomains) - 30} more")

        records = data.get("data", [])
        if records:
            lines.append("")
            lines.append(f"Records ({len(records)}):")
            for i, rec in enumerate(records[:30], 1):
                rec_type = rec.get("type", "?")
                subdomain = rec.get("subdomain", "")
                value = rec.get("value", "")
                fqdn = f"{subdomain}.{domain}" if subdomain else domain
                lines.append(f"  [{i}] {rec_type}  {fqdn} -> {value}")
            if len(records) > 30:
                lines.append(f"  ... and {len(records) - 30} more records")

        if not subdomains and not records:
            lines.append("No DNS data found")

        if data.get("more", False):
            lines.append("\nNote: Additional results available (API returned partial data)")

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return _handle_http_error(e, "dns_domain")
    except Exception as e:
        logger.error(f"Shodan DNS domain failed: {e}")
        return f"Shodan DNS domain error: {str(e)}"


async def _action_count(api_key: str, query: str) -> str:
    """Count Shodan results for a query without consuming search credits."""
    if not query:
        return "Error: 'query' parameter is required for action='count'"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/shodan/host/count",
                params={
                    "key": api_key,
                    "query": query,
                    "facets": "port,country,org",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        total = data.get("total", 0)
        lines = [f"Shodan count: {total} hosts matching '{query}'"]

        facets = data.get("facets", {})
        for facet_name, facet_values in facets.items():
            if facet_values:
                lines.append(f"\n{facet_name}:")
                for fv in facet_values[:10]:
                    lines.append(f"  {fv.get('value', '?')}: {fv.get('count', 0)}")

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return _handle_http_error(e, "count")
    except Exception as e:
        logger.error(f"Shodan count failed: {e}")
        return f"Shodan count error: {str(e)}"


def _handle_http_error(e: 'httpx.HTTPStatusError', action: str) -> str:
    """Common HTTP error handler for all Shodan actions."""
    status = e.response.status_code
    if status == 401:
        return "Shodan API error: Invalid API key. Check Global Settings."
    elif status == 403:
        return f"Shodan API error: Action '{action}' requires a paid Shodan API key."
    elif status == 429:
        return "Shodan API error: Rate limit exceeded. Try again later."
    return f"Shodan API error: HTTP {status}"


# =============================================================================
# PHASE-AWARE TOOL EXECUTOR
# =============================================================================

class PhaseAwareToolExecutor:
    """
    Executes tools with phase-awareness.
    Validates that tools are allowed in the current phase before execution.
    """

    def __init__(
        self,
        mcp_manager: MCPToolsManager,
        graph_tool: Optional[callable],
        web_search_tool: Optional[callable] = None,
        shodan_tool: Optional[callable] = None,
        google_dork_tool: Optional[callable] = None,
    ):
        self.mcp_manager = mcp_manager
        self.graph_tool = graph_tool
        self.web_search_tool = web_search_tool
        self._all_tools: Dict[str, callable] = {}

        # Register graph tool
        if graph_tool:
            self._all_tools["query_graph"] = graph_tool

        # Register web search tool
        if web_search_tool:
            self._all_tools["web_search"] = web_search_tool

        # Register Shodan tool
        if shodan_tool:
            self._all_tools["shodan"] = shodan_tool

        # Register Google dork tool
        if google_dork_tool:
            self._all_tools["google_dork"] = google_dork_tool

    def register_mcp_tools(self, tools: List) -> None:
        """Register MCP tools after they're loaded."""
        for tool in tools:
            tool_name = getattr(tool, 'name', None)
            if tool_name:
                self._all_tools[tool_name] = tool

    def update_web_search_tool(self, tool: callable) -> None:
        """Replace the web search tool (e.g. when Tavily key changes)."""
        self.web_search_tool = tool
        self._all_tools["web_search"] = tool

    def update_shodan_tool(self, tool: Optional[callable]) -> None:
        """Replace or remove the Shodan tool (e.g. when API key changes)."""
        if tool:
            self._all_tools["shodan"] = tool
        else:
            self._all_tools.pop("shodan", None)

    def update_google_dork_tool(self, tool: Optional[callable]) -> None:
        """Replace or remove the Google dork tool (e.g. when SerpAPI key changes)."""
        if tool:
            self._all_tools["google_dork"] = tool
        else:
            self._all_tools.pop("google_dork", None)

    def _extract_text_from_output(self, output) -> str:
        """
        Extract clean text from MCP tool output.

        MCP tools return responses in various formats:
        - List of content blocks: [{'type': 'text', 'text': '...', 'id': '...'}]
        - Plain string
        - Other formats

        This method normalizes all formats to clean text.
        """
        if output is None:
            return ""

        # If it's already a string, return it
        if isinstance(output, str):
            return output

        # If it's a list (MCP content blocks format)
        if isinstance(output, list):
            text_parts = []
            for item in output:
                if isinstance(item, dict):
                    # Extract 'text' field from content block
                    if 'text' in item:
                        text_parts.append(item['text'])
                    elif 'content' in item:
                        text_parts.append(str(item['content']))
                elif isinstance(item, str):
                    text_parts.append(item)
            return '\n'.join(text_parts) if text_parts else str(output)

        # If it's a dict with 'text' or 'content'
        if isinstance(output, dict):
            if 'text' in output:
                return output['text']
            if 'content' in output:
                return str(output['content'])
            if 'output' in output:
                return str(output['output'])

        # Fallback: convert to string
        return str(output)

    async def execute(
        self,
        tool_name: str,
        tool_args: dict,
        phase: str,
        skip_phase_check: bool = False
    ) -> dict:
        """
        Execute a tool if allowed in the current phase.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool
            phase: Current agent phase
            skip_phase_check: If True, bypass phase restriction (for internal use like prewarm)

        Returns:
            dict with 'success', 'output', and optionally 'error'
        """
        # Check phase restriction
        if not skip_phase_check and not is_tool_allowed_in_phase(tool_name, phase):
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' is not allowed in '{phase}' phase. "
                         f"This tool requires: {get_phase_for_tool(tool_name)}"
            }

        # Get the tool
        tool = self._all_tools.get(tool_name)
        if not tool:
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' not found"
            }

        try:
            # Execute the tool
            if tool_name == "query_graph":
                # Graph tool expects 'question' argument
                question = tool_args.get("question", "")
                output = await tool.ainvoke(question)
            elif tool_name == "web_search":
                # Web search tool expects 'query' argument
                query = tool_args.get("query", "")
                output = await tool.ainvoke(query)
            elif tool_name == "shodan":
                # Shodan tool handles routing internally via action param
                output = await tool.ainvoke(tool_args)
            elif tool_name == "google_dork":
                # Google dork tool expects 'query' argument
                query = tool_args.get("query", "")
                output = await tool.ainvoke(query)
            else:
                # MCP tools - invoke with the appropriate argument
                output = await tool.ainvoke(tool_args)

            # Extract clean text from MCP response
            # MCP returns list of content blocks: [{'type': 'text', 'text': '...', 'id': '...'}]
            clean_output = self._extract_text_from_output(output)

            return {
                "success": True,
                "output": clean_output,
                "error": None
            }

        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }

    async def execute_with_progress(
        self,
        tool_name: str,
        tool_args: dict,
        phase: str,
        progress_callback: Callable[[str, str, bool], Awaitable[None]],
        poll_interval: float = 5.0,
        progress_url: str | None = None
    ) -> dict:
        """
        Execute a long-running tool with integrated progress streaming.

        Polls the HTTP progress endpoint during execution and sends updates
        via the progress_callback. Works with any tool that exposes a
        /progress HTTP endpoint (Metasploit on 8013, Hydra on 8014).

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool
            phase: Current agent phase
            progress_callback: Async callback(tool_name, chunk, is_final)
            poll_interval: How often to poll for progress (seconds)
            progress_url: HTTP URL for progress endpoint. Defaults to Metasploit's.

        Returns:
            dict with 'success', 'output', and optionally 'error'
        """
        # Start the main tool execution as a background task
        execution_task = asyncio.create_task(
            self.execute(tool_name, tool_args, phase)
        )

        last_line_count = 0
        last_output = ""

        url = progress_url or os.environ.get(
            'MCP_METASPLOIT_PROGRESS_URL',
            'http://host.docker.internal:8013/progress'
        )

        async with httpx.AsyncClient(timeout=2.0) as client:
            while not execution_task.done():
                await asyncio.sleep(poll_interval)

                if execution_task.done():
                    break

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        progress = resp.json()

                        if progress.get("active"):
                            current_output = progress.get("output", "")
                            line_count = progress.get("line_count", 0)
                            elapsed = progress.get("elapsed_seconds", 0)

                            # Only send if new content
                            if line_count > last_line_count and current_output != last_output:
                                # Calculate the new portion
                                if last_output and current_output.startswith(last_output):
                                    new_content = current_output[len(last_output):]
                                else:
                                    new_content = current_output

                                if new_content.strip():
                                    # Format progress update with context
                                    progress_msg = f"[Progress: {line_count} lines, {elapsed}s]\n{new_content[-1000:]}"
                                    await progress_callback(
                                        tool_name,
                                        progress_msg,
                                        False  # not final
                                    )

                                last_output = current_output
                                last_line_count = line_count

                except httpx.TimeoutException:
                    # Progress polling timeout is fine, continue
                    pass
                except httpx.HTTPError as e:
                    # Connection errors during polling are best-effort, log and continue
                    logger.debug(f"Progress polling error (non-fatal): {e}")
                except Exception as e:
                    # Unexpected errors, log but don't fail the execution
                    logger.warning(f"Progress polling unexpected error: {e}")

        # Wait for the execution to complete and return result
        return await execution_task

    def get_all_tools(self) -> List:
        """Get all registered tools."""
        return list(self._all_tools.values())

    def get_tools_for_phase(self, phase: str) -> List:
        """Get tools allowed in the given phase."""
        return [
            tool for name, tool in self._all_tools.items()
            if is_tool_allowed_in_phase(name, phase)
        ]


def get_phase_for_tool(tool_name: str) -> str:
    """Get the minimum phase required for a tool."""
    allowed_phases = get_setting('TOOL_PHASE_MAP', {}).get(tool_name, [])
    if "informational" in allowed_phases:
        return "informational"
    elif "exploitation" in allowed_phases:
        return "exploitation"
    elif "post_exploitation" in allowed_phases:
        return "post_exploitation"
    return "unknown"
