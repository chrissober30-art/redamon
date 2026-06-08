"""
RedAmon Agent WebSocket API

FastAPI application providing WebSocket endpoint for real-time agent communication.
Supports session-based conversation continuity and phase-based approval flow.

Endpoints:
    WS /ws/agent - WebSocket endpoint for real-time bidirectional streaming
    GET /health - Health check
    GET /defaults - Agent default settings (camelCase, for frontend)
    GET /models - Available AI models from all configured providers
"""

import asyncio
import base64
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import websockets
from fastapi import FastAPI, File, Form, Query, UploadFile, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel

from logging_config import setup_logging
from orchestrator import AgentOrchestrator
from orchestrator_helpers import normalize_content
from startup_guard import check_single_worker
from utils import get_session_count
from websocket_api import WebSocketManager, websocket_endpoint, MessageType
import workspace_fs
import job_runner
import ws_job_emitter

# Initialize logging with file rotation
setup_logging(log_level=logging.INFO, log_to_console=True, log_to_file=True)
logger = logging.getLogger(__name__)

orchestrator: Optional[AgentOrchestrator] = None
ws_manager: Optional[WebSocketManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes the orchestrator and WebSocket manager on startup and cleans up on shutdown.
    """
    global orchestrator, ws_manager

    # Refuse to start under multi-worker uvicorn/gunicorn. The fireteam
    # confirmation registry uses an in-process dict; multiple workers would
    # silently break confirmation routing. See startup_guard for the env
    # vars consulted and the documented remediation paths.
    check_single_worker()

    # Agent container runs as root; bind-mounted /workspace files would
    # otherwise end up root:root on the host (UID 1000), breaking the
    # plan's promise that the workspace is browsable/editable directly
    # from the host. umask 0 makes new dirs world-writable (0777) and
    # new files world-readable+writable (0666), so the host user can
    # rm/edit them. Ownership still root, but mode 666/777 makes that OK.
    os.umask(0)

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    # Background job recovery: flip any meta files marked 'running' on disk
    # (from a previous agent process that died mid-job) to 'interrupted' so
    # the drawer can show their final state correctly. In-flight asyncio
    # tasks are gone by definition - this is a state-only fixup.
    reg = job_runner.get_registry()
    reg.recover_on_boot()

    # Wire the JobRegistry to push job_update events through the WS manager
    # so the frontend drawer sees status changes in real time. The emitter
    # lives in ws_job_emitter.py so it stays unit-testable without the
    # full FastAPI/langgraph stack.
    ws_job_emitter.set_ws_manager(ws_manager)
    reg.set_ws_emitter(ws_job_emitter.emit_job_update)

    logger.info("RedAmon Agent API ready (WebSocket)")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="WebSocket API for real-time agent communication with phase tracking, MCP tools, and Neo4j integration",
    version="3.0.0",
    lifespan=lifespan
)

# Add CORS middleware for webapp (allow all origins for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when allow_origins is ["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# RESPONSE MODELS (for /health endpoint only)
# =============================================================================

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    tools_loaded: int
    active_sessions: int
    # Fireteam (multi-agent) observability
    fireteam_enabled: bool = False
    persistent_checkpointer: bool = False
    active_waves: int = 0


# =============================================================================
# ENDPOINTS
# =============================================================================


# =============================================================================
# TARGET GUARDRAIL — LLM-based check before project creation
# =============================================================================

class GuardrailRequest(BaseModel):
    """Request model for target guardrail check."""
    target_domain: str = ""
    target_ips: list[str] = []
    project_id: str = ""
    user_id: str = ""


@app.post("/guardrail/check-target", tags=["Guardrail"])
async def check_target_guardrail(body: GuardrailRequest):
    """
    Check if a target domain or IP list is safe to scan.

    Two layers:
    1. Hard guardrail (deterministic): always blocks government/public domains.
       Cannot be disabled. Runs first.
    2. Soft guardrail (LLM-based): blocks well-known private companies.
       Fails open if LLM is unavailable.
    """
    from orchestrator_helpers.hard_guardrail import is_hard_blocked
    from orchestrator_helpers.guardrail import check_target_allowed
    from project_settings import DEFAULT_AGENT_SETTINGS

    # Hard guardrail: deterministic, non-disableable
    if body.target_domain:
        blocked, reason = is_hard_blocked(body.target_domain)
        if blocked:
            return {"allowed": False, "reason": reason, "hard_blocked": True}

    if not orchestrator or not orchestrator._initialized:
        return {"allowed": True, "reason": "Agent not initialized, guardrail skipped"}

    # Ensure LLM is set up
    if not orchestrator.llm:
        if body.project_id:
            try:
                orchestrator._apply_project_settings(body.project_id)
            except Exception as e:
                logger.warning(f"Guardrail: failed to load project settings: {e}")
        # Still no LLM? Bootstrap with default model + user's API keys from DB
        if not orchestrator.llm:
            try:
                from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
                import requests as _requests

                model_name = DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
                user_providers = []

                # Fetch user's LLM providers from DB (needed for API keys)
                if body.user_id:
                    webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
                    try:
                        resp = _requests.get(
                            f"{webapp_url.rstrip('/')}/api/users/{body.user_id}/llm-providers?internal=true",
                            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
                            timeout=10,
                        )
                        resp.raise_for_status()
                        user_providers = resp.json()
                    except Exception as e:
                        logger.warning(f"Guardrail: failed to fetch user LLM providers: {e}")

                openai_p = _resolve_provider_key(user_providers, "openai")
                anthropic_p = _resolve_provider_key(user_providers, "anthropic")
                openrouter_p = _resolve_provider_key(user_providers, "openrouter")
                deepseek_p = _resolve_provider_key(user_providers, "deepseek")
                gemini_p = _resolve_provider_key(user_providers, "gemini")
                glm_p = _resolve_provider_key(user_providers, "glm")
                kimi_p = _resolve_provider_key(user_providers, "kimi")
                qwen_p = _resolve_provider_key(user_providers, "qwen")
                xai_p = _resolve_provider_key(user_providers, "xai")
                mistral_p = _resolve_provider_key(user_providers, "mistral")

                orchestrator.llm = setup_llm(
                    model_name,
                    openai_api_key=(openai_p or {}).get("apiKey"),
                    anthropic_api_key=(anthropic_p or {}).get("apiKey"),
                    openrouter_api_key=(openrouter_p or {}).get("apiKey"),
                    deepseek_api_key=(deepseek_p or {}).get("apiKey"),
                    gemini_api_key=(gemini_p or {}).get("apiKey"),
                    glm_api_key=(glm_p or {}).get("apiKey"),
                    kimi_api_key=(kimi_p or {}).get("apiKey"),
                    qwen_api_key=(qwen_p or {}).get("apiKey"),
                    xai_api_key=(xai_p or {}).get("apiKey"),
                    mistral_api_key=(mistral_p or {}).get("apiKey"),
                )
                orchestrator.model_name = model_name
                logger.info(f"Guardrail: bootstrapped LLM with default model {model_name}")
            except Exception as e:
                logger.warning(f"Guardrail: failed to bootstrap default LLM: {e}")
                return {"allowed": True, "reason": "LLM not configured, guardrail skipped"}

    try:
        result = await check_target_allowed(
            orchestrator.llm,
            target_domain=body.target_domain,
            target_ips=body.target_ips,
        )
        return result
    except Exception as e:
        logger.error(f"Guardrail error: {e}")
        return {"allowed": True, "reason": f"Guardrail error: {str(e)}"}


# =============================================================================
# ROE PARSING — LLM-based extraction of Rules of Engagement from document text
# =============================================================================

class RoeParseRequest(BaseModel):
    """Request model for RoE document parsing."""
    text: str
    model: str | None = None  # Optional: override the LLM model for parsing


_ROE_PARSE_PROMPT = """You are parsing a Rules of Engagement (RoE) document for a penetration testing engagement.
Extract ALL relevant information into the JSON structure below.
Use null for any field not mentioned in the document. Only set values you are confident about.

Return ONLY valid JSON — no markdown, no explanations, no code fences.

{
  "name": "suggested project name based on client/target",
  "description": "brief engagement description",
  "targetDomain": "primary target domain (e.g. devergolabs.com) — just the root domain, no www prefix",
  "targetIps": ["in-scope IPs/CIDRs"],
  "ipMode": false,
  "subdomainList": ["subdomain PREFIXES only, NOT full domains — e.g. 'www', 'api', 'portal', NOT 'www.example.com'"],
  "stealthMode": "ONLY set true if the document EXPLICITLY requires passive-only/no active scanning. Mentions of 'stealth' or 'low-noise' do NOT qualify — those are handled by notes. Default: false",

  "roeClientName": "client organization name",
  "roeClientContactName": "primary client point of contact name",
  "roeClientContactEmail": "client POC email",
  "roeClientContactPhone": "client POC phone",
  "roeEmergencyContact": "who to contact if incident occurs",
  "roeEngagementStartDate": "YYYY-MM-DD",
  "roeEngagementEndDate": "YYYY-MM-DD",
  "roeEngagementType": "external|internal|web_app|api|mobile|physical|social_engineering|red_team",

  "roeExcludedHosts": ["IPs/domains explicitly excluded from testing"],
  "roeExcludedHostReasons": ["reason for each exclusion, parallel array"],

  "roeTimeWindowEnabled": true,
  "roeTimeWindowTimezone": "timezone (e.g. America/New_York, Europe/Rome)",
  "roeTimeWindowDays": ["monday","tuesday"],
  "roeTimeWindowStartTime": "HH:MM",
  "roeTimeWindowEndTime": "HH:MM",

  "roeForbiddenCategories": ["brute_force, dos, social_engineering, physical"],
  "roeMaxSeverityPhase": "informational|exploitation|post_exploitation",
  "agentToolPhaseMap": "ONLY set this if the RoE says something like 'do not use Hydra' or 'tool X is forbidden'. Set the forbidden tool to []. Example: if the RoE says 'Hydra must not be used', return {\"execute_hydra\": []}. 'discouraged' or 'use with caution' does NOT count — only an explicit unconditional ban. Return null if no tool is explicitly banned by name.",
  "roeAllowDos": false,
  "roeAllowSocialEngineering": false,
  "roeAllowPhysicalAccess": false,
  "roeAllowDataExfiltration": false,
  "roeAllowAccountLockout": false,
  "roeAllowProductionTesting": true,

  "roeGlobalMaxRps": 0,

  "roeSensitiveDataHandling": "no_access|prove_access_only|limited_collection|full_access",
  "roeDataRetentionDays": 90,
  "roeRequireDataEncryption": true,

  "roeStatusUpdateFrequency": "daily|weekly|on_finding|none",
  "roeCriticalFindingNotify": true,
  "roeIncidentProcedure": "description of incident response procedure",

  "roeThirdPartyProviders": ["cloud/hosting providers needing separate authorization"],
  "roeComplianceFrameworks": ["PCI-DSS", "HIPAA", "SOC2", "GDPR", "ISO27001"],

  "roeNotes": "any other rules, restrictions, or guidance not captured above",

  "naabuRateLimit": null,
  "nucleiRateLimit": null,
  "katanaRateLimit": null,
  "httpxRateLimit": null,
  "nucleiSeverity": null,
  "scanModules": null
}

IMPORTANT RULES:
- If DoS is prohibited, set roeAllowDos=false AND add "dos" to roeForbiddenCategories
- If social engineering is prohibited, set roeAllowSocialEngineering=false AND add "social_engineering" to roeForbiddenCategories
- If brute force is EXPLICITLY forbidden (not just "discouraged"), add "brute_force" to roeForbiddenCategories AND set execute_hydra to [] in agentToolPhaseMap
- For phase restrictions (e.g. "no post-exploitation", "reconnaissance only"), ONLY set roeMaxSeverityPhase. Do NOT touch agentToolPhaseMap for phase-level restrictions.
- If a global rate limit is specified, also set individual tool rate limits to that value
- Map compliance requirements (PCI, HIPAA, etc.) to roeComplianceFrameworks
- "discouraged", "use with caution", or "avoid unattended use" does NOT mean forbidden. Only disable a tool if the RoE explicitly says "do not use [tool]" or "[tool] is prohibited/forbidden".
- agentToolPhaseMap: Return null unless the RoE explicitly bans a specific tool by name with words like "forbidden", "prohibited", "must not be used", or "not permitted".

RoE Document:
---
{document_text}
---"""


@app.post("/roe/parse", tags=["RoE"])
async def parse_roe_document(body: RoeParseRequest):
    """Parse a Rules of Engagement document using the LLM and extract structured settings."""
    import json as json_mod
    from project_settings import DEFAULT_AGENT_SETTINGS

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    # Use the requested model, or fall back to orchestrator's current LLM
    from orchestrator_helpers.llm_setup import setup_llm

    requested_model = body.model or DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        llm = _setup_llm_for_endpoint(requested_model)
    except Exception as e:
        logger.error(f"RoE parse: failed to set up LLM ({requested_model}): {e}")
        return JSONResponse(content={"error": f"LLM not available for model {requested_model}"}, status_code=503)

    try:
        # System message has instructions only; user document goes in HumanMessage
        # to reduce prompt injection risk from adversarial document content
        system_prompt = _ROE_PARSE_PROMPT.split("RoE Document:\n---")[0].strip()
        doc_text = body.text[:50000]
        logger.info(f"RoE parse: using model {requested_model}")
        response = await llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"RoE Document:\n---\n{doc_text}\n---\n\nParse the RoE document above and return the JSON."),
        ])
        content = normalize_content(response.content).strip()

        # Strip markdown code fences if present (handle ```json, ```JSON, ``` json, etc.)
        import re
        fence_match = re.search(r'```(?:json)?\s*\n(.*?)```', content, re.DOTALL | re.IGNORECASE)
        if fence_match:
            content = fence_match.group(1).strip()
        else:
            # Fallback: try to extract first JSON object
            brace_start = content.find('{')
            if brace_start > 0:
                content = content[brace_start:]
            # Strip trailing non-JSON
            brace_end = content.rfind('}')
            if brace_end >= 0 and brace_end < len(content) - 1:
                content = content[:brace_end + 1]

        parsed = json_mod.loads(content)
        return parsed

    except json_mod.JSONDecodeError as e:
        logger.error(f"RoE parse: invalid JSON from LLM: {e}")
        return JSONResponse(
            content={"error": f"LLM returned invalid JSON: {str(e)}"},
            status_code=422,
        )
    except Exception as e:
        logger.error(f"RoE parse error: {e}")
        return JSONResponse(
            content={"error": f"Failed to parse RoE document: {str(e)}"},
            status_code=500,
        )


# =============================================================================
# REPORT SUMMARIZER — LLM-generated narratives for pentest report sections
# =============================================================================

class ReportSummarizeRequest(BaseModel):
    """Request model for report narrative generation."""
    data: dict
    model: str | None = None


@app.post("/api/report/summarize", tags=["Report"])
async def summarize_report(body: ReportSummarizeRequest):
    """Generate LLM narrative summaries for pentest report sections."""
    from orchestrator_helpers.report_summarizer import generate_report_narratives
    from project_settings import DEFAULT_AGENT_SETTINGS
    from orchestrator_helpers.llm_setup import setup_llm

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    requested_model = body.model or DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        llm = _setup_llm_for_endpoint(requested_model)
    except Exception as e:
        logger.error(f"Report summarizer: failed to set up LLM ({requested_model}): {e}")
        return JSONResponse(content={"error": f"LLM not available for model {requested_model}"}, status_code=503)

    try:
        narratives = await generate_report_narratives(llm, body.data)
        return narratives
    except Exception as e:
        logger.error(f"Report summarizer error: {e}")
        return JSONResponse(
            content={"error": f"Failed to generate report narratives: {str(e)}"},
            status_code=500,
        )


class FfufExtensionsRequest(BaseModel):
    url: str
    headers: dict
    model: str
    max_extensions: int = 6
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_FFUF_EXT_SYSTEM_PROMPT = """You are a security testing assistant helping with directory fuzzing.

Given a target URL and its HTTP response headers, suggest the file extensions
most likely to discover real files on this server. Use header signals
(Server, X-Powered-By, Set-Cookie like JSESSIONID, framework hints) and the
URL path context to choose suffixes.

Rules:
- Path-aware: if the path is /js/ or /static/, prefer no extensions or only
  source-map/config-style extensions (.map). For /api/ prefer .json, .xml.
- Tech-aware: Apache+PHP -> .php, .phtml, .bak. IIS/ASP.NET -> .aspx, .asmx,
  .config. Tomcat/Java -> .jsp, .do, .action.
- Always include a small tail of generic backup/config suffixes when the
  path looks admin-like: .bak, .old, .config, .zip.
- Each extension must start with '.' and be a-z/0-9 only, max 8 chars.
- If the path is clearly a CDN/static asset path with no useful suffixes,
  return an empty list -- do not invent.
- Never include leading wildcards or directory separators.

Respond with ONLY a JSON object of this exact shape, no prose:
{"extensions": [".ext1", ".ext2", ...]}"""


def _build_llm_with_model_for_user(model_name: str, user_id: Optional[str]):
    """Build an LLM using the user's saved providers but force a specific model.
    Mirrors `_build_llm_for_user` but takes the model as an explicit argument
    instead of reading it from project settings."""
    import os
    import requests as requests_mod
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key

    user_providers: list = []
    if user_id:
        webapp_url = os.environ.get('WEBAPP_URL', 'http://webapp:3000')
        internal_key = os.environ.get('INTERNAL_API_KEY', '')
        try:
            resp = requests_mod.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
                headers={'x-internal-key': internal_key} if internal_key else {},
                timeout=10,
            )
            resp.raise_for_status()
            user_providers = resp.json() or []
        except Exception as e:
            logger.warning(f"ffuf-extensions: failed to fetch user LLM providers: {e}")

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")
    deepseek_p = _resolve_provider_key(user_providers, "deepseek")
    gemini_p = _resolve_provider_key(user_providers, "gemini")
    glm_p = _resolve_provider_key(user_providers, "glm")
    kimi_p = _resolve_provider_key(user_providers, "kimi")
    qwen_p = _resolve_provider_key(user_providers, "qwen")
    xai_p = _resolve_provider_key(user_providers, "xai")
    mistral_p = _resolve_provider_key(user_providers, "mistral")
    return setup_llm(
        model_name,
        openai_api_key=(openai_p or {}).get("apiKey"),
        anthropic_api_key=(anthropic_p or {}).get("apiKey"),
        openrouter_api_key=(openrouter_p or {}).get("apiKey"),
        deepseek_api_key=(deepseek_p or {}).get("apiKey"),
        gemini_api_key=(gemini_p or {}).get("apiKey"),
        glm_api_key=(glm_p or {}).get("apiKey"),
        kimi_api_key=(kimi_p or {}).get("apiKey"),
        qwen_api_key=(qwen_p or {}).get("apiKey"),
        xai_api_key=(xai_p or {}).get("apiKey"),
        mistral_api_key=(mistral_p or {}).get("apiKey"),
        aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
        aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
        aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
        aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
    )


@app.post("/llm/ffuf-extensions", tags=["LLM"])
async def llm_ffuf_extensions(body: FfufExtensionsRequest):
    """Suggest FFuf file extensions for a target based on its response headers.

    Called by the recon container's AI planner when FFUF_AI_EXTENSIONS is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "ffuf-extensions: url=%s model=%s user=%s headers=%d-keys",
        body.url, body.model, body.user_id, len(body.headers or {}),
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except Exception as e:
        logger.error(f"ffuf-extensions: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    user_msg = (
        f"URL: {body.url}\n"
        f"Headers: {json_mod.dumps(body.headers)}\n"
        f"Suggest up to {body.max_extensions} extensions."
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_FFUF_EXT_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"ffuf-extensions: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    # Strip ``` fences if the model wrapped the JSON
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"ffuf-extensions: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    extensions = data.get('extensions', [])
    if not isinstance(extensions, list):
        return JSONResponse(content={"error": "Model returned non-list extensions", "raw": str(extensions)[:500]}, status_code=502)

    return {"extensions": extensions[:body.max_extensions]}


class NucleiTagsRequest(BaseModel):
    technologies: list[str]
    servers: list[str]
    current_tags: list[str]
    candidates: list[str]
    model: str
    max_tags: int = 15
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_NUCLEI_TAGS_SYSTEM_PROMPT = """You are a security testing assistant selecting Nuclei
template tags for a vulnerability scan. Given a tech stack fingerprint, pick the
tags most likely to find real vulnerabilities and drop irrelevant ones.

Rules:
- You MUST pick ONLY from the `candidates` list provided. Any tag not in
  candidates will be rejected.
- ALWAYS keep universal high-impact tags when present in candidates: cve,
  exposure, misconfig, default-login, kev, oast, takeover.
- INCLUDE tech-specific tags ONLY when the technology is detected:
    WordPress signal -> wordpress, wp-plugin, wp (when in candidates)
    Apache signal    -> apache
    Nginx signal     -> nginx
    IIS / ASP.NET    -> iis, dotnet
    Tomcat / JVM     -> tomcat, java
    PHP signal       -> php
    Node/React/Express signal -> nodejs
    Joomla / Drupal / Magento / Jenkins / GitLab / Jira / Confluence -> their tag
    AWS / Azure / GCP / cloud signal -> their cloud tag
- DROP tech tags whose stack is NOT detected. Do not invent technologies that
  are not in the input.
- DROP narrow vuln-class tags that don't fit the stack (e.g. drop xxe on pure-JS
  apps with no XML, drop ssti if no template engine signal, drop sqli if the
  app appears static).
- Cap output at `max_tags` (default 15). Prefer breadth over redundancy.
- Be conservative: if unsure whether a tag matches, drop it.

Respond with ONLY a JSON object of this exact shape, no prose:
{"tags": ["tag1", "tag2", ...]}"""


@app.post("/llm/nuclei-tags", tags=["LLM"])
async def llm_nuclei_tags(body: NucleiTagsRequest):
    """Suggest Nuclei tags for a vuln scan based on tech fingerprint.

    Called by the recon container's AI planner when NUCLEI_AI_TAGS is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "nuclei-tags: model=%s user=%s techs=%d servers=%d candidates=%d",
        body.model, body.user_id, len(body.technologies or []),
        len(body.servers or []), len(body.candidates or []),
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except Exception as e:
        logger.error(f"nuclei-tags: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    user_msg = (
        f"Detected technologies: {json_mod.dumps(body.technologies)}\n"
        f"Detected servers: {json_mod.dumps(body.servers)}\n"
        f"User's current tags: {json_mod.dumps(body.current_tags)}\n"
        f"Candidates (pick only from these): {json_mod.dumps(body.candidates)}\n"
        f"Pick up to {body.max_tags} tags."
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_TAGS_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"nuclei-tags: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"nuclei-tags: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    tags = data.get('tags', [])
    if not isinstance(tags, list):
        return JSONResponse(content={"error": "Model returned non-list tags", "raw": str(tags)[:500]}, status_code=502)

    return {"tags": tags[:body.max_tags]}


class WafClassifyRequest(BaseModel):
    url: str
    status_code: int
    headers: dict
    body_sample: str = ""
    response_time_ms: int = 0
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_WAF_CLASSIFY_SYSTEM_PROMPT = """You are a security testing assistant classifying whether
an HTTP response came through a WAF (Web Application Firewall) or CDN edge layer.
Your output drives downstream throttling and false-positive filtering, so calibrated
confidence matters more than guessing a vendor.

You will receive: target URL, HTTP status code, full response headers, the first
4KB of the response body, and an optional response_time_ms hint.

Detection signals to weigh:
- Header tokens (vendor-branded): cf-ray, cf-cache-status, x-amz-cf-id, x-served-by,
  x-akamai-*, x-fastly-request-id, x-azure-ref, x-azure-fdid, x-sucuri-id, x-iinfo
  (Imperva), Server: cloudflare/cloudfront/akamai/fastly/varnish/imperva/sucuri.
- Cookie tokens: __cf_bm, cf_clearance, __cfduid (cloudflare), incap_ses_, visid_incap_
  (imperva), AKA_A2/AKAALB_ (akamai), awsalb (AWS), TS01* (BIG-IP/F5).
- Body fingerprints: "Attention Required! | Cloudflare", "error 1003", "Request blocked",
  "Access denied", "Reference #", challenge-page HTML structures, captcha widgets,
  Akamai "Pragma" pages, AWS WAF "Request blocked" JSON.
- Status+body mismatch: 200 OK with a tiny "blocked" body, 403 with branded reason
  phrase, 406/418/429 returned for benign requests.
- Latency outliers: response_time_ms >> 200ms for a static-looking 403 hints at
  inspection delay.
- Status codes commonly used by WAFs to short-circuit: 403, 406, 418, 429, 503.

WAF type values you may emit (lowercase, snake/kebab):
cloudflare, akamai, aws_waf, imperva, sucuri, fastly, azure_frontdoor, cloudfront,
modsecurity, f5, fortinet, barracuda, stackpath, custom. Use null for waf_type when
waf_detected is false. Use "custom" if signals indicate a WAF but vendor is unclear.

Confidence calibration (be honest, not optimistic):
- 90-100: clear vendor branding in multiple places (header + cookie + body)
- 70-89: strong fingerprint (one branded header OR challenge-page body)
- 40-69: suggestive signals (status+body mismatch, latency, no vendor token)
- 10-39: weak hints, mostly speculative
- 0-9:   no signal at all (return waf_detected=false)

Reasoning field: ONE sentence (<=200 chars) citing the strongest signals.

Respond with ONLY a JSON object of this exact shape, no prose:
{"waf_detected": true|false, "waf_type": "cloudflare"|null, "confidence": 0..100, "reasoning": "..."}"""


@app.post("/llm/waf-classify", tags=["LLM"])
async def llm_waf_classify(body: WafClassifyRequest):
    """Classify whether a response came through a WAF/CDN.

    Called by the recon container's WAF AI classifier when WAF_AI_CLASSIFIER is on.
    Reuses the same per-user LLM provider resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "waf-classify: url=%s status=%d model=%s user=%s headers=%d body=%dB rt=%dms",
        body.url, body.status_code, body.model, body.user_id,
        len(body.headers or {}), len(body.body_sample or ''), body.response_time_ms,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except Exception as e:
        logger.error(f"waf-classify: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    user_msg = (
        f"URL: {body.url}\n"
        f"Status: {body.status_code}\n"
        f"Response time (ms): {body.response_time_ms}\n"
        f"Headers: {json_mod.dumps(body.headers)}\n"
        f"Body sample (first 4KB):\n{body.body_sample}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_WAF_CLASSIFY_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"waf-classify: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"waf-classify: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    detected = data.get('waf_detected')
    confidence = data.get('confidence')
    if not isinstance(detected, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "waf_detected": detected,
        "waf_type": data.get('waf_type'),
        "confidence": int(confidence),
        "reasoning": (data.get('reasoning') or '')[:500],
    }


class NucleiFpFilterRequest(BaseModel):
    template_id: str
    tags: list[str] = []
    status_line: str = ""
    response_sample: str = ""
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_NUCLEI_FP_FILTER_SYSTEM_PROMPT = """You are a security testing assistant deciding
whether a Nuclei response is a real vulnerability hit or a WAF/rate-limit block
page disguised as one. Your verdict gates the finding -- a wrong "blocked" call
HIDES a real vuln, a wrong "real" call SHIPS a false positive. Calibrate.

You will receive: Nuclei template id, template tags (sqli/xss/rce/...), HTTP
status line, and the first 4KB of the response body.

Block-page signals (lean toward is_blocked=true):
- Status 403/406/418/429/503 paired with a tiny generic body.
- Body contains vendor-branded WAF text: "Cloudflare Ray ID", "Reference #",
  "Request ID:", "AWS WAF", "Imperva Incapsula", "Sucuri", "ModSecurity",
  "Forbidden by F5", "Fortinet". Note: a body MENTIONING WAF terms in a
  legitimate context (admin panel, docs) is NOT a block; look at structure.
- Body is a generic 1-2 line error: "Access Denied", "Request blocked",
  "Sorry, your request couldn't be processed".
- AWS WAF JSON shape: {"message": "Forbidden"} or similar minimal JSON error.
- Cookies set in response: __cf_bm, cf_clearance, incap_ses_, visid_incap_,
  AKA_A2, awsalb, TS01* (BIG-IP/F5).
- Body is a captcha/challenge page: "Please verify you are human", JS challenge
  redirect, "Just a moment...".

Real-finding signals (lean toward is_blocked=false):
- Status 200/302 with substantive content (DB error message, reflected payload,
  exposed file content, version banner, debug page).
- Body contains actual evidence the template was looking for: SQL error string,
  reflected XSS payload echo, OS command output, leaked stack trace, file system
  paths, debug variable dumps.
- Body discusses WAF terms in CONTEXT (e.g. an admin panel that lets you toggle
  WAF settings) -- that's the page being exposed, not the page blocking you.
- Status code matches what the template hunts for (e.g. 200 for an exposure
  template, 500 for a backend error template).

Confidence calibration (be honest):
- 90-100: clear vendor branding (WAF cookie + status + branded body).
- 70-89: strong block-page shape (small body + suspicious status + generic
  error tone) OR strong real-hit shape (clear template-target evidence).
- 40-69: ambiguous (small 403 with no vendor signature, could be either).
- 10-39: weak hint, mostly speculative.
- 0-9: no signal -- return is_blocked=false.

Reason field: ONE sentence (<=200 chars) citing the strongest signal.

Respond with ONLY a JSON object of this exact shape, no prose:
{"is_blocked": true|false, "confidence": 0..100, "reason": "..."}"""


@app.post("/llm/nuclei-fp-filter", tags=["LLM"])
async def llm_nuclei_fp_filter(body: NucleiFpFilterRequest):
    """Classify whether a Nuclei response is a WAF/rate-limit block page
    rather than a real vulnerability hit.

    Called by the recon container's Nuclei FP filter when
    NUCLEI_AI_RESPONSE_FILTER is on. Reuses the same per-user LLM provider
    resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "nuclei-fp-filter: template=%s tags=%s status=%s body=%dB model=%s user=%s",
        body.template_id, body.tags, body.status_line[:60],
        len(body.response_sample or ''), body.model, body.user_id,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except Exception as e:
        logger.error(f"nuclei-fp-filter: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    user_msg = (
        f"Template: {body.template_id}\n"
        f"Tags: {json_mod.dumps(body.tags)}\n"
        f"Status: {body.status_line}\n"
        f"Response sample (first 4KB):\n{body.response_sample}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_FP_FILTER_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"nuclei-fp-filter: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"nuclei-fp-filter: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    is_blocked = data.get('is_blocked')
    confidence = data.get('confidence')
    if not isinstance(is_blocked, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "is_blocked": is_blocked,
        "confidence": int(confidence),
        "reason": (data.get('reason') or '')[:500],
    }


class TakeoverClassifyRequest(BaseModel):
    hostname: str
    expected_provider: str = ""
    status_code: int = 0
    headers: dict = {}
    response_sample: str = ""
    model: str
    user_id: Optional[str] = None
    project_id: Optional[str] = None


_TAKEOVER_CLASSIFY_SYSTEM_PROMPT = """You are a security testing assistant deciding
whether an HTTP response is a genuine third-party SaaS "service unclaimed" page
(a real subdomain takeover candidate) or a WAF block page that LOOKS like one.

Subdomain takeover detectors (Subjack, Nuclei takeover templates) match against
fingerprint strings like "There's nothing here yet" (Heroku), "NoSuchBucket"
(S3), "The page you have requested does not exist" (Bitbucket). WAFs and CDN
edges with no origin configured for a hostname return very similar text. The
collision produces critical-severity false positives that page on-call.

You will receive: hostname, the takeover provider the static signature claimed
to match, HTTP status code, response headers, and the first 4KB of the
response body.

WAF-block signals (lean is_waf_block=true):
- Status 403/406/429/503 (most SaaS unclaimed pages return 404).
- Body is a generic 1-2 line error with no provider branding.
- Body contains vendor WAF signatures: "Cloudflare Ray ID", "Reference #",
  "AWS WAF", "Imperva", "Akamai", "Sucuri", "ModSecurity", "Forbidden by F5".
- Cookies set: __cf_bm, cf_clearance, incap_ses_, awsalb, TS01*, akamai-*.
- Response body claims "blocked" / "denied" / "unauthorized" without naming
  the SaaS provider the static fingerprint claimed.
- Body shape mismatches the claimed provider (e.g. claimed "heroku" but the
  body has no Heroku branding, dyno mention, or characteristic styling).

Genuine-unclaimed signals (lean is_waf_block=false):
- Status 404 with body that EXPLICITLY names the claimed provider:
  - heroku: "There's nothing here yet", references herokuapp.com
  - s3: "NoSuchBucket", "The specified bucket does not exist"
  - github pages: "There isn't a GitHub Pages site here"
  - bitbucket: "Repository not found"
  - netlify/vercel/surge: provider-branded "site not found" pages
- Body has provider-specific HTML structure (Heroku error theme, S3 XML
  error, GitHub octocat).
- Headers include the SaaS edge's Server token (Server: AmazonS3,
  GitHub.com, Netlify, Vercel) -- this is unambiguous proof.

Special case -- AMBIGUOUS but lean WAF when:
- Generic "page not found" 404 with NO provider branding at all (could be
  either; absence of provider signal is itself suspicious for a real
  takeover).

Confidence calibration:
- 90-100: clear vendor branding (WAF cookie/branded body OR clear SaaS-
  branded unclaimed page).
- 70-89: strong shape signal (clean WAF block tone OR clean SaaS error).
- 40-69: ambiguous, no clear vendor token either way.
- 10-39: weak hint.
- 0-9: no signal.

Reason field: ONE sentence (<=200 chars) citing the strongest signal.

Respond with ONLY a JSON object of this exact shape, no prose:
{"is_waf_block": true|false, "confidence": 0..100, "reason": "..."}"""


@app.post("/llm/takeover-classify", tags=["LLM"])
async def llm_takeover_classify(body: TakeoverClassifyRequest):
    """Disambiguate a takeover finding from a WAF block masquerading as one.

    Called by the recon container's takeover scanner when
    TAKEOVER_AI_CLASSIFIER is on. Reuses the same per-user LLM provider
    resolution as the agent itself.
    """
    import json as json_mod

    logger.info(
        "takeover-classify: host=%s provider=%s status=%d body=%dB model=%s user=%s",
        body.hostname, body.expected_provider, body.status_code,
        len(body.response_sample or ''), body.model, body.user_id,
    )

    try:
        llm = _build_llm_with_model_for_user(body.model, body.user_id)
    except Exception as e:
        logger.error(f"takeover-classify: cannot set up LLM: {e}")
        return JSONResponse(content={"error": f"LLM not configured: {e}"}, status_code=503)

    user_msg = (
        f"Hostname: {body.hostname}\n"
        f"Claimed provider: {body.expected_provider}\n"
        f"Status: {body.status_code}\n"
        f"Headers: {json_mod.dumps(body.headers)}\n"
        f"Response sample (first 4KB):\n{body.response_sample}"
    )

    try:
        response = await llm.ainvoke([
            SystemMessage(content=_TAKEOVER_CLASSIFY_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])
    except Exception as e:
        logger.error(f"takeover-classify: LLM call failed: {e}")
        return JSONResponse(content={"error": f"LLM call failed: {e}"}, status_code=502)

    raw_text = normalize_content(getattr(response, 'content', None)).strip()
    if raw_text.startswith('```'):
        raw_text = raw_text.strip('`')
        if raw_text.startswith('json'):
            raw_text = raw_text[4:].strip()

    try:
        data = json_mod.loads(raw_text)
    except (json_mod.JSONDecodeError, ValueError) as e:
        logger.warning(f"takeover-classify: model returned non-JSON ({e}): {raw_text[:200]}")
        return JSONResponse(content={"error": "Model returned non-JSON", "raw": raw_text[:500]}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse(content={"error": "Model returned non-object", "raw": str(data)[:500]}, status_code=502)

    is_waf_block = data.get('is_waf_block')
    confidence = data.get('confidence')
    if not isinstance(is_waf_block, bool) or not isinstance(confidence, (int, float)):
        return JSONResponse(content={"error": "Model returned malformed schema", "raw": str(data)[:500]}, status_code=502)

    return {
        "is_waf_block": is_waf_block,
        "confidence": int(confidence),
        "reason": (data.get('reason') or '')[:500],
    }


@app.post("/emergency-stop-all", tags=["System"])
async def emergency_stop_all():
    """Emergency stop: cancel every running agent task immediately."""
    if not ws_manager:
        return JSONResponse(content={"stopped": 0}, status_code=503)
    stopped = await ws_manager.stop_all()
    logger.warning(f"Emergency stop: cancelled {stopped} agent task(s)")
    return {"stopped": stopped}


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Health check endpoint.

    Returns the API status, version, number of loaded tools, and active sessions.
    """
    tools_count = 0
    if orchestrator and orchestrator.tool_executor:
        tools_count = len(orchestrator.tool_executor.get_all_tools())

    sessions_count = get_session_count()

    # Count in-flight fireteam waves by scanning active asyncio tasks for
    # names starting with "fireteam-" (set by fireteam_deploy_node). Cheap
    # probe — no DB roundtrip.
    active_waves = 0
    try:
        for task in asyncio.all_tasks():
            name = task.get_name() or ""
            if name.startswith("fireteam-"):
                active_waves += 1
    except Exception:
        pass

    from project_settings import get_setting
    return HealthResponse(
        status="ok" if orchestrator and orchestrator._initialized else "initializing",
        version="3.0.0",
        tools_loaded=tools_count,
        active_sessions=sessions_count,
        fireteam_enabled=bool(get_setting("FIRETEAM_ENABLED", False)),
        persistent_checkpointer=bool(get_setting("PERSISTENT_CHECKPOINTER", False)),
        active_waves=active_waves,
    )


def _setup_llm_for_endpoint(model_name: str) -> "BaseChatModel":
    """Set up an LLM for non-agent endpoints (RoE parse, report summarizer).

    Uses the orchestrator's loaded project settings (user LLM providers from DB).
    """
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import get_settings

    settings = get_settings()
    user_providers = settings.get('USER_LLM_PROVIDERS', [])
    custom_config = settings.get('CUSTOM_LLM_CONFIG')

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")
    deepseek_p = _resolve_provider_key(user_providers, "deepseek")
    gemini_p = _resolve_provider_key(user_providers, "gemini")
    glm_p = _resolve_provider_key(user_providers, "glm")
    kimi_p = _resolve_provider_key(user_providers, "kimi")
    qwen_p = _resolve_provider_key(user_providers, "qwen")
    xai_p = _resolve_provider_key(user_providers, "xai")
    mistral_p = _resolve_provider_key(user_providers, "mistral")

    return setup_llm(
        model_name,
        openai_api_key=(openai_p or {}).get("apiKey"),
        anthropic_api_key=(anthropic_p or {}).get("apiKey"),
        openrouter_api_key=(openrouter_p or {}).get("apiKey"),
        deepseek_api_key=(deepseek_p or {}).get("apiKey"),
        gemini_api_key=(gemini_p or {}).get("apiKey"),
        glm_api_key=(glm_p or {}).get("apiKey"),
        kimi_api_key=(kimi_p or {}).get("apiKey"),
        qwen_api_key=(qwen_p or {}).get("apiKey"),
        xai_api_key=(xai_p or {}).get("apiKey"),
        mistral_api_key=(mistral_p or {}).get("apiKey"),
        aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
        aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
        aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
        aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
        custom_llm_config=custom_config,
    )


# =============================================================================
# TRADECRAFT — Verify endpoint for the per-user knowledge resource catalog
# =============================================================================

class TradecraftVerifyRequest(BaseModel):
    url: str
    user_id: Optional[str] = None      # used to load the user's LLM provider keys
    github_token: Optional[str] = None
    force: bool = False
    # Per-resource model override. When set, the verify endpoint builds a
    # provider-agnostic LLM for THIS model (resolving the user's provider
    # keys) instead of reusing orchestrator.llm. Decouples tradecraft
    # ingestion from the agent's current chat model and from project-load
    # order (fixes the "agent reverted to default Anthropic after restart"
    # 401 path).
    model: Optional[str] = None


_CUSTOM_PROVIDER_TYPES = ("openai_compatible", "bedrock_custom", "ollama_local")


def _pick_custom_provider(user_providers: list, model_name: str) -> Optional[dict]:
    """Return the custom-provider record that should serve this request, if any.

    Resolution order:
      1. If `model_name` is `custom/<id>`, look up that exact provider id.
      2. Otherwise, the first provider whose providerType is custom.
    Returns None when no custom provider is configured.
    """
    if model_name and model_name.startswith("custom/"):
        wanted_id = model_name[len("custom/"):]
        for p in user_providers or []:
            if p.get("id") == wanted_id:
                return p
    for p in user_providers or []:
        if p.get("providerType") in _CUSTOM_PROVIDER_TYPES:
            return p
    return None


def _build_llm_for_user(user_id: Optional[str]):
    """Build an LLM for a non-project endpoint by loading the user's providers
    via the internal webapp API. Falls back to env-based providers when user_id
    is missing or the lookup fails.

    When the user has only a custom (OpenAI-compatible / bedrock_custom /
    ollama_local) provider configured, this honors it instead of falling back
    to the global default model — otherwise the call would crash trying to
    instantiate an Anthropic client with no key.
    """
    import os
    import requests
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import DEFAULT_AGENT_SETTINGS, get_settings

    model_name = (get_settings() or {}).get(
        'OPENAI_MODEL', DEFAULT_AGENT_SETTINGS.get('OPENAI_MODEL', 'claude-opus-4-6')
    )
    user_providers: list = []
    if user_id:
        webapp_url = os.environ.get('WEBAPP_URL', 'http://webapp:3000')
        internal_key = os.environ.get('INTERNAL_API_KEY', '')
        try:
            resp = requests.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
                headers={'x-internal-key': internal_key} if internal_key else {},
                timeout=10,
            )
            resp.raise_for_status()
            user_providers = resp.json() or []
        except Exception as e:
            logger.warning(f"tradecraft verify: failed to fetch user LLM providers: {e}")

    custom_provider = _pick_custom_provider(user_providers, model_name)
    if custom_provider:
        custom_model = f"custom/{custom_provider.get('id', '')}"
        logger.info(
            f"tradecraft verify: using custom provider id={custom_provider.get('id')} "
            f"type={custom_provider.get('providerType')}"
        )
        return setup_llm(custom_model, custom_llm_config=custom_provider)

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")
    deepseek_p = _resolve_provider_key(user_providers, "deepseek")
    gemini_p = _resolve_provider_key(user_providers, "gemini")
    glm_p = _resolve_provider_key(user_providers, "glm")
    kimi_p = _resolve_provider_key(user_providers, "kimi")
    qwen_p = _resolve_provider_key(user_providers, "qwen")
    xai_p = _resolve_provider_key(user_providers, "xai")
    mistral_p = _resolve_provider_key(user_providers, "mistral")
    return setup_llm(
        model_name,
        openai_api_key=(openai_p or {}).get("apiKey"),
        anthropic_api_key=(anthropic_p or {}).get("apiKey"),
        openrouter_api_key=(openrouter_p or {}).get("apiKey"),
        deepseek_api_key=(deepseek_p or {}).get("apiKey"),
        gemini_api_key=(gemini_p or {}).get("apiKey"),
        glm_api_key=(glm_p or {}).get("apiKey"),
        kimi_api_key=(kimi_p or {}).get("apiKey"),
        qwen_api_key=(qwen_p or {}).get("apiKey"),
        xai_api_key=(xai_p or {}).get("apiKey"),
        mistral_api_key=(mistral_p or {}).get("apiKey"),
        aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
        aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
        aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
        aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
    )


@app.post("/tradecraft/verify", tags=["Tradecraft"])
async def tradecraft_verify(body: TradecraftVerifyRequest):
    """
    Fetch a tradecraft resource URL, detect its type, build a sitemap, and
    LLM-summarize its scope. Called by the webapp `/api/users/{id}/tradecraft-resources/{rid}/verify` route.
    """
    from orchestrator_helpers.tradecraft_lookup import verify_resource
    from project_settings import DEFAULT_AGENT_SETTINGS

    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(
            {"error": "Agent not initialized"}, status_code=503
        )
    # SSRF / scheme validation runs BEFORE LLM setup so a private-IP probe
    # never wakes the LLM client. verify_resource also re-validates internally,
    # but failing fast here keeps the path symmetric with the webapp guard.
    from orchestrator_helpers.tradecraft_lookup import validate_url
    ok, err = validate_url(body.url)
    if not ok:
        return {
            "summary": "",
            "resource_type": "agentic-crawl",
            "sitemap": {},
            "crawl_stopped_because": "",
            "crawl_stats": {},
            "last_error": err,
        }
    # Resolve the LLM used for crawl decisions + summary:
    #   1. If the request specifies a per-resource model, build a provider-
    #      agnostic LLM for THAT model from the user's saved providers.
    #      (Same path the 5 recon AI classifiers use.) This is the normal
    #      path — the webapp always sends a model now that the field is
    #      required at create/edit time.
    #   2. Otherwise (back-compat for direct API callers and old rows
    #      written before this column existed), prefer the orchestrator's
    #      loaded LLM, then fall back to _build_llm_for_user.
    try:
        if body.model:
            llm = _build_llm_with_model_for_user(body.model, body.user_id)
        elif orchestrator.llm is not None:
            llm = orchestrator.llm
        else:
            llm = _build_llm_for_user(body.user_id)
    except Exception as e:
        logger.error(f"tradecraft verify: cannot set up LLM: {e}")
        return JSONResponse(
            {"error": f"LLM not configured: {e}"}, status_code=503
        )
    bounds = {
        "max_pages": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_PAGES", 30),
        "max_llm_calls": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_LLM_CALLS", 20),
        "time_budget_sec": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_TIME_BUDGET_SEC", 180),
        "max_depth": DEFAULT_AGENT_SETTINGS.get("TRADECRAFT_CRAWL_MAX_DEPTH", 3),
    }
    mcp_manager = getattr(orchestrator, "_mcp_manager", None)
    try:
        result = await verify_resource(
            body.url,
            github_token=body.github_token or "",
            force=body.force,
            llm=llm,
            mcp_manager=mcp_manager,
            bounds=bounds,
        )
        return result
    except Exception as exc:
        logger.error(f"tradecraft verify failed: {exc}")
        return JSONResponse(
            {"error": str(exc)}, status_code=500
        )


@app.get("/mcp/manifest", tags=["MCP"])
async def get_mcp_manifest():
    """
    Return the current MCP server manifest as seen by the agent.

    Combines the 5 system MCP servers (shipped with the product) and any
    user-managed servers loaded from the most recent project session. Auth
    tokens are NOT exposed — only env-var references.
    """
    import mcp_registry
    return {
        "servers": mcp_registry.redact_for_api(mcp_registry.current()),
        "errors": [e.model_dump() for e in mcp_registry.current_errors()],
        "warnings": [w.model_dump() for w in mcp_registry.current_warnings()],
        "system_server_ids": sorted(mcp_registry.SYSTEM_SERVER_IDS),
    }


@app.post("/mcp/reload", tags=["MCP"])
async def reload_mcp_manifest(payload: dict = None):
    """
    Re-merge system + user MCP servers and reconnect the MCP client.

    Called by the webapp after a user adds/edits/deletes an MCP server.
    Body (optional): {"userMcpServers": [...]} — when omitted, uses the
    most recent cached project settings.
    """
    if orchestrator is None:
        return JSONResponse({"error": "orchestrator not ready"}, status_code=503)

    user_servers_raw = None
    if isinstance(payload, dict):
        user_servers_raw = payload.get("userMcpServers")

    try:
        result = await orchestrator.reload_mcp_manifests(user_servers_raw)
        return result
    except Exception as exc:
        logger.exception(f"/mcp/reload failed: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.post("/mcp/test", tags=["MCP"])
async def test_mcp_server(server: dict):
    """
    Test connectivity to a single MCP server draft (NOT yet persisted).

    Builds a throwaway MultiServerMCPClient, calls list_tools(), tears it down.
    Does not mutate any agent state — safe to call while scans are in flight.
    """
    import mcp_registry
    import time
    from langchain_mcp_adapters.client import MultiServerMCPClient

    started = time.monotonic()
    parse_errors: list = []
    try:
        srv_obj = mcp_registry.MCPServer.model_validate(server)
    except Exception as exc:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": f"schema validation failed: {exc}",
            "warnings": [],
        }

    config_dict, env_warnings = mcp_registry.to_mcp_servers_dict([srv_obj])
    if not config_dict:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": "server is disabled — enable it before testing",
            "warnings": [w.model_dump() for w in env_warnings],
        }

    # Fast-fail check for stdio transport: missing/invalid `command`. The
    # full diagnostic spawn happens only on real-MCP-client failure below.
    if srv_obj.transport == "stdio" and not srv_obj.command:
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": "stdio transport requires a `command`",
            "warnings": [w.model_dump() for w in env_warnings],
        }

    def _stdio_diagnostic_stderr() -> Optional[str]:
        """
        Spawn the stdio MCP ourselves and capture stderr if it crashes.
        Used only when the real MCP client failed, to translate the
        SDK's opaque "Connection closed" into the actual reason
        (missing API key, npm package not found, etc.).

        Returns the formatted error string, or None if the process is
        still running after the timeout (in which case it's not an
        immediate-crash failure mode and we should fall back to the
        upstream message).
        """
        if srv_obj.transport != "stdio" or not srv_obj.command:
            return None
        import subprocess
        spawn_env = {**os.environ, **(srv_obj.env or {})}
        try:
            proc = subprocess.Popen(
                [srv_obj.command, *list(srv_obj.args or [])],
                env=spawn_env,
                cwd=srv_obj.cwd or None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return (
                f"command not found: '{srv_obj.command}'. Is it installed in "
                f"the agent container? (e.g. for npx-based MCPs ensure node, "
                f"for uvx ensure uv)"
            )
        except OSError as exc:
            return f"failed to spawn '{srv_obj.command}': {exc}"
        # Generous timeout: npx/uvx may need to fetch the package on first
        # run before the actual MCP server starts up and immediately
        # crashes on bad config. 25s covers cold cache for typical MCPs.
        try:
            stderr_text = proc.communicate(timeout=25.0)[1] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            return None
        # Pick the most informative slice of stderr. Node.js / Python
        # tracebacks print the actual `Error: <message>` line ABOVE the
        # stack trace, so a plain tail loses the message we care about.
        # Strategy: surface any line that looks like an error message,
        # then add the last few lines for context. Cap total length.
        all_lines = [ln for ln in stderr_text.splitlines() if ln.strip()]
        error_pattern = re.compile(
            r"^\s*(?:[A-Z][a-zA-Z]*Error|Exception|Traceback|throw\b|"
            r"FATAL|Cannot find|Missing|Required|environment variable)",
        )
        error_lines = [ln for ln in all_lines if error_pattern.search(ln)]
        # Combine: deduplicated error lines (preserve order) + last 8 lines.
        chosen: list[str] = []
        seen: set[str] = set()
        for ln in error_lines + all_lines[-8:]:
            stripped = ln.strip()
            if stripped and stripped not in seen:
                seen.add(stripped)
                chosen.append(stripped)
        if not chosen:
            chosen_str = "(no stderr output)"
        else:
            joined = " | ".join(chosen)
            chosen_str = joined if len(joined) <= 1500 else joined[:1500] + "…"
        return (
            f"stdio MCP exited (code {proc.returncode}) before/during MCP "
            f"handshake. stderr: {chosen_str}"
        )

    client = None
    try:
        client = MultiServerMCPClient(config_dict)

        # Open an MCP session and call list_tools at the protocol level.
        # This returns mcp.types.Tool objects with their raw inputSchema
        # JSON dict, exactly as the server published it — works with any
        # MCP-spec-compliant server regardless of how langchain happens
        # to wrap things.
        async def _fetch_raw_tools():
            async with client.session(srv_obj.id) as session:
                resp = await session.list_tools()
                return resp.tools

        raw_tools = await asyncio.wait_for(_fetch_raw_tools(), timeout=30.0)

        discovered = []
        declared_names = {t.name for t in srv_obj.tools}
        seen_names = set()
        for mcp_tool in raw_tools:
            name = getattr(mcp_tool, "name", None)
            if not name:
                continue
            seen_names.add(name)
            # inputSchema is a pydantic-modeled dict per the MCP spec.
            # model_dump() flattens it back to the canonical JSON Schema dict.
            schema = getattr(mcp_tool, "inputSchema", None)
            if hasattr(schema, "model_dump"):
                schema = schema.model_dump(exclude_none=True)
            elif not isinstance(schema, dict):
                schema = None
            discovered.append({
                "name": name,
                "description": getattr(mcp_tool, "description", "") or "",
                "input_schema": schema,
            })

        warnings = [w.model_dump() for w in env_warnings]
        for declared_name in declared_names - seen_names:
            warnings.append({
                "server_id": srv_obj.id, "code": "declared_not_live",
                "message": f"Tool '{declared_name}' declared in form but not returned by server.",
            })

        return {
            "ok": True,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": discovered,
            "error": None,
            "warnings": warnings,
        }
    except asyncio.TimeoutError:
        diag = _stdio_diagnostic_stderr()
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": diag or "connection timed out after 30s",
            "warnings": [w.model_dump() for w in env_warnings],
        }
    except BaseExceptionGroup as group:  # noqa: F821 — Python 3.11+
        # langchain_mcp_adapters wraps anyio TaskGroup failures in an
        # ExceptionGroup whose default str() is "unhandled errors in a
        # TaskGroup (1 sub-exception)" — useless. Recursively flatten
        # the leaves so the user sees the real cause (401, DNS error, etc).
        leaves: list[BaseException] = []
        def _flatten(g):
            for sub in g.exceptions:
                if isinstance(sub, BaseExceptionGroup):
                    _flatten(sub)
                else:
                    leaves.append(sub)
        _flatten(group)
        msg = "; ".join(f"{type(e).__name__}: {e}" for e in leaves) or str(group)
        logger.warning(f"/mcp/test ExceptionGroup unwrapped: {msg}")
        # For stdio "Connection closed"-style failures, the SDK swallows
        # the subprocess stderr. Re-spawn ourselves to capture the real
        # reason (missing API key, npm pkg not found, etc.).
        if srv_obj.transport == "stdio" and (
            "Connection closed" in msg or "ClosedResourceError" in msg or "BrokenPipe" in msg
        ):
            diag = _stdio_diagnostic_stderr()
            if diag:
                msg = diag
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": msg,
            "warnings": [w.model_dump() for w in env_warnings],
        }
    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        if srv_obj.transport == "stdio" and (
            "Connection closed" in msg or "ClosedResource" in msg or "BrokenPipe" in msg
        ):
            diag = _stdio_diagnostic_stderr()
            if diag:
                msg = diag
        return {
            "ok": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "discovered_tools": [],
            "error": msg,
            "warnings": [w.model_dump() for w in env_warnings],
        }
    finally:
        # Drop the throwaway client; rely on GC + peer SSE half-close.
        client = None


@app.get("/defaults", tags=["System"])
async def get_defaults():
    """
    Get default agent settings for frontend project creation.

    Returns DEFAULT_AGENT_SETTINGS with camelCase keys prefixed with 'agent'
    for frontend compatibility (e.g., OPENAI_MODEL -> agentOpenaiModel).
    """
    from project_settings import DEFAULT_AGENT_SETTINGS

    def to_camel_case(snake_str: str, prefix: str = "agent") -> str:
        """Convert SCREAMING_SNAKE_CASE to prefixCamelCase."""
        prefixed = f"{prefix}_{snake_str}" if prefix else snake_str
        components = prefixed.lower().split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    # STEALTH_MODE is a project-level setting (not agent-specific), served by
    # recon defaults as "stealthMode".  Exclude it here to avoid creating a
    # duplicate "agentStealthMode" key that Prisma doesn't recognise.
    SKIP_KEYS = {'STEALTH_MODE', 'USER_ATTACK_SKILLS'}

    # HYDRA_* keys map to Prisma fields without the 'agent' prefix
    # (e.g. HYDRA_ENABLED -> hydraEnabled, not agentHydraEnabled)
    NO_PREFIX_KEYS = {k for k in DEFAULT_AGENT_SETTINGS if k.startswith(('HYDRA_', 'PHISHING_', 'ROE_', 'ATTACK_SKILL_', 'SHODAN_', 'DOS_', 'FIRETEAM_'))}
    # Exclude internal-only fireteam keys that the frontend should not see.
    SKIP_KEYS = SKIP_KEYS | {'PERSISTENT_CHECKPOINTER'}

    camel_case_defaults = {}
    for k, v in DEFAULT_AGENT_SETTINGS.items():
        if k in SKIP_KEYS:
            continue
        if k in NO_PREFIX_KEYS:
            camel_case_defaults[to_camel_case(k, prefix="")] = v
        else:
            camel_case_defaults[to_camel_case(k)] = v

    return camel_case_defaults


class ModelsRequest(BaseModel):
    providers: list[dict] | None = None


@app.post("/models", tags=["System"])
async def get_models(body: ModelsRequest | None = None):
    """
    Fetch available AI models from all configured providers.

    Providers (a list of UserLlmProvider rows) are passed in the POST body
    rather than the URL to keep apiKey values out of uvicorn access logs.
    Falls back to env vars when the body is empty.
    """
    from orchestrator_helpers.model_providers import fetch_all_models

    provider_list = body.providers if body else None
    return await fetch_all_models(providers=provider_list)


# =============================================================================
# SKILLS — Infosec-skills-compatible skill catalog endpoint
# =============================================================================

@app.get("/skills", tags=["System"])
async def list_skills():
    """
    Return the catalog of all available Infosec-skills-compatible skills.

    Each entry contains: id, name, description, category.
    The frontend uses this to populate the skill selector in Project Settings.
    """
    from orchestrator_helpers.skill_loader import list_skills as _list_skills
    skills = _list_skills()
    return {"skills": skills, "total": len(skills)}


@app.get("/skills/{skill_id:path}", tags=["System"])
async def get_skill_content(skill_id: str):
    """Return full content of a specific skill."""
    from orchestrator_helpers.skill_loader import load_skill_content, list_skills as _list_skills
    content = load_skill_content(skill_id)
    if content is None:
        return JSONResponse({"error": f"Skill not found: {skill_id}"}, status_code=404)
    # Find metadata
    skills = _list_skills()
    meta = next((s for s in skills if s['id'] == skill_id), {})
    return {"id": skill_id, "name": meta.get("name", skill_id), "description": meta.get("description", ""), "category": meta.get("category", "general"), "content": content}


@app.get("/community-skills", tags=["System"])
async def list_community_skills():
    """Return catalog of community Agent Skills from agentic/community-skills/."""
    from pathlib import Path
    skills_dir = Path(__file__).parent / "community-skills"
    skills = []
    if skills_dir.exists():
        for md_file in sorted(skills_dir.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            name = md_file.stem.replace("_", " ").title()
            desc = ""
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    desc = stripped[:200]
                    break
            skills.append({
                "id": md_file.stem,
                "name": name,
                "description": desc,
                "file": str(md_file),
            })
    return {"skills": skills, "total": len(skills)}


@app.get("/community-skills/{skill_id}", tags=["System"])
async def get_community_skill_content(skill_id: str):
    """Return full content of a specific community Agent Skill."""
    from pathlib import Path
    skills_dir = Path(__file__).parent / "community-skills"
    skill_path = skills_dir / f"{skill_id}.md"
    if not skill_path.exists():
        return JSONResponse({"error": f"Community skill not found: {skill_id}"}, status_code=404)
    content = skill_path.read_text(encoding="utf-8")
    name = skill_id.replace("_", " ").title()
    return {"id": skill_id, "name": name, "content": content}


# =============================================================================
# LLM PROVIDER TEST — test a provider config with a simple message
# =============================================================================

class LlmProviderTestRequest(BaseModel):
    """Request model for testing an LLM provider config."""
    providerType: str = "openai_compatible"
    apiKey: str = ""
    baseUrl: str = ""
    modelIdentifier: str = ""
    defaultHeaders: dict = {}
    timeout: int = 120
    temperature: float = 0
    maxTokens: int = 16384
    sslVerify: bool = True
    awsRegion: str = "us-east-1"
    awsAccessKeyId: str = ""
    awsSecretKey: str = ""
    awsBearerToken: str = ""


@app.post("/llm-provider/test", tags=["System"])
async def test_llm_provider(body: LlmProviderTestRequest):
    """Test an LLM provider config by sending a simple message."""
    from orchestrator_helpers.llm_setup import setup_llm

    try:
        ptype = body.providerType

        if ptype == "openai":
            llm = setup_llm("gpt-4o-mini", openai_api_key=body.apiKey)
        elif ptype == "anthropic":
            # Connection check uses a current, valid alias (no date suffix).
            # Dated snapshots like claude-sonnet-4-20250514 are deprecated and 404
            # once retired. claude-opus-4-6 still accepts the temperature param.
            llm = setup_llm("claude-opus-4-6", anthropic_api_key=body.apiKey)
        elif ptype == "openrouter":
            llm = setup_llm("openrouter/openai/gpt-4o-mini", openrouter_api_key=body.apiKey)
        elif ptype == "deepseek":
            llm = setup_llm("deepseek/deepseek-chat", deepseek_api_key=body.apiKey)
        elif ptype == "gemini":
            from orchestrator_helpers.model_providers import fetch_gemini_models
            available = await fetch_gemini_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Gemini models available for this API key"},
                    status_code=400,
                )
            flash = next((m for m in available if "flash" in m["id"].lower()), available[0])
            llm = setup_llm(flash["id"], gemini_api_key=body.apiKey)
        elif ptype == "glm":
            from orchestrator_helpers.model_providers import fetch_glm_models
            available = await fetch_glm_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No GLM models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "flash" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], glm_api_key=body.apiKey)
        elif ptype == "kimi":
            from orchestrator_helpers.model_providers import fetch_kimi_models
            available = await fetch_kimi_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Kimi models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "8k" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], kimi_api_key=body.apiKey)
        elif ptype == "qwen":
            from orchestrator_helpers.model_providers import fetch_qwen_models
            available = await fetch_qwen_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Qwen models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "turbo" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], qwen_api_key=body.apiKey)
        elif ptype == "xai":
            from orchestrator_helpers.model_providers import fetch_xai_models
            available = await fetch_xai_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No xAI models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "mini" in m["id"].lower() or "fast" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], xai_api_key=body.apiKey)
        elif ptype == "mistral":
            from orchestrator_helpers.model_providers import fetch_mistral_models
            available = await fetch_mistral_models(api_key=body.apiKey)
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Mistral models available for this API key"},
                    status_code=400,
                )
            pick = next((m for m in available if "small" in m["id"].lower() or "nemo" in m["id"].lower()), available[0])
            llm = setup_llm(pick["id"], mistral_api_key=body.apiKey)
        elif ptype == "bedrock":
            from orchestrator_helpers.model_providers import fetch_bedrock_models
            available = await fetch_bedrock_models(
                region=body.awsRegion,
                access_key_id=body.awsAccessKeyId,
                secret_access_key=body.awsSecretKey,
                bearer_token=body.awsBearerToken,
            )
            if not available:
                return JSONResponse(
                    content={"success": False, "error": "No Bedrock models available — check region, credentials, and Model Access in the Bedrock console."},
                    status_code=400,
                )
            # Prefer a small Haiku/Nova model for the smoke test if present;
            # otherwise fall back to the first listed model.
            pick = next(
                (m for m in available if "haiku" in m["id"].lower() or "nova-micro" in m["id"].lower()),
                available[0],
            )
            llm = setup_llm(
                pick["id"],
                aws_access_key_id=body.awsAccessKeyId,
                aws_secret_access_key=body.awsSecretKey,
                aws_bearer_token=body.awsBearerToken,
                aws_region=body.awsRegion,
            )
        elif ptype == "openai_compatible":
            from langchain_openai import ChatOpenAI
            kwargs = dict(
                model=body.modelIdentifier or "default",
                api_key=body.apiKey or "ollama",
                temperature=body.temperature,
                max_tokens=body.maxTokens,
            )
            if body.baseUrl:
                kwargs["base_url"] = body.baseUrl
            if body.defaultHeaders:
                kwargs["default_headers"] = body.defaultHeaders
            if body.timeout:
                kwargs["timeout"] = float(body.timeout)
            if not body.sslVerify:
                import httpx
                kwargs["http_client"] = httpx.Client(verify=False)
                kwargs["http_async_client"] = httpx.AsyncClient(verify=False)
            llm = ChatOpenAI(**kwargs)
        else:
            return JSONResponse(
                content={"success": False, "error": f"Unknown provider type: {ptype}"},
                status_code=400,
            )

        response = await llm.ainvoke([HumanMessage(content="Say hello in one sentence.")])
        from orchestrator_helpers import normalize_content
        text = normalize_content(response.content).strip()

        return {"success": True, "response_text": text}

    except Exception as e:
        logger.error(f"LLM provider test failed: {e}")
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=400,
        )


@app.get("/files", tags=["Files"])
async def download_file(
    path: str = Query(..., description="File path inside kali-sandbox (must be under /tmp/)"),
):
    """
    Download a file from kali-sandbox via the kali_shell MCP tool.

    Reads the file using base64 encoding through the existing MCP tool,
    decodes it, and returns the binary content.
    Security: Only paths under /tmp/ are allowed.
    """
    # Security: restrict to /tmp/ paths and prevent directory traversal
    if not path.startswith("/tmp/"):
        return Response(content="Forbidden: only /tmp/ paths allowed", status_code=403)
    normalized = os.path.normpath(path)
    if not normalized.startswith("/tmp/"):
        return Response(content="Forbidden: path traversal detected", status_code=403)

    if not orchestrator or not orchestrator.tool_executor:
        return Response(content="Agent not initialized", status_code=503)

    try:
        # Check file exists first
        check_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"test -f {normalized} && stat -c '%s' {normalized}"},
            "informational",
            skip_phase_check=True,
        )
        if not check_result.get("success") or not check_result.get("output", "").strip():
            return Response(content="File not found", status_code=404)

        # Read file as base64
        b64_result = await orchestrator.tool_executor.execute(
            "kali_shell",
            {"command": f"base64 -w0 {normalized}"},
            "informational",
            skip_phase_check=True,
        )
        if not b64_result.get("success"):
            return Response(
                content=f"Error reading file: {b64_result.get('error', 'unknown')}",
                status_code=500,
            )

        b64_str = (b64_result.get("output") or "").strip()
        file_bytes = base64.b64decode(b64_str)
        filename = os.path.basename(normalized)

        # Content type mapping for common payload/document types
        ext = os.path.splitext(filename)[1].lower()
        content_types = {
            ".exe": "application/x-msdownload",
            ".elf": "application/x-elf",
            ".pdf": "application/pdf",
            ".docm": "application/vnd.ms-word.document.macroEnabled.12",
            ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
            ".apk": "application/vnd.android.package-archive",
            ".war": "application/x-webarchive",
            ".ps1": "text/plain",
            ".py": "text/plain",
            ".sh": "text/plain",
            ".hta": "text/html",
            ".lnk": "application/x-ms-shortcut",
            ".rtf": "application/rtf",
            ".vba": "text/plain",
            ".macho": "application/x-mach-binary",
        }
        content_type = content_types.get(ext, "application/octet-stream")

        return Response(
            content=file_bytes,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(file_bytes)),
            },
        )
    except Exception as e:
        logger.error(f"File download error: {e}")
        return Response(content=f"Error reading file: {str(e)}", status_code=500)


# =============================================================================
# WORKSPACE - per-project filesystem + background-job HTTP endpoints
# =============================================================================
# All routes are project-scoped (projectId is required) and use the same
# _resolve_safe validator as the fs_* tools, so path traversal and symlink
# escape attempts are rejected at the boundary. The webapp drawer + AI panel
# both consume these.


@app.get("/workspace/list", tags=["Workspace"])
async def workspace_list(
    projectId: str = Query(..., description="Project UUID"),
    path: str = Query(".", description="Subdir relative to /workspace/<projectId>/"),
):
    """Directory listing as structured JSON for the drawer Files tab."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        entries = workspace_fs.list_dir_for_project(projectId, path)
        return {"projectId": projectId, "path": path, "entries": entries}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/list failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/tree", tags=["Workspace"])
async def workspace_tree(
    projectId: str = Query(...),
    path: str = Query("."),
    maxDepth: int = Query(3, ge=1, le=10),
    maxEntries: int = Query(500, ge=10, le=5000),
):
    """ASCII tree view of a workspace subtree."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return {"projectId": projectId, "path": path,
                "tree": workspace_fs.tree_for_project(projectId, path, maxDepth, maxEntries)}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/tree failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/download", tags=["Workspace"])
async def workspace_download(
    projectId: str = Query(...),
    path: str = Query(...),
):
    """Stream file bytes directly from the bind-mount (no kali_shell round-trip)."""
    if not projectId:
        return Response(content="projectId required", status_code=400)
    try:
        content_bytes, mime = workspace_fs.download_for_project(projectId, path)
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/download failed: {e}")
        return Response(content=str(e), status_code=500)
    filename = os.path.basename(path) or "download"
    return Response(
        content=content_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(content_bytes)),
        },
    )


class WorkspaceRenameRequest(BaseModel):
    projectId: str
    path: str
    newName: str


@app.post("/workspace/rename", tags=["Workspace"])
async def workspace_rename(req: WorkspaceRenameRequest):
    """Rename a single entry within its parent (no cross-dir moves)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        new_path = workspace_fs.rename_for_project(req.projectId, req.path, req.newName)
        return {"projectId": req.projectId, "path": new_path}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/rename failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.delete("/workspace", tags=["Workspace"])
async def workspace_delete(
    projectId: str = Query(...),
    path: str = Query(...),
    recursive: bool = Query(False),
):
    """Delete a file or directory (recursive required for dirs)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        workspace_fs.delete_for_project(projectId, path, recursive)
        return {"projectId": projectId, "path": path, "deleted": True}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/delete failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceResetRequest(BaseModel):
    projectId: str


@app.post("/workspace/reset", tags=["Workspace"])
async def workspace_reset(req: WorkspaceResetRequest):
    """Wipe the workspace back to its initial state (4 empty default folders)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        summary = workspace_fs.reset_for_project(req.projectId)
        return {"projectId": req.projectId, **summary}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/reset failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/jobs", tags=["Workspace"])
async def workspace_jobs_list(
    projectId: str = Query(...),
    active: Optional[bool] = Query(None, description="True=running only, False=terminal only, omit for all"),
):
    """List background jobs for the drawer Jobs tab."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    reg = job_runner.get_registry()
    return {"projectId": projectId, "jobs": reg.list(projectId, active=active)}


@app.post("/workspace/jobs/{job_id}/cancel", tags=["Workspace"])
async def workspace_job_cancel(
    job_id: str,
    projectId: str = Query(...),
):
    """Cancel a running background job."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    reg = job_runner.get_registry()
    result = await reg.cancel(projectId, job_id)
    return result


@app.post("/workspace/upload", tags=["Workspace"])
async def workspace_upload(
    projectId: str = Form(...),
    path: str = Form("."),
    overwrite: bool = Form(False),
    file: UploadFile = File(...),
):
    """Multipart file upload into a workspace directory.

    409 (`code: exists`) on name collision when `overwrite=False` so the
    frontend can prompt for confirmation, then retry with `overwrite=true`.
    """
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        file_bytes = await file.read()
        new_path = workspace_fs.upload_for_project(
            projectId, path, file_bytes, file.filename or "uploaded", overwrite=overwrite,
        )
        return {"projectId": projectId, "path": new_path, "size": len(file_bytes)}
    except FileExistsError as e:
        return JSONResponse(
            content={"error": str(e), "code": "exists"}, status_code=409,
        )
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/upload failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceMkdirRequest(BaseModel):
    projectId: str
    path: str


@app.post("/workspace/mkdir", tags=["Workspace"])
async def workspace_mkdir(req: WorkspaceMkdirRequest):
    """Create a new directory (parents created automatically)."""
    if not req.projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        new_path = workspace_fs.mkdir_for_project(req.projectId, req.path)
        return {"projectId": req.projectId, "path": new_path}
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/mkdir failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class WorkspaceBulkArchiveRequest(BaseModel):
    projectId: str
    paths: list[str]
    format: str = "tar.gz"
    archiveName: str = "bundle"


@app.post("/workspace/bulk-archive", tags=["Workspace"])
async def workspace_bulk_archive(req: WorkspaceBulkArchiveRequest):
    """Bundle N workspace entries into one tar.gz/zip; stream back to client.

    POST (not GET) because the list of paths can be long and we want a JSON
    body for clarity over a megalong query string.
    """
    if not req.projectId:
        return Response(content="projectId required", status_code=400)
    try:
        archive_bytes, filename = workspace_fs.bulk_archive_for_project(
            req.projectId, req.paths, format=req.format, archive_name=req.archiveName,
        )
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/bulk-archive failed: {e}")
        return Response(content=str(e), status_code=500)
    mime = "application/gzip" if req.format == "tar.gz" else "application/zip"
    return Response(
        content=archive_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(archive_bytes)),
        },
    )


@app.get("/workspace/archive-download", tags=["Workspace"])
async def workspace_archive_download(
    projectId: str = Query(...),
    path: str = Query(...),
    format: str = Query("tar.gz"),
):
    """Stream a directory as a tar.gz or zip archive."""
    if not projectId:
        return Response(content="projectId required", status_code=400)
    try:
        archive_bytes, filename = workspace_fs.archive_dir_for_project(
            projectId, path, format=format,
        )
    except ValueError as e:
        return Response(content=str(e), status_code=400)
    except Exception as e:
        logger.error(f"/workspace/archive-download failed: {e}")
        return Response(content=str(e), status_code=500)
    mime = "application/gzip" if format == "tar.gz" else "application/zip"
    return Response(
        content=archive_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(archive_bytes)),
        },
    )


@app.get("/workspace/preview", tags=["Workspace"])
async def workspace_preview(
    projectId: str = Query(...),
    path: str = Query(...),
    maxBytes: int = Query(1024 * 1024, ge=1, le=10 * 1024 * 1024),
):
    """File preview for the inline viewer pane (text or base64 binary)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return workspace_fs.preview_for_project(projectId, path, max_bytes=maxBytes)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/preview failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/workspace/properties", tags=["Workspace"])
async def workspace_properties(
    projectId: str = Query(...),
    path: str = Query(...),
):
    """Rich metadata for the properties popover (size, mtime, mode, sha256)."""
    if not projectId:
        return JSONResponse(content={"error": "projectId required"}, status_code=400)
    try:
        return workspace_fs.properties_for_project(projectId, path)
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"/workspace/properties failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# =============================================================================
# COMMAND WHISPERER - NLP-to-command translation using the project's LLM
# =============================================================================

_COMMAND_WHISPERER_SYSTEM_PROMPT = """You are a command-line expert for penetration testing.
The user has an active {session_type} session and needs a command.

Session type details:
- "meterpreter": Meterpreter commands (hashdump, getsystem, upload, download, sysinfo, getuid, ps, migrate, search, cat, ls, portfwd, route, load, etc.)
- "shell": Standard Linux/Unix shell commands (find, grep, cat, ls, whoami, id, uname, ifconfig, netstat, awk, sed, curl, wget, chmod, python, perl, etc.)

Rules:
1. Output ONLY the command — no explanations, no markdown, no commentary
2. Single command (use && or ; to chain if needed)
3. No sudo unless explicitly requested
4. Prefer concise, commonly-used flags
5. If ambiguous, pick the most likely interpretation"""


class CommandWhispererRequest(BaseModel):
    prompt: str
    session_type: str
    project_id: str


@app.post("/command-whisperer", tags=["Sessions"])
async def command_whisperer(body: CommandWhispererRequest):
    """Translate a natural language request into a shell command using the project's LLM."""
    if not orchestrator or not orchestrator._initialized:
        return JSONResponse(content={"error": "Agent not initialized"}, status_code=503)

    # Ensure LLM is set up for this project
    if not orchestrator.llm:
        try:
            orchestrator._apply_project_settings(body.project_id)
        except Exception as e:
            logger.error(f"Command whisperer LLM setup error: {e}")
            return JSONResponse(
                content={"error": "LLM not configured. Open the AI assistant first or check API keys."},
                status_code=503,
            )

    if not orchestrator.llm:
        return JSONResponse(content={"error": "LLM not available"}, status_code=503)

    try:
        system_prompt = _COMMAND_WHISPERER_SYSTEM_PROMPT.format(
            session_type=body.session_type,
        )
        response = await orchestrator.llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=body.prompt),
        ])

        command = normalize_content(response.content).strip()

        # Strip markdown code fences if the LLM wraps the answer
        if command.startswith("```") and command.endswith("```"):
            command = command[3:-3].strip()
        if command.startswith(("bash\n", "sh\n", "shell\n")):
            command = command.split("\n", 1)[1].strip()

        return {"command": command}

    except Exception as e:
        logger.error(f"Command whisperer error: {e}")
        return JSONResponse(
            content={"error": f"Failed to generate command: {str(e)}"},
            status_code=500,
        )


# =============================================================================
# SESSION MANAGEMENT PROXY — proxies to kali-sandbox:8013 session endpoints
# =============================================================================

# Derive base URL from existing progress URL (already in docker-compose)
_SESSION_BASE = os.environ.get(
    "MCP_METASPLOIT_PROGRESS_URL", "http://kali-sandbox:8013/progress"
).rsplit("/progress", 1)[0]


@app.get("/tunnel-status", tags=["System"])
async def get_tunnel_status():
    """Return live status of ngrok and chisel tunnels."""
    from utils import _query_ngrok_tunnel, _query_chisel_tunnel

    # Always try to query both — they return None gracefully if not running
    ngrok_info = _query_ngrok_tunnel()
    chisel_info = _query_chisel_tunnel()

    return {
        "ngrok": {"active": True, "host": ngrok_info["host"], "port": ngrok_info["port"]} if ngrok_info else {"active": False},
        "chisel": {"active": True, "host": chisel_info["host"], "port": chisel_info["port"], "srvPort": chisel_info["srv_port"]} if chisel_info else {"active": False},
    }


@app.get("/sessions", tags=["Sessions"])
async def get_sessions():
    """List all active Metasploit sessions, background jobs, and non-MSF sessions."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{_SESSION_BASE}/sessions")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.TimeoutException:
        return JSONResponse(content={"error": "Session manager timeout"}, status_code=504)
    except Exception as e:
        logger.error(f"Session proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/sessions/{session_id}/interact", tags=["Sessions"])
async def interact_session(session_id: int, body: dict):
    """Send a command to a specific Metasploit session."""
    try:
        async with httpx.AsyncClient(timeout=40.0) as client:
            resp = await client.post(
                f"{_SESSION_BASE}/sessions/{session_id}/interact", json=body
            )
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.TimeoutException:
        return JSONResponse(content={"error": "Session interaction timeout"}, status_code=504)
    except Exception as e:
        logger.error(f"Session interact proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/sessions/{session_id}/kill", tags=["Sessions"])
async def kill_session(session_id: int):
    """Kill a specific Metasploit session."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/sessions/{session_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/jobs/{job_id}/kill", tags=["Sessions"])
async def kill_job(job_id: int):
    """Kill a background Metasploit job."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/jobs/{job_id}/kill")
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Job kill proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/session-chat-map", tags=["Sessions"])
async def session_chat_map(body: dict):
    """Register a mapping between a Metasploit session ID and agent chat session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/session-chat-map", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Session chat map proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


@app.post("/non-msf-sessions", tags=["Sessions"])
async def register_non_msf_session(body: dict):
    """Register a non-Metasploit session (netcat, socat, etc.)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_SESSION_BASE}/non-msf-sessions", json=body)
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        logger.error(f"Non-MSF session register proxy error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=502)


# =============================================================================
# TEXT-TO-CYPHER — Generate Cypher from natural language using existing prompt
# =============================================================================

class TextToCypherRequest(BaseModel):
    """Request model for text-to-cypher conversion."""
    question: str
    user_id: str
    project_id: str
    # Default True for backward compatibility with the webapp graph view, which
    # needs whole nodes/relationships to render. CLI callers (e.g. redagraph)
    # should send False so the LLM is free to return scalar properties.
    for_graph_view: bool = True


@app.post("/text-to-cypher", tags=["Graph"])
async def text_to_cypher(body: TextToCypherRequest):
    """
    Generate a Cypher query from a natural language description.

    Reuses the TEXT_TO_CYPHER_SYSTEM prompt and Neo4jToolManager._generate_cypher()
    so the graph schema is always in sync with the agent's query_graph tool.

    Returns the raw Cypher (without tenant filters) for the webapp to save and execute.
    """
    from tools import Neo4jToolManager
    from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key
    from project_settings import DEFAULT_AGENT_SETTINGS, fetch_agent_settings
    import requests as _requests

    # 1. Resolve LLM for the user
    llm = None

    # Try to get project-specific model first
    model_name = DEFAULT_AGENT_SETTINGS['OPENAI_MODEL']
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        settings = fetch_agent_settings(body.project_id, webapp_url)
        if settings and settings.get('OPENAI_MODEL'):
            model_name = settings['OPENAI_MODEL']
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch project settings: {e}")

    # Fetch user's LLM providers for API keys
    user_providers = []
    try:
        webapp_url = os.environ.get('WEBAPP_API_URL', 'http://webapp:3000')
        resp = _requests.get(
            f"{webapp_url.rstrip('/')}/api/users/{body.user_id}/llm-providers?internal=true",
            headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
            timeout=10,
        )
        resp.raise_for_status()
        user_providers = resp.json()
    except Exception as e:
        logger.warning(f"text-to-cypher: failed to fetch user LLM providers: {e}")

    openai_p = _resolve_provider_key(user_providers, "openai")
    anthropic_p = _resolve_provider_key(user_providers, "anthropic")
    openrouter_p = _resolve_provider_key(user_providers, "openrouter")
    bedrock_p = _resolve_provider_key(user_providers, "bedrock")
    deepseek_p = _resolve_provider_key(user_providers, "deepseek")
    gemini_p = _resolve_provider_key(user_providers, "gemini")
    glm_p = _resolve_provider_key(user_providers, "glm")
    kimi_p = _resolve_provider_key(user_providers, "kimi")
    qwen_p = _resolve_provider_key(user_providers, "qwen")
    xai_p = _resolve_provider_key(user_providers, "xai")
    mistral_p = _resolve_provider_key(user_providers, "mistral")

    try:
        # Check if model uses custom provider config
        if model_name.startswith("custom/"):
            config_id = model_name[len("custom/"):]
            matched = None
            for p in user_providers:
                if p.get("id") == config_id:
                    matched = p
                    break
            if not matched and user_providers:
                matched = user_providers[0]
            if matched:
                llm = setup_llm(model_name, custom_llm_config=matched)
            else:
                return JSONResponse(
                    content={"error": "Custom LLM provider not found. Configure an AI model in settings."},
                    status_code=400,
                )
        else:
            llm = setup_llm(
                model_name,
                openai_api_key=(openai_p or {}).get("apiKey"),
                anthropic_api_key=(anthropic_p or {}).get("apiKey"),
                openrouter_api_key=(openrouter_p or {}).get("apiKey"),
                deepseek_api_key=(deepseek_p or {}).get("apiKey"),
                gemini_api_key=(gemini_p or {}).get("apiKey"),
                glm_api_key=(glm_p or {}).get("apiKey"),
                kimi_api_key=(kimi_p or {}).get("apiKey"),
                qwen_api_key=(qwen_p or {}).get("apiKey"),
                xai_api_key=(xai_p or {}).get("apiKey"),
                mistral_api_key=(mistral_p or {}).get("apiKey"),
                aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
                aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
                aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
                aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
            )
    except Exception as e:
        logger.error(f"text-to-cypher: failed to create LLM: {e}")
        return JSONResponse(
            content={"error": f"Failed to initialize LLM: {str(e)}. Make sure an AI model is configured."},
            status_code=400,
        )

    if not llm:
        return JSONResponse(
            content={"error": "No LLM configured. Configure an AI model in project settings to use graph views."},
            status_code=400,
        )

    # 2. Create Neo4jToolManager and generate Cypher
    neo4j_uri = os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')
    neo4j_user = os.environ.get('NEO4J_USER', 'neo4j')
    neo4j_password = os.environ.get('NEO4J_PASSWORD', 'password')

    manager = Neo4jToolManager(neo4j_uri, neo4j_user, neo4j_password, llm)

    try:
        from langchain_community.graphs import Neo4jGraph
        manager.graph = Neo4jGraph(
            url=neo4j_uri,
            username=neo4j_user,
            password=neo4j_password,
        )
    except Exception as e:
        logger.error(f"text-to-cypher: failed to connect to Neo4j: {e}")
        return JSONResponse(
            content={"error": f"Failed to connect to graph database: {str(e)}"},
            status_code=500,
        )

    # 3. Generate Cypher with retry logic
    last_error = None
    last_cypher = None
    cypher = None
    max_retries = 3

    for attempt in range(max_retries):
        try:
            if attempt == 0:
                cypher = await manager._generate_cypher(body.question, for_graph_view=body.for_graph_view)
            else:
                cypher = await manager._generate_cypher(
                    body.question,
                    previous_error=last_error,
                    previous_cypher=last_cypher,
                    for_graph_view=body.for_graph_view,
                )

            # Reject write operations -- data filters are read-only
            if manager._find_disallowed_write_operation(cypher):
                return JSONResponse(
                    content={"error": "Write operations are not allowed in data filters"},
                    status_code=400,
                )

            # Validate by executing (with tenant filter) to catch syntax errors
            filtered = manager._inject_tenant_filter(cypher, body.user_id, body.project_id)
            manager.graph.query(
                filtered,
                params={
                    "tenant_user_id": body.user_id,
                    "tenant_project_id": body.project_id,
                },
            )

            # Return the raw (un-filtered) Cypher for saving
            return JSONResponse(content={"cypher": cypher})

        except Exception as e:
            last_error = str(e)
            last_cypher = cypher
            logger.warning(f"text-to-cypher attempt {attempt + 1} failed: {last_error}")

            if attempt == max_retries - 1:
                return JSONResponse(
                    content={"error": f"Failed to generate valid Cypher after {max_retries} attempts: {last_error}"},
                    status_code=422,
                )

    return JSONResponse(content={"error": "Unexpected end of retry loop"}, status_code=500)


# =============================================================================
# KALI TERMINAL — WebSocket PTY proxy to kali-sandbox terminal server
# =============================================================================

_KALI_TERMINAL_WS_URL = os.environ.get("KALI_TERMINAL_WS_URL", "ws://kali-sandbox:8016")


@app.websocket("/ws/kali-terminal")
async def kali_terminal_proxy(websocket: WebSocket):
    """
    Proxy WebSocket connection to the kali-sandbox PTY terminal server.

    Bridges the browser ↔ agent ↔ kali-sandbox terminal for interactive shell access.
    """
    await websocket.accept()

    try:
        async with websockets.connect(
            _KALI_TERMINAL_WS_URL,
            ping_interval=30,
            ping_timeout=60,
            max_size=2**20,
        ) as kali_ws:

            async def browser_to_kali():
                try:
                    while True:
                        data = await websocket.receive()
                        if "text" in data:
                            await kali_ws.send(data["text"])
                        elif "bytes" in data:
                            await kali_ws.send(data["bytes"])
                except Exception as e:
                    logger.debug("Browser→Kali stream ended: %s", e)

            async def kali_to_browser():
                try:
                    async for message in kali_ws:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)
                except Exception as e:
                    logger.debug("Kali→Browser stream ended: %s", e)

            upstream = asyncio.create_task(browser_to_kali())
            downstream = asyncio.create_task(kali_to_browser())
            try:
                await asyncio.wait(
                    [upstream, downstream], return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                upstream.cancel()
                downstream.cancel()
                await asyncio.gather(upstream, downstream, return_exceptions=True)

    except Exception as e:
        logger.error("Kali terminal proxy error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time agent communication.

    Provides bidirectional streaming of:
    - LLM thinking process
    - Tool executions and outputs
    - Phase transitions
    - Approval requests
    - Agent questions
    - Todo list updates

    The client must send an 'init' message first to authenticate the session.
    """
    if not orchestrator:
        await websocket.close(code=1011, reason="Orchestrator not initialized")
        return

    if not ws_manager:
        await websocket.close(code=1011, reason="WebSocket manager not initialized")
        return

    await websocket_endpoint(websocket, orchestrator, ws_manager)


# =============================================================================
# CYPHERFIX WEBSOCKET ENDPOINTS
# =============================================================================


@app.websocket("/ws/cypherfix-triage")
async def cypherfix_triage_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for CypherFix triage agent.

    Runs vulnerability triage: collects findings from Neo4j graph,
    correlates and prioritizes them, generates remediation items.
    """
    from cypherfix_triage.websocket_handler import handle_triage_websocket
    await handle_triage_websocket(websocket)


@app.websocket("/ws/cypherfix-codefix")
async def cypherfix_codefix_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for CypherFix CodeFix agent.

    Runs automated code remediation: clones repo, explores codebase,
    implements fix, streams diff blocks for review, creates PR.
    """
    from cypherfix_codefix.websocket_handler import handle_codefix_websocket
    await handle_codefix_websocket(websocket)
