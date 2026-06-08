import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/**
 * "AI Surface" inventory view — every AI/LLM/MCP/vector-DB surface discovered,
 * across ALL modules (http_probe, port_scan, resource_enum, js_recon, and the
 * central ai_surface_recon). Returns one array per sub-sheet.
 */
export async function GET(request: NextRequest) {
  const pid = request.nextUrl.searchParams.get('projectId')
  if (!pid) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })

  const session = getSession()
  try {
    // --- LLM / chat / framework endpoints ---
    const llm = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid})
       WHERE ep.ai_interface_type IS NOT NULL OR ep.is_ai_framework_detected = true
       RETURN ep.baseurl AS baseUrl, ep.path AS path, ep.method AS method,
              ep.ai_interface_type AS interfaceType,
              ep.ai_supports_streaming AS streaming,
              ep.ai_supports_tools AS tools,
              ep.ai_supports_vision AS vision,
              ep.ai_model_family_guess AS modelFamily,
              ep.ai_latency_p50_ms AS latencyMs,
              ep.is_ai_rag_ingest AS ragIngest,
              ep.ai_framework_name AS framework,
              ep.ai_frontend_product_guess AS frontend,
              ep.ai_tool_schema_ref AS schemaRef,
              ep.source AS source
       ORDER BY ep.ai_interface_type, ep.baseurl, ep.path LIMIT 2000`,
      { pid })

    // --- MCP servers ---
    const mcp = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.ai_interface_type = 'mcp'
       RETURN ep.baseurl AS baseUrl, ep.path AS path,
              ep.ai_mcp_server_name AS serverName,
              ep.ai_mcp_server_version AS serverVersion,
              ep.ai_mcp_protocol_version AS protocolVersion,
              ep.ai_mcp_tool_count AS toolCount,
              ep.ai_mcp_resource_count AS resourceCount,
              ep.ai_mcp_prompt_count AS promptCount,
              ep.ai_mcp_caps AS capabilities,
              ep.ai_mcp_auth_required AS authRequired,
              ep.ai_mcp_tools_hash AS toolsHash
       ORDER BY ep.baseurl LIMIT 500`,
      { pid })

    // --- AI technologies (category ai-*) ---
    const tech = await session.run(
      `MATCH (t:Technology {project_id: $pid}) WHERE t.category STARTS WITH 'ai-'
       OPTIONAL MATCH (x)-[r]->(t) WHERE type(r) IN ['USES_TECHNOLOGY','HAS_TECHNOLOGY']
       RETURN t.name AS name, t.category AS category, t.version AS version,
              [d IN collect(DISTINCT r.detected_by) WHERE d IS NOT NULL] AS detectedBy,
              count(DISTINCT x) AS attachedTo
       ORDER BY t.category, t.name LIMIT 2000`,
      { pid })

    // --- Vector databases ---
    const vdb = await session.run(
      `MATCH (t:Technology {project_id: $pid, category: 'ai-vector-db'})
       OPTIONAL MATCH (p:Port)-[r:HAS_TECHNOLOGY]->(t)
       OPTIONAL MATCH (ip:IP)-[:HAS_PORT]->(p)
       RETURN t.name AS name, ip.address AS host, p.number AS port,
              coalesce(r.detected_by, t.source) AS detectedBy
       ORDER BY t.name LIMIT 500`,
      { pid })

    // --- Model inventory (flatten ai_model_ids) ---
    const models = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.ai_model_ids IS NOT NULL
       UNWIND ep.ai_model_ids AS modelId
       RETURN DISTINCT modelId AS modelId, ep.ai_model_family_guess AS family,
              ep.baseurl AS baseUrl, ep.path AS sourceEndpoint
       ORDER BY modelId LIMIT 1000`,
      { pid })

    const sheets = {
      llmEndpoints: llm.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), method: r.get('method'),
        interfaceType: r.get('interfaceType'), streaming: r.get('streaming'),
        tools: r.get('tools'), vision: r.get('vision'), modelFamily: r.get('modelFamily'),
        latencyMs: toNum(r.get('latencyMs')), ragIngest: r.get('ragIngest'),
        framework: r.get('framework'), frontend: r.get('frontend'),
        schemaRef: r.get('schemaRef'), source: r.get('source'),
      })),
      mcpServers: mcp.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), serverName: r.get('serverName'),
        serverVersion: r.get('serverVersion'), protocolVersion: r.get('protocolVersion'),
        toolCount: toNum(r.get('toolCount')), resourceCount: toNum(r.get('resourceCount')),
        promptCount: toNum(r.get('promptCount')),
        capabilities: (r.get('capabilities') as string[]) || [],
        authRequired: r.get('authRequired'), toolsHash: r.get('toolsHash'),
      })),
      technologies: tech.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), category: r.get('category'), version: r.get('version'),
        detectedBy: (r.get('detectedBy') as string[]) || [], attachedTo: toNum(r.get('attachedTo')),
      })),
      vectorDbs: vdb.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), host: r.get('host'), port: toNum(r.get('port')),
        detectedBy: r.get('detectedBy'),
      })),
      models: models.records.map((r: { get: (key: string) => unknown }) => ({
        modelId: r.get('modelId'), family: r.get('family'),
        baseUrl: r.get('baseUrl'), sourceEndpoint: r.get('sourceEndpoint'),
      })),
    }

    return NextResponse.json({
      sheets,
      meta: {
        llmEndpoints: sheets.llmEndpoints.length,
        mcpServers: sheets.mcpServers.length,
        technologies: sheets.technologies.length,
        vectorDbs: sheets.vectorDbs.length,
        models: sheets.models.length,
      },
    })
  } catch (error) {
    console.error('Red-zone aiSurface error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' }, { status: 500 })
  } finally {
    await session.close()
  }
}
