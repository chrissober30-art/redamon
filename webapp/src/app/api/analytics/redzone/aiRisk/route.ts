import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/**
 * "AI Risk (LLM)" offensive view — the attackable AI findings, mapped to
 * OWASP-LLM / MITRE ATLAS: MCP tool poisoning, prompt-injectable parameters,
 * RAG ingestion sinks, exposed runtimes/gateways, and unauthenticated MCP.
 */
export async function GET(request: NextRequest) {
  const pid = request.nextUrl.searchParams.get('projectId')
  if (!pid) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })

  const session = getSession()
  try {
    // --- MCP tool-poisoning / exfiltration / annotation findings ---
    const findings = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid, source: 'ai_surface_recon'})
       OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)
       RETURN v.severity AS severity, v.type AS type, v.name AS name,
              v.ai_owasp_llm_id AS owasp, v.ai_atlas_technique AS atlas,
              v.ai_payload_class AS payloadClass, v.evidence AS evidence, v.id AS findingId,
              coalesce(e.baseurl, '') AS baseUrl, e.path AS endpointPath
       ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 1000`,
      { pid })

    // --- Prompt-injectable parameters ---
    const params = await session.run(
      `MATCH (p:Parameter {project_id: $pid}) WHERE p.is_ai_prompt_injectable = true
       OPTIONAL MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p)
       RETURN p.name AS name, coalesce(e.path, p.endpoint_path) AS endpointPath,
              coalesce(e.baseurl, p.baseurl) AS baseUrl,
              p.ai_tool_arg_path AS toolArgPath, p.position AS position
       ORDER BY p.name LIMIT 1000`,
      { pid })

    // --- RAG ingestion points (indirect-prompt-injection vectors) ---
    const rag = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid}) WHERE ep.is_ai_rag_ingest = true
       RETURN ep.baseurl AS baseUrl, ep.path AS path, ep.method AS method,
              ep.ai_interface_type AS interfaceType
       ORDER BY ep.baseurl, ep.path LIMIT 1000`,
      { pid })

    // --- Exposed AI runtimes / gateways ---
    const exposed = await session.run(
      `MATCH (t:Technology {project_id: $pid}) WHERE t.category IN ['ai-runtime','ai-proxy']
       OPTIONAL MATCH (p:Port)-[:HAS_TECHNOLOGY]->(t)
       OPTIONAL MATCH (ip:IP)-[:HAS_PORT]->(p)
       WITH t, [hp IN collect(DISTINCT (ip.address + ':' + toString(p.number))) WHERE hp <> ':'] AS hostPorts
       RETURN t.name AS name, t.category AS category, t.version AS version, hostPorts AS exposedOn
       ORDER BY t.category, t.name LIMIT 1000`,
      { pid })

    // --- Unauthenticated MCP servers ---
    const unauth = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid})
       WHERE ep.ai_interface_type = 'mcp' AND coalesce(ep.ai_mcp_auth_required, false) = false
       RETURN ep.baseurl AS baseUrl, ep.path AS path, ep.ai_mcp_server_name AS serverName,
              ep.ai_mcp_tool_count AS toolCount
       ORDER BY ep.baseurl LIMIT 500`,
      { pid })

    const sheets = {
      findings: findings.records.map((r: { get: (key: string) => unknown }) => ({
        severity: r.get('severity'), type: r.get('type'), name: r.get('name'),
        owasp: r.get('owasp'), atlas: r.get('atlas'), payloadClass: r.get('payloadClass'),
        evidence: r.get('evidence'), findingId: r.get('findingId'),
        baseUrl: r.get('baseUrl'), endpointPath: r.get('endpointPath'),
      })),
      injectableParams: params.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), endpointPath: r.get('endpointPath'), baseUrl: r.get('baseUrl'),
        toolArgPath: r.get('toolArgPath'), position: r.get('position'),
      })),
      ragPoints: rag.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), method: r.get('method'),
        interfaceType: r.get('interfaceType'),
      })),
      exposedRuntimes: exposed.records.map((r: { get: (key: string) => unknown }) => ({
        name: r.get('name'), category: r.get('category'), version: r.get('version'),
        exposedOn: (r.get('exposedOn') as string[]) || [],
      })),
      unauthenticatedMcp: unauth.records.map((r: { get: (key: string) => unknown }) => ({
        baseUrl: r.get('baseUrl'), path: r.get('path'), serverName: r.get('serverName'),
        toolCount: toNum(r.get('toolCount')),
      })),
    }

    return NextResponse.json({
      sheets,
      meta: {
        findings: sheets.findings.length,
        injectableParams: sheets.injectableParams.length,
        ragPoints: sheets.ragPoints.length,
        exposedRuntimes: sheets.exposedRuntimes.length,
        unauthenticatedMcp: sheets.unauthenticatedMcp.length,
      },
    })
  } catch (error) {
    console.error('Red-zone aiRisk error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' }, { status: 500 })
  } finally {
    await session.close()
  }
}
