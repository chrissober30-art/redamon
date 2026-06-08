/**
 * Route handler tests for the AI Surface + AI Risk red-zone endpoints.
 *
 * Both routes fire MULTIPLE session.run() calls (one per sub-sheet), so the
 * mock returns a QUEUE of record-sets — one shift per run() call, in route order.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/aiTablesRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runQueue: Array<Array<Record<string, unknown>>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      const rows = runQueue.shift() ?? []
      return { records: rows.map(row => ({ get: (key: string) => row[key] })) }
    },
    close: async () => { /* no-op */ },
  }),
}))

const aiSurface = await import('./aiSurface/route')
const aiRisk = await import('./aiRisk/route')

function req(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/test?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/test'
  return { nextUrl: new URL(url) }
}

beforeEach(() => {
  runCalls.length = 0
  runQueue = []
  shouldThrow = null
})

// --------------------------------------------------------------------------- //
describe('AI red-zone routes — guards', () => {
  test.each([
    ['aiSurface', aiSurface.GET],
    ['aiRisk', aiRisk.GET],
  ])('%s returns 400 when projectId missing', async (_name, handler) => {
    const res = await handler(req(null))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/projectId/i)
  })

  test.each([
    ['aiSurface', aiSurface.GET],
    ['aiRisk', aiRisk.GET],
  ])('%s returns 500 on query error', async (_name, handler) => {
    shouldThrow = new Error('boom')
    const res = await handler(req('p1'))
    expect(res.status).toBe(500)
    expect((await res.json()).error).toBe('boom')
  })

  test.each([
    ['aiSurface', aiSurface.GET, ['llmEndpoints', 'mcpServers', 'technologies', 'vectorDbs', 'models']],
    ['aiRisk', aiRisk.GET, ['findings', 'injectableParams', 'ragPoints', 'exposedRuntimes', 'unauthenticatedMcp']],
  ])('%s smoke: empty graph -> 200 with all sheet keys as []', async (_name, handler, keys) => {
    const res = await handler(req('p1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    for (const k of keys as string[]) {
      expect(body.sheets[k]).toEqual([])
      expect(body.meta[k]).toBe(0)
    }
    expect(runCalls).toHaveLength(5) // one query per sheet
    expect(runCalls.every(c => c.params.pid === 'p1')).toBe(true)
  })
})

// --------------------------------------------------------------------------- //
describe('aiSurface route — field mapping', () => {
  test('maps every sub-sheet and converts neo4j ints', async () => {
    runQueue = [
      // llmEndpoints
      [{ baseUrl: 'http://h:9106', path: '/v1/chat/completions', method: 'GET',
         interfaceType: 'llm-chat', streaming: true, tools: true, vision: true,
         modelFamily: 'llama', latencyMs: 11.2, ragIngest: null, framework: null,
         frontend: null, schemaRef: '/tmp/x.json', source: 'ai_surface_recon' }],
      // mcpServers (toolCount as neo4j int {low})
      [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'demo', serverVersion: '1.0',
         protocolVersion: '2025-06-18', toolCount: { low: 4, high: 0 }, resourceCount: { low: 1, high: 0 },
         promptCount: { low: 1, high: 0 }, capabilities: ['tools', 'prompts'],
         authRequired: false, toolsHash: 'abc' }],
      // technologies
      [{ name: 'qdrant', category: 'ai-vector-db', version: '', detectedBy: ['naabu-ai-port'], attachedTo: { low: 2, high: 0 } }],
      // vectorDbs
      [{ name: 'qdrant', host: '1.2.3.4', port: { low: 6333, high: 0 }, detectedBy: 'ai-surface-recon-probe' }],
      // models
      [{ modelId: 'gpt-4o', family: 'gpt', baseUrl: 'http://h:9106', sourceEndpoint: '/v1/models' }],
    ]
    const res = await aiSurface.GET(req('p1'))
    const { sheets, meta } = await res.json()

    expect(sheets.llmEndpoints[0]).toMatchObject({ interfaceType: 'llm-chat', streaming: true, latencyMs: 11.2 })
    expect(sheets.mcpServers[0].toolCount).toBe(4)        // {low:4} -> 4
    expect(sheets.mcpServers[0].resourceCount).toBe(1)
    expect(sheets.mcpServers[0].capabilities).toEqual(['tools', 'prompts'])
    expect(sheets.mcpServers[0].authRequired).toBe(false)
    expect(sheets.technologies[0].attachedTo).toBe(2)
    expect(sheets.vectorDbs[0].port).toBe(6333)
    expect(sheets.models[0]).toMatchObject({ modelId: 'gpt-4o', family: 'gpt' })
    expect(meta).toMatchObject({ llmEndpoints: 1, mcpServers: 1, technologies: 1, vectorDbs: 1, models: 1 })
  })

  test('null array fields default to []', async () => {
    runQueue = [
      [], // llm
      [{ baseUrl: 'http://h', path: '/mcp', serverName: 'd', serverVersion: null,
         protocolVersion: null, toolCount: null, resourceCount: null, promptCount: null,
         capabilities: null, authRequired: null, toolsHash: null }],
      [{ name: 't', category: 'ai-runtime', version: null, detectedBy: null, attachedTo: null }],
      [], [],
    ]
    const res = await aiSurface.GET(req('p1'))
    const { sheets } = await res.json()
    expect(sheets.mcpServers[0].capabilities).toEqual([])
    expect(sheets.mcpServers[0].toolCount).toBeNull()
    expect(sheets.technologies[0].detectedBy).toEqual([])
  })
})

// --------------------------------------------------------------------------- //
describe('aiRisk route — field mapping', () => {
  test('maps findings + risk sheets with OWASP/ATLAS + exposedOn array', async () => {
    runQueue = [
      // findings
      [{ severity: 'high', type: 'mcp_tool_poisoning', name: 'poison', owasp: 'LLM01',
         atlas: 'AML.T0051', payloadClass: 'mcp_static', evidence: '{}', findingId: 'aisr_1',
         baseUrl: 'http://h:9107', endpointPath: '/mcp' }],
      // injectableParams
      [{ name: 'query', endpointPath: '/mcp', baseUrl: 'http://h:9107',
         toolArgPath: '/inputSchema/properties/query', position: 'body' }],
      // ragPoints
      [],
      // exposedRuntimes
      [{ name: 'ollama', category: 'ai-runtime', version: null, exposedOn: ['1.2.3.4:11434'] }],
      // unauthenticatedMcp
      [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'demo', toolCount: { low: 4, high: 0 } }],
    ]
    const res = await aiRisk.GET(req('p1'))
    const { sheets, meta } = await res.json()

    expect(sheets.findings[0]).toMatchObject({ type: 'mcp_tool_poisoning', owasp: 'LLM01', atlas: 'AML.T0051' })
    expect(sheets.injectableParams[0].toolArgPath).toBe('/inputSchema/properties/query')
    expect(sheets.exposedRuntimes[0].exposedOn).toEqual(['1.2.3.4:11434'])
    expect(sheets.unauthenticatedMcp[0].toolCount).toBe(4)
    expect(meta).toMatchObject({ findings: 1, injectableParams: 1, ragPoints: 0, exposedRuntimes: 1, unauthenticatedMcp: 1 })
  })

  test('exposedOn defaults to [] when null', async () => {
    runQueue = [[], [], [], [{ name: 'x', category: 'ai-proxy', version: null, exposedOn: null }], []]
    const res = await aiRisk.GET(req('p1'))
    const { sheets } = await res.json()
    expect(sheets.exposedRuntimes[0].exposedOn).toEqual([])
  })
})

// --------------------------------------------------------------------------- //
describe('aiRisk route — Cypher shape', () => {
  test('queries are project-scoped and target the right nodes', async () => {
    await aiRisk.GET(req('proj-x'))
    expect(runCalls).toHaveLength(5)
    expect(runCalls[0].cypher).toMatch(/Vulnerability.*source: 'ai_surface_recon'/s)
    expect(runCalls[1].cypher).toMatch(/is_ai_prompt_injectable = true/)
    expect(runCalls[2].cypher).toMatch(/is_ai_rag_ingest = true/)
    expect(runCalls[3].cypher).toMatch(/\['ai-runtime','ai-proxy'\]/)
    expect(runCalls[4].cypher).toMatch(/ai_mcp_auth_required/)
    expect(runCalls.every(c => c.params.pid === 'proj-x')).toBe(true)
  })
})
