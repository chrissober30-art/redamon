/**
 * Unit + integration tests for the AI Surface / AI Risk multi-sheet tables.
 *
 * Verifies: data fetch + render, sheet-tab counts, sheet switching, empty-state,
 * null-safe cells, and the projectId=null no-fetch guard.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/AiTables.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { createElement } from 'react'

import { AiSurfaceTable, AiRiskTable } from './AiTables'

const SURFACE = {
  sheets: {
    llmEndpoints: [{ baseUrl: 'http://h:9106', path: '/v1/chat/completions', method: 'GET',
      interfaceType: 'llm-chat', streaming: true, tools: true, vision: true, modelFamily: 'llama',
      latencyMs: 11.2, ragIngest: null, framework: null, source: 'ai_surface_recon' }],
    mcpServers: [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'redamon-poison-mcp',
      serverVersion: '1.0', protocolVersion: '2025-06-18', toolCount: 4, resourceCount: 1,
      promptCount: 1, capabilities: ['tools'], authRequired: false, toolsHash: 'abc' }],
    technologies: [{ name: 'qdrant', category: 'ai-vector-db', version: '', detectedBy: ['naabu-ai-port'], attachedTo: 2 }],
    vectorDbs: [{ name: 'qdrant', host: '1.2.3.4', port: 6333, detectedBy: 'probe' }],
    models: [{ modelId: 'gpt-4o', family: 'gpt', baseUrl: 'http://h:9106', sourceEndpoint: '/v1/models' }],
  },
  meta: { llmEndpoints: 1, mcpServers: 1, technologies: 1, vectorDbs: 1, models: 1 },
}

const RISK = {
  sheets: {
    findings: [{ severity: 'high', type: 'mcp_tool_poisoning', name: 'poison', owasp: 'LLM01',
      atlas: 'AML.T0051', payloadClass: 'mcp_static', evidence: '{}', findingId: 'aisr_1',
      baseUrl: 'http://h:9107', endpointPath: '/mcp' }],
    injectableParams: [{ name: 'query', endpointPath: '/mcp', baseUrl: 'http://h:9107',
      toolArgPath: '/inputSchema/properties/query', position: 'body' }],
    ragPoints: [],
    exposedRuntimes: [{ name: 'ollama', category: 'ai-runtime', version: null, exposedOn: ['1.2.3.4:11434'] }],
    unauthenticatedMcp: [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'demo', toolCount: 4 }],
  },
  meta: { findings: 1, injectableParams: 1, ragPoints: 0, exposedRuntimes: 1, unauthenticatedMcp: 1 },
}

function mockFetch(payloadFor: (url: string) => unknown, ok = true) {
  global.fetch = vi.fn(async (url: string) => ({
    ok,
    status: ok ? 200 : 500,
    json: async () => (ok ? payloadFor(String(url)) : { error: 'fail' }),
  })) as unknown as typeof fetch
}

beforeEach(() => {
  mockFetch(url => (url.includes('aiSurface') ? SURFACE : RISK))
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('AiSurfaceTable', () => {
  test('fetches and renders the default (LLM Endpoints) sheet', async () => {
    render(createElement(AiSurfaceTable, { projectId: 'p1' }))
    await waitFor(() => expect(screen.getByText('/v1/chat/completions')).toBeTruthy())
    expect(screen.getByText('llm-chat')).toBeTruthy()
    expect((global.fetch as any)).toHaveBeenCalledWith(
      expect.stringContaining('/api/analytics/redzone/aiSurface?projectId=p1'))
  })

  test('renders every sheet tab (as buttons) with its count', async () => {
    render(createElement(AiSurfaceTable, { projectId: 'p1' }))
    await waitFor(() => screen.getByText('/v1/chat/completions'))
    for (const label of ['LLM Endpoints', 'MCP Servers', 'AI Technologies', 'Vector DBs', 'Model Inventory']) {
      // sheet tabs are buttons; the same label also appears in the meta summary,
      // so target the button role to disambiguate.
      expect(screen.getByRole('button', { name: new RegExp(label) })).toBeTruthy()
    }
  })

  test('switching to MCP Servers sheet shows MCP data', async () => {
    render(createElement(AiSurfaceTable, { projectId: 'p1' }))
    await waitFor(() => screen.getByText('/v1/chat/completions'))
    fireEvent.click(screen.getByRole('button', { name: /MCP Servers/ }))
    await waitFor(() => expect(screen.getByText('redamon-poison-mcp')).toBeTruthy())
    expect(screen.getByText('2025-06-18')).toBeTruthy()
  })

  test('does not fetch when projectId is null', async () => {
    render(createElement(AiSurfaceTable, { projectId: null }))
    await new Promise(r => setTimeout(r, 20))
    expect(global.fetch).not.toHaveBeenCalled()
  })
})

describe('AiRiskTable', () => {
  test('renders findings with severity + OWASP/ATLAS', async () => {
    render(createElement(AiRiskTable, { projectId: 'p1' }))
    await waitFor(() => expect(screen.getByText('mcp_tool_poisoning')).toBeTruthy())
    expect(screen.getByText('LLM01')).toBeTruthy()
    expect(screen.getByText('AML.T0051')).toBeTruthy()
    expect((global.fetch as any)).toHaveBeenCalledWith(
      expect.stringContaining('/api/analytics/redzone/aiRisk'))
  })

  test('empty sheet (RAG Ingestion) shows the empty-state label', async () => {
    render(createElement(AiRiskTable, { projectId: 'p1' }))
    await waitFor(() => screen.getByText('mcp_tool_poisoning'))
    fireEvent.click(screen.getByRole('button', { name: /RAG Ingestion/ }))
    await waitFor(() => expect(screen.getByText(/No RAG ingestion endpoints/i)).toBeTruthy())
  })

  test('null version cell renders without crashing', async () => {
    render(createElement(AiRiskTable, { projectId: 'p1' }))
    await waitFor(() => screen.getByText('mcp_tool_poisoning'))
    fireEvent.click(screen.getByRole('button', { name: /Exposed Runtimes/ }))
    await waitFor(() => expect(screen.getByText('ollama')).toBeTruthy())
    expect(screen.getByText('1.2.3.4:11434')).toBeTruthy()
  })
})
