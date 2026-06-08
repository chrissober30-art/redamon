/**
 * Regression + unit tests for the /api/models proxy route.
 *
 * Pre-fix: `GET /api/models?userId=xxx` fetched the user's UserLlmProvider rows
 * from Postgres and forwarded them — apiKey and all — as a URL-encoded
 * `?providers=...` query string on a GET to the agent's `/models` endpoint.
 * uvicorn's access log persisted the full URL (including the apiKey) to disk.
 *
 * Post-fix: `POST /api/models` reads `userId` from a JSON body and forwards
 * the providers list in a JSON POST body to the agent — never in a URL.
 *
 * Tests below would fail pre-fix:
 *   - "exports POST, not GET" — pre-fix only exported GET
 *   - "agent fetch is POST" — pre-fix used GET
 *   - "apiKey appears only in fetch body, never in URL" — pre-fix put it in URL
 *
 * Run: npx vitest run src/app/api/models/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const CANARY_KEY = 'sk-ant-api03-LEAK-CANARY-DO-NOT-LOG-XXXXXXXXXX'

// Mock Prisma before importing the route. Hoisted by vitest.
const mockFindMany = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { userLlmProvider: { findMany: (...args: unknown[]) => mockFindMany(...args) } },
}))

// Import after mocks are registered. Vitest hoists vi.mock above this.
// Note: AGENT_API_URL is captured at module-import time, so it resolves to the
// default `http://localhost:8090`. Tests assert on URL shape (path + query),
// not the host, since the host isn't what leaks.
import * as route from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(body: unknown | undefined): Request {
  const init: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }
  if (body !== undefined) init.body = JSON.stringify(body)
  return new Request('http://webapp.test/api/models', init)
}

/** Capture the last `fetch` call arguments for assertion. */
let capturedFetch: { url: string; init: RequestInit } | null = null

function installFetchStub(response: unknown, ok = true): void {
  capturedFetch = null
  global.fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    capturedFetch = { url: String(url), init: init ?? {} }
    return new Response(JSON.stringify(response), {
      status: ok ? 200 : 503,
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
}

beforeEach(() => {
  mockFindMany.mockReset()
  capturedFetch = null
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Route exports — regression: GET must not exist anymore.
// ---------------------------------------------------------------------------

describe('route module exports', () => {
  test('exports POST, not GET (regression: pre-fix exported GET)', () => {
    expect(typeof route.POST).toBe('function')
    expect((route as Record<string, unknown>).GET).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// POST handler — happy paths
// ---------------------------------------------------------------------------

describe('POST /api/models', () => {
  test('with userId: fetches providers from DB and forwards to agent as POST body', async () => {
    const providerRow = {
      id: 'p1',
      userId: 'u1',
      providerType: 'anthropic',
      name: 'Anthropic',
      apiKey: CANARY_KEY,
    }
    mockFindMany.mockResolvedValueOnce([providerRow])
    installFetchStub({ anthropic: [{ id: 'claude-x' }] })

    const res = await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ anthropic: [{ id: 'claude-x' }] })

    expect(mockFindMany).toHaveBeenCalledWith({ where: { userId: 'u1' } })

    expect(capturedFetch).not.toBeNull()
    // URL is path-suffix `/models` with NO query string.
    expect(capturedFetch!.url).toMatch(/\/models$/)
    expect(capturedFetch!.url).not.toContain('?')
    expect(capturedFetch!.init.method).toBe('POST')
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody.providers).toEqual([providerRow])
  })

  test('without userId: no DB lookup, agent gets null providers', async () => {
    installFetchStub({})

    const res = await route.POST(makeRequest({}) as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).not.toHaveBeenCalled()
    expect(capturedFetch!.init.method).toBe('POST')
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody).toEqual({ providers: null })
  })

  test('with userId but no provider rows: null providers, no upstream leak', async () => {
    mockFindMany.mockResolvedValueOnce([])
    installFetchStub({})

    const res = await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).toHaveBeenCalled()
    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody).toEqual({ providers: null })
  })

  test('malformed body: handler treats it as empty (no DB lookup, no crash)', async () => {
    installFetchStub({})

    // Body that is not valid JSON.
    const bad = new Request('http://webapp.test/api/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    })
    const res = await route.POST(bad as never)

    expect(res.status).toBe(200)
    expect(mockFindMany).not.toHaveBeenCalled()
  })

  test('agent error response is propagated as 503', async () => {
    mockFindMany.mockResolvedValueOnce([])
    installFetchStub({ error: 'boom' }, false)

    const res = await route.POST(makeRequest({}) as never)
    expect(res.status).toBe(503)
  })
})

// ---------------------------------------------------------------------------
// Critical regression: apiKey is in BODY, never in URL.
// ---------------------------------------------------------------------------

describe('apiKey leakage — URL must never carry the key', () => {
  test('canary apiKey appears in fetch body but NOT in fetch URL', async () => {
    mockFindMany.mockResolvedValueOnce([
      { id: 'p1', userId: 'u1', providerType: 'anthropic', apiKey: CANARY_KEY },
    ])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    expect(capturedFetch).not.toBeNull()
    // URL must NOT contain the canary, the literal "apiKey" param name, nor
    // the URL-encoded `providers=` blob that leaked pre-fix.
    expect(capturedFetch!.url).not.toContain(CANARY_KEY)
    expect(capturedFetch!.url).not.toContain(encodeURIComponent(CANARY_KEY))
    expect(capturedFetch!.url).not.toContain('apiKey')
    expect(capturedFetch!.url).not.toContain('providers=')

    // Sanity: the body DOES contain it (so the agent can use it downstream).
    expect(capturedFetch!.init.body as string).toContain(CANARY_KEY)
  })

  test('canary in body survives JSON round-trip, parsed value matches', async () => {
    mockFindMany.mockResolvedValueOnce([
      { providerType: 'openai', apiKey: CANARY_KEY },
      { providerType: 'anthropic', apiKey: 'sk-ant-api03-OTHER-KEY' },
    ])
    installFetchStub({})

    await route.POST(makeRequest({ userId: 'u1' }) as never)

    const sentBody = JSON.parse(capturedFetch!.init.body as string)
    expect(sentBody.providers).toHaveLength(2)
    expect(sentBody.providers[0].apiKey).toBe(CANARY_KEY)
    expect(sentBody.providers[1].apiKey).toBe('sk-ant-api03-OTHER-KEY')
  })
})
