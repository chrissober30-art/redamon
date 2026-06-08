/**
 * Tests for POST /api/users/[id]/tradecraft-resources.
 *
 * Covers the new `llmModel` requirement introduced when we moved
 * tradecraft off the agent's chat model and onto a per-resource model
 * picker. Before this change, POST silently used the agent's default
 * model and crashed with 401 when the user had no Anthropic key.
 *
 * What this asserts:
 *   1. POST rejects requests missing or empty `llmModel` (the API gate
 *      that protects against direct-API callers bypassing the UI).
 *   2. POST persists `llmModel` exactly as sent.
 *   3. The background `/tradecraft/verify` call forwards the resource's
 *      `llmModel` as the agent's `model` field.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

// -------------------------------------------------------------------------
// Prisma mocks — hoisted by vitest.
// -------------------------------------------------------------------------
const mockTradecraftCreate = vi.fn()
const mockTradecraftFindUnique = vi.fn()
const mockTradecraftUpdate = vi.fn()
const mockUserSettingsFindUnique = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userTradecraftResource: {
      create: (...a: unknown[]) => mockTradecraftCreate(...a),
      findUnique: (...a: unknown[]) => mockTradecraftFindUnique(...a),
      findMany: vi.fn(),
      update: (...a: unknown[]) => mockTradecraftUpdate(...a),
    },
    userSettings: {
      findUnique: (...a: unknown[]) => mockUserSettingsFindUnique(...a),
    },
  },
}))

import { NextRequest } from 'next/server'
import * as route from './route'

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/** The route reads `request.nextUrl.searchParams`, so plain `Request` won't
 *  work — we need a `NextRequest` (which extends Request with .nextUrl). */
function makeRequest(body: unknown, qs = ''): NextRequest {
  return new NextRequest(
    `http://webapp.test/api/users/user-1/tradecraft-resources${qs}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  )
}

const PARAMS = { params: Promise.resolve({ id: 'user-1' }) }

/** Captures the last `fetch` call against the agent API. */
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

/** Wait one event loop tick — POST kicks off background verify with a
 *  fire-and-forget IIFE; we need the awaitable scheduling to flush. */
async function flushMicrotasks() {
  // Give fire-and-forget verify call a chance to fire the fetch stub.
  // 50 ms is enough for vitest's fake-async to drain in practice; we
  // assert on captured shape afterwards so a slow CI just takes longer.
  await new Promise(r => setTimeout(r, 50))
}

beforeEach(() => {
  mockTradecraftCreate.mockReset()
  mockTradecraftFindUnique.mockReset().mockResolvedValue(null)
  mockTradecraftUpdate.mockReset().mockResolvedValue({})
  mockUserSettingsFindUnique.mockReset().mockResolvedValue(null)
  capturedFetch = null
})

afterEach(() => {
  vi.restoreAllMocks()
})

// -------------------------------------------------------------------------
// llmModel required at API layer
// -------------------------------------------------------------------------

describe('POST llmModel requirement', () => {
  test('rejects missing llmModel with 400', async () => {
    const req = makeRequest({ name: 'HackTricks', url: 'https://book.hacktricks.wiki' })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
    const body = await r.json()
    expect(body.error).toMatch(/llmModel is required/i)
    expect(mockTradecraftCreate).not.toHaveBeenCalled()
  })

  test('rejects empty-string llmModel with 400', async () => {
    const req = makeRequest({
      name: 'HackTricks',
      url: 'https://book.hacktricks.wiki',
      llmModel: '',
    })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
    expect(mockTradecraftCreate).not.toHaveBeenCalled()
  })

  test('rejects whitespace-only llmModel with 400', async () => {
    const req = makeRequest({
      name: 'X', url: 'https://x.com', llmModel: '   ',
    })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
    expect(mockTradecraftCreate).not.toHaveBeenCalled()
  })

  test('rejects non-string llmModel with 400', async () => {
    const req = makeRequest({
      name: 'X', url: 'https://x.com', llmModel: 123,
    })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
    expect(mockTradecraftCreate).not.toHaveBeenCalled()
  })
})

// -------------------------------------------------------------------------
// llmModel persisted on create + trimmed
// -------------------------------------------------------------------------

describe('POST llmModel persistence', () => {
  test('persists llmModel exactly as sent (when no whitespace)', async () => {
    mockTradecraftCreate.mockResolvedValue({
      id: 'res-1', name: 'HackTricks', slug: 'hacktricks',
      url: 'https://book.hacktricks.wiki', llmModel: 'bedrock/minimax.minimax-m2.5',
      githubTokenOverride: '', enabled: true, resourceType: 'agentic-crawl',
    })
    installFetchStub({})
    const req = makeRequest({
      name: 'HackTricks',
      url: 'https://book.hacktricks.wiki',
      llmModel: 'bedrock/minimax.minimax-m2.5',
    }, '?skipVerify=true')
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(201)
    expect(mockTradecraftCreate).toHaveBeenCalledTimes(1)
    const args = mockTradecraftCreate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.llmModel).toBe('bedrock/minimax.minimax-m2.5')
  })

  test('trims leading/trailing whitespace before persisting', async () => {
    mockTradecraftCreate.mockResolvedValue({
      id: 'res-1', name: 'X', url: 'https://x.com', slug: 'x',
      llmModel: 'claude-haiku-4-5', githubTokenOverride: '', enabled: true,
      resourceType: 'agentic-crawl',
    })
    const req = makeRequest({
      name: 'X', url: 'https://x.com',
      llmModel: '  claude-haiku-4-5  ',
    }, '?skipVerify=true')
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(201)
    const args = mockTradecraftCreate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.llmModel).toBe('claude-haiku-4-5')
  })
})

// -------------------------------------------------------------------------
// Background verify forwards llmModel as `model` field
// -------------------------------------------------------------------------

describe('POST background verify forwards model', () => {
  test('agent verify call includes model field from llmModel', async () => {
    mockTradecraftCreate.mockResolvedValue({
      id: 'res-7', name: 'HT', slug: 'ht',
      url: 'https://book.hacktricks.wiki',
      llmModel: 'bedrock/minimax.minimax-m2.5',
      githubTokenOverride: '',
      enabled: true, resourceType: 'agentic-crawl',
    })
    installFetchStub({
      summary: 'stub', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const req = makeRequest({
      name: 'HT',
      url: 'https://book.hacktricks.wiki',
      llmModel: 'bedrock/minimax.minimax-m2.5',
    })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(201)
    await flushMicrotasks()
    expect(capturedFetch).not.toBeNull()
    // Path: /tradecraft/verify on the agent.
    expect(capturedFetch!.url).toContain('/tradecraft/verify')
    // Body: model field present, set to the persisted llmModel.
    const fetchedBody = JSON.parse(String(capturedFetch!.init.body))
    expect(fetchedBody.model).toBe('bedrock/minimax.minimax-m2.5')
    expect(fetchedBody.url).toBe('https://book.hacktricks.wiki')
    expect(fetchedBody.user_id).toBe('user-1')
  })

  test('agent verify call is skipped when skipVerify=true', async () => {
    mockTradecraftCreate.mockResolvedValue({
      id: 'res-8', name: 'X', slug: 'x', url: 'https://x.com',
      llmModel: 'gpt-4o', githubTokenOverride: '', enabled: true,
      resourceType: 'agentic-crawl',
    })
    installFetchStub({})
    const req = makeRequest({
      name: 'X', url: 'https://x.com', llmModel: 'gpt-4o',
    }, '?skipVerify=true')
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(201)
    await flushMicrotasks()
    expect(capturedFetch).toBeNull()
  })
})

// -------------------------------------------------------------------------
// Basic validation still works (regression — not new logic)
// -------------------------------------------------------------------------

describe('POST general validation (regression)', () => {
  test('missing name returns 400', async () => {
    const req = makeRequest({ url: 'https://x.com', llmModel: 'gpt-4o' })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
  })

  test('missing url returns 400', async () => {
    const req = makeRequest({ name: 'X', llmModel: 'gpt-4o' })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
  })

  test('private-network URL rejected', async () => {
    const req = makeRequest({
      name: 'X', url: 'http://127.0.0.1/x', llmModel: 'gpt-4o',
    })
    const r = await route.POST(req as never, PARAMS as never)
    expect(r.status).toBe(400)
    const body = await r.json()
    expect(body.error).toMatch(/private|http/i)
  })
})
