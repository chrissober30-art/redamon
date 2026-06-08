/**
 * Tests for PUT /api/users/[id]/tradecraft-resources/[resourceId].
 *
 * Asserts on the `llmModel` field behavior:
 *   - Updating with a non-empty llmModel succeeds and persists trimmed.
 *   - Updating with an empty / whitespace llmModel returns 400.
 *   - Omitting llmModel entirely leaves the existing value untouched.
 *   - Server-managed fields (slug, summary, sitemap, resourceType, crawl_*)
 *     are still stripped from the update — regression test on the existing
 *     deletion logic, which we left untouched.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const mockFindFirst = vi.fn()
const mockUpdate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userTradecraftResource: {
      findFirst: (...a: unknown[]) => mockFindFirst(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
  },
}))

import { NextRequest } from 'next/server'
import * as route from './route'

const PARAMS = (resId = 'res-1') => ({
  params: Promise.resolve({ id: 'user-1', resourceId: resId }),
})

function makePut(body: unknown): NextRequest {
  return new NextRequest(
    'http://webapp.test/api/users/user-1/tradecraft-resources/res-1',
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  )
}

const EXISTING = {
  id: 'res-1', userId: 'user-1', slug: 'hacktricks',
  name: 'HackTricks', url: 'https://book.hacktricks.wiki',
  enabled: true, resourceType: 'mkdocs-wiki',
  summary: 'old summary', sitemap: { x: 1 },
  crawlStoppedBecause: '', crawlStats: {},
  githubTokenOverride: 'ghp_realtoken1234',
  cacheTtlSec: 0,
  llmModel: 'gpt-4o-existing',
  lastVerifiedAt: null, lastRefreshedAt: null, lastError: '',
}

beforeEach(() => {
  mockFindFirst.mockReset().mockResolvedValue(EXISTING)
  mockUpdate.mockReset().mockImplementation(async (args: unknown) => {
    const { data } = args as { data: Record<string, unknown> }
    return { ...EXISTING, ...data }
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

// -------------------------------------------------------------------------
// llmModel updates
// -------------------------------------------------------------------------

describe('PUT llmModel updates', () => {
  test('updating llmModel to a new value persists the new value (trimmed)', async () => {
    const r = await route.PUT(
      makePut({ llmModel: '  bedrock/minimax.minimax-m2.5  ' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalledTimes(1)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.llmModel).toBe('bedrock/minimax.minimax-m2.5')
  })

  test('rejects empty-string llmModel with 400 (resource would be unusable)', async () => {
    const r = await route.PUT(
      makePut({ llmModel: '' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(400)
    const body = await r.json()
    expect(body.error).toMatch(/llmModel cannot be empty/i)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('rejects whitespace-only llmModel with 400', async () => {
    const r = await route.PUT(
      makePut({ llmModel: '    ' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('rejects non-string llmModel with 400', async () => {
    const r = await route.PUT(
      makePut({ llmModel: 42 }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('omitting llmModel leaves existing value untouched (no key in update)', async () => {
    const r = await route.PUT(
      makePut({ name: 'HackTricks renamed' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect('llmModel' in args.data).toBe(false)
    expect(args.data.name).toBe('HackTricks renamed')
  })
})

// -------------------------------------------------------------------------
// Server-managed fields stripped (regression — not new logic, but if a
// future llmModel-related refactor breaks the strip list these tests catch it)
// -------------------------------------------------------------------------

describe('PUT strips server-managed fields (regression)', () => {
  test('slug cannot be changed via PUT', async () => {
    const r = await route.PUT(
      makePut({ slug: 'attacker-supplied-slug', llmModel: 'gpt-4o' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect('slug' in args.data).toBe(false)
  })

  test('summary / sitemap / resourceType cannot be changed via PUT', async () => {
    const r = await route.PUT(
      makePut({
        summary: 'attacker summary',
        sitemap: { malicious: true },
        resourceType: 'agentic-crawl',
        crawlStoppedBecause: 'fake',
        crawlStats: { fake: 1 },
      }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect('summary' in args.data).toBe(false)
    expect('sitemap' in args.data).toBe(false)
    expect('resourceType' in args.data).toBe(false)
    expect('crawlStoppedBecause' in args.data).toBe(false)
    expect('crawlStats' in args.data).toBe(false)
  })

  test('masked github token preserved when user did not change it', async () => {
    const r = await route.PUT(
      makePut({ githubTokenOverride: '••••••••1234' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.githubTokenOverride).toBe('ghp_realtoken1234')
  })

  test('real github token override updates persist', async () => {
    const r = await route.PUT(
      makePut({ githubTokenOverride: 'ghp_NEW_TOKEN_HERE' }) as never,
      PARAMS() as never,
    )
    expect(r.status).toBe(200)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.githubTokenOverride).toBe('ghp_NEW_TOKEN_HERE')
  })

  test('returns 404 when resource not owned by user', async () => {
    mockFindFirst.mockResolvedValueOnce(null)
    const r = await route.PUT(
      makePut({ llmModel: 'gpt-4o' }) as never,
      PARAMS('missing') as never,
    )
    expect(r.status).toBe(404)
  })
})
