/**
 * Integration tests for /api/user/preferences route handlers.
 *
 * Run: npx vitest run src/app/api/user/preferences/route.test.ts
 *
 * Mocks @/lib/prisma and @/lib/session so handlers can be exercised end-to-end
 * without requiring a database or a real auth cookie.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

// ---------------------------------------------------------------------------
// Mocks (must be hoisted via vi.mock — declarations only)
// ---------------------------------------------------------------------------

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockGetSession = vi.fn()
const mockRequireSession = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: (...args: unknown[]) => mockFindUnique(...args),
      update: (...args: unknown[]) => mockUpdate(...args),
    },
  },
}))

vi.mock('@/lib/session', async () => {
  const actual = await vi.importActual<typeof import('next/server')>('next/server')
  return {
    getSession: (...args: unknown[]) => mockGetSession(...args),
    requireSession: async (...args: unknown[]) => {
      const result = await mockRequireSession(...args)
      // requireSession may return a NextResponse or a Session.
      return result
    },
    isInternalRequest: () => false,
    // Re-export so route can `instanceof NextResponse` correctly
    __esModule: true,
    NextResponse: actual.NextResponse,
  }
})

import { NextResponse } from 'next/server'
import { GET, PATCH } from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(userId = 'user-1') {
  return { userId, role: 'standard' as const }
}

function makeRequest(body?: unknown): Request {
  return new Request('http://localhost/api/user/preferences', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpdate.mockReset()
  mockGetSession.mockReset()
  mockRequireSession.mockReset()
})

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

describe('GET /api/user/preferences', () => {
  test('401 when no session', async () => {
    mockRequireSession.mockResolvedValue(
      NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    )
    const res = await GET()
    expect(res.status).toBe(401)
  })

  test('returns {} when uiPreferences is null (existing user, never set)', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue({ uiPreferences: null })
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({})
  })

  test('returns existing preferences', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    const stored = { nodeDetailsTable: { Domain: { hiddenColumns: ['x'] } } }
    mockFindUnique.mockResolvedValue({ uiPreferences: stored })
    const res = await GET()
    expect(await res.json()).toEqual(stored)
  })

  test('404 when user not found', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue(null)
    const res = await GET()
    expect(res.status).toBe(404)
  })

  test('500 when prisma throws', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockRejectedValue(new Error('db down'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET()
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })

  test('queries only the current session userId', async () => {
    mockRequireSession.mockResolvedValue(makeSession('user-XYZ'))
    mockFindUnique.mockResolvedValue({ uiPreferences: {} })
    await GET()
    expect(mockFindUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'user-XYZ' } })
    )
  })
})

// ---------------------------------------------------------------------------
// PATCH
// ---------------------------------------------------------------------------

describe('PATCH /api/user/preferences', () => {
  test('401 when no session', async () => {
    mockRequireSession.mockResolvedValue(
      NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    )
    const res = await PATCH(makeRequest({ featureKey: 'k', value: {} }) as never)
    expect(res.status).toBe(401)
  })

  test('400 on missing featureKey', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    const res = await PATCH(makeRequest({ value: {} }) as never)
    expect(res.status).toBe(400)
  })

  test('400 on empty featureKey', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    const res = await PATCH(makeRequest({ featureKey: '', value: {} }) as never)
    expect(res.status).toBe(400)
  })

  test('400 on undefined value', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    const res = await PATCH(makeRequest({ featureKey: 'k' }) as never)
    expect(res.status).toBe(400)
  })

  test('400 on invalid JSON body', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    const req = new Request('http://localhost/api/user/preferences', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json{',
    })
    const res = await PATCH(req as never)
    expect(res.status).toBe(400)
  })

  test('merges new featureKey into existing preferences (preserves other keys)', async () => {
    mockRequireSession.mockResolvedValue(makeSession('u1'))
    mockFindUnique.mockResolvedValue({
      uiPreferences: { otherFeature: { keep: 'me' } },
    })
    mockUpdate.mockImplementation(({ data }: { data: { uiPreferences: unknown } }) => ({
      uiPreferences: data.uiPreferences,
    }))

    const res = await PATCH(
      makeRequest({ featureKey: 'nodeDetailsTable', value: { Domain: { hiddenColumns: ['a'] } } }) as never
    )

    expect(res.status).toBe(200)
    const writtenData = mockUpdate.mock.calls[0][0].data
    expect(writtenData.uiPreferences).toEqual({
      otherFeature: { keep: 'me' },
      nodeDetailsTable: { Domain: { hiddenColumns: ['a'] } },
    })
  })

  test('replaces existing featureKey value entirely (no deep merge)', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue({
      uiPreferences: {
        nodeDetailsTable: {
          Domain: { hiddenColumns: ['old1', 'old2'] },
          IP: { hiddenColumns: ['ipOld'] },
        },
      },
    })
    mockUpdate.mockImplementation(({ data }: { data: { uiPreferences: unknown } }) => ({
      uiPreferences: data.uiPreferences,
    }))

    // Send a new value with only Domain key — IP key should be DROPPED
    await PATCH(
      makeRequest({
        featureKey: 'nodeDetailsTable',
        value: { Domain: { hiddenColumns: ['new'] } },
      }) as never
    )

    const writtenData = mockUpdate.mock.calls[0][0].data
    expect(writtenData.uiPreferences).toEqual({
      nodeDetailsTable: { Domain: { hiddenColumns: ['new'] } },
    })
  })

  test('treats null uiPreferences as {} when merging', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue({ uiPreferences: null })
    mockUpdate.mockImplementation(({ data }: { data: { uiPreferences: unknown } }) => ({
      uiPreferences: data.uiPreferences,
    }))

    await PATCH(
      makeRequest({ featureKey: 'newFeature', value: { x: 1 } }) as never
    )

    const writtenData = mockUpdate.mock.calls[0][0].data
    expect(writtenData.uiPreferences).toEqual({ newFeature: { x: 1 } })
  })

  test('accepts primitive values (string, number, bool)', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue({ uiPreferences: {} })
    mockUpdate.mockImplementation(({ data }: { data: { uiPreferences: unknown } }) => ({
      uiPreferences: data.uiPreferences,
    }))

    await PATCH(makeRequest({ featureKey: 'theme', value: 'dark' }) as never)

    const writtenData = mockUpdate.mock.calls[0][0].data
    expect(writtenData.uiPreferences).toEqual({ theme: 'dark' })
  })

  test('404 when user not found', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue(null)
    const res = await PATCH(makeRequest({ featureKey: 'k', value: {} }) as never)
    expect(res.status).toBe(404)
  })

  test('500 when prisma update throws', async () => {
    mockRequireSession.mockResolvedValue(makeSession())
    mockFindUnique.mockResolvedValue({ uiPreferences: {} })
    mockUpdate.mockRejectedValue(new Error('write failed'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PATCH(makeRequest({ featureKey: 'k', value: {} }) as never)
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})
