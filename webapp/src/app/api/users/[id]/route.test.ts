/**
 * Integration tests for /api/users/[id] GET + PUT.
 *
 * Run: npx vitest run "src/app/api/users/[id]/route.test.ts"
 *
 * Focus: the per-user remembered-model defaults (defaultAgentModel /
 * defaultAiPipelineModel) added for the project model-gate feature — that GET
 * returns them, PUT persists them, the typeof-string guard holds, and a
 * standard user can update their OWN defaults without admin rights.
 *
 * @/lib/prisma and @/lib/session are mocked so handlers run without a DB or
 * a real auth cookie.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: (...args: unknown[]) => mockFindUnique(...args),
      update: (...args: unknown[]) => mockUpdate(...args),
    },
  },
}))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import { GET, PUT } from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(userId = 'user-1', role: 'admin' | 'standard' = 'standard') {
  return { userId, role }
}

function makeParams(id: string) {
  return { params: Promise.resolve({ id }) }
}

function getReq() {
  return new Request('http://localhost/api/users/user-1') as never
}

function putReq(body: unknown) {
  return new Request('http://localhost/api/users/user-1', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpdate.mockReset()
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
  mockIsInternal.mockReturnValue(false)
})

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

describe('GET /api/users/[id]', () => {
  test('401 when no session (not internal)', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user requests another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await GET(getReq(), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('returns the user including the new default-model fields (self)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({
      id: 'user-1',
      name: 'Sam',
      email: 's@example.com',
      role: 'standard',
      defaultAgentModel: 'deepseek/deepseek-chat',
      defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      projects: [],
    })
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(body.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('select clause requests the new default-model fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({ id: 'user-1', projects: [] })
    await GET(getReq(), makeParams('user-1'))
    const select = mockFindUnique.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('internal request bypasses session checks', async () => {
    mockIsInternal.mockReturnValue(true)
    mockFindUnique.mockResolvedValue({ id: 'user-9', defaultAgentModel: null, projects: [] })
    const res = await GET(getReq(), makeParams('user-9'))
    expect(res.status).toBe(200)
    expect(mockGetSession).not.toHaveBeenCalled()
  })

  test('404 when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(404)
  })

  test('500 when prisma throws', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockRejectedValue(new Error('db down'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

describe('PUT /api/users/[id]', () => {
  test('401 when no session', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user updates another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('standard user persists their OWN default models (no admin needed)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
      id: 'user-1',
      ...data,
    }))
    const res = await PUT(
      putReq({
        defaultAgentModel: 'deepseek/deepseek-chat',
        defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      }),
      makeParams('user-1'),
    )
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(data.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('only the provided default field is written (partial update)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(putReq({ defaultAgentModel: 'deepseek/deepseek-chat' }), makeParams('user-1'))
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('non-string default values are ignored (typeof guard)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    // numbers / objects must not reach the DB write
    await PUT(
      putReq({ defaultAgentModel: 123, defaultAiPipelineModel: { nope: true } }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect('defaultAgentModel' in data).toBe(false)
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('the new default fields are returned in the select clause', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockResolvedValue({ id: 'user-1' })
    await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    const select = mockUpdate.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('updating name/email still works alongside the new fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(
      putReq({ name: 'New Name', defaultAgentModel: 'deepseek/deepseek-chat' }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.name).toBe('New Name')
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
  })

  test('404 (P2025) when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(Object.assign(new Error('not found'), { code: 'P2025' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(404)
    errSpy.mockRestore()
  })

  test('500 on other prisma errors', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(new Error('write failed'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})
