/**
 * Integration test for the server-side model-guard in POST /api/projects.
 *
 * Run: npx vitest run "src/app/api/projects/route.modelGuard.integration.test.ts"
 *
 * Exercises the real route handler (real Prisma DMMF-based sanitizer + real
 * isBlankModelField) with prisma and Neo4j mocked. Proves the regression fix:
 * a blank agentOpenaiModel/aiPipelineModel is DROPPED on create so the schema
 * @default("claude-opus-4-6") applies, instead of persisting "" — the
 * server-side backstop for the client model-gate.
 *
 * Uses ipMode:true (skips targetDomain requirement + the Neo4j Domain node) and
 * targetGuardrailEnabled:false (skips the soft-guardrail fetch) to keep the
 * handler's collaborators minimal.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockProjectUpdate = vi.fn()
const mockGetSession = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => mockProjectCreate(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))

// Neo4j session — not reached in ipMode, but mocked so the import resolves.
vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: (...a: unknown[]) => mockGetSession(...a),
}))

import { POST } from './route'

function postReq(body: Record<string, unknown>) {
  return new Request('http://localhost/api/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

const BASE = {
  userId: 'user-1',
  name: 'Test Project',
  ipMode: true,
  targetGuardrailEnabled: false,
}

beforeEach(() => {
  mockUserFindUnique.mockReset()
  mockProjectCreate.mockReset()
  mockProjectUpdate.mockReset()
  mockGetSession.mockReset()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  // Echo the create data back as the created project.
  mockProjectCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
    id: 'proj-1',
    ...data,
  }))
})

function createdData() {
  expect(mockProjectCreate).toHaveBeenCalledTimes(1)
  return mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>
}

describe('POST /api/projects — model-field guard', () => {
  test('REGRESSION: blank agentOpenaiModel is dropped (schema default applies)', async () => {
    const res = await POST(postReq({ ...BASE, agentOpenaiModel: '' }))
    expect(res.status).toBe(201)
    expect('agentOpenaiModel' in createdData()).toBe(false)
  })

  test('REGRESSION: blank aiPipelineModel is dropped', async () => {
    const res = await POST(postReq({ ...BASE, aiPipelineModel: '   ' }))
    expect(res.status).toBe(201)
    expect('aiPipelineModel' in createdData()).toBe(false)
  })

  test('REGRESSION: both blank models dropped together', async () => {
    await POST(postReq({ ...BASE, agentOpenaiModel: '', aiPipelineModel: '' }))
    const data = createdData()
    expect('agentOpenaiModel' in data).toBe(false)
    expect('aiPipelineModel' in data).toBe(false)
  })

  test('a real agent model IS persisted', async () => {
    await POST(postReq({ ...BASE, agentOpenaiModel: 'deepseek/deepseek-chat' }))
    expect(createdData().agentOpenaiModel).toBe('deepseek/deepseek-chat')
  })

  test('a real pipeline model IS persisted', async () => {
    await POST(postReq({ ...BASE, aiPipelineModel: 'deepseek/deepseek-reasoner' }))
    expect(createdData().aiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('mixed: real agent model kept, blank pipeline dropped', async () => {
    await POST(
      postReq({ ...BASE, agentOpenaiModel: 'deepseek/deepseek-chat', aiPipelineModel: '' }),
    )
    const data = createdData()
    expect(data.agentOpenaiModel).toBe('deepseek/deepseek-chat')
    expect('aiPipelineModel' in data).toBe(false)
  })
})
