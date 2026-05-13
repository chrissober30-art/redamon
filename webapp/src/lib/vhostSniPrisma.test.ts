/**
 * Real Prisma round-trip test for vhostSni* fields.
 *
 * Creates a project with vhostSni* values via Prisma client, reads them back,
 * verifies the column shapes match the schema, then deletes the test project.
 *
 * Hits a real Postgres instance (the redamon-postgres docker container).
 * Auto-skips when PRISMA_FOR_TESTS_OK env var isn't set.
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()
let testUserId: string
let testProjectId: string

const HAS_DB = process.env.DATABASE_URL !== undefined

beforeAll(async () => {
  if (!HAS_DB) return
  const user = await prisma.user.create({
    data: {
      email: `vhostsni-prisma-test-${Date.now()}@example.com`,
      name: 'vhost-sni test user',
      password: 'x',
    },
  })
  testUserId = user.id
})

afterAll(async () => {
  if (!HAS_DB) return
  if (testProjectId) {
    try {
      await prisma.project.delete({ where: { id: testProjectId } })
    } catch { /* ignore */ }
  }
  if (testUserId) {
    try {
      await prisma.user.delete({ where: { id: testUserId } })
    } catch { /* ignore */ }
  }
  await prisma.$disconnect()
})

describe.skipIf(!HAS_DB)('Prisma round-trip: vhostSni* fields', () => {
  test('default values match the schema (project created with no overrides)', async () => {
    const project = await prisma.project.create({
      data: {
        name: 'Default vhostsni',
        userId: testUserId,
        targetDomain: 'example.com',
      },
    })
    testProjectId = project.id

    expect(project.vhostSniEnabled).toBe(false)
    expect(project.vhostSniTimeout).toBe(3)
    expect(project.vhostSniConcurrency).toBe(20)
    expect(project.vhostSniBaselineSizeTolerance).toBe(50)
    expect(project.vhostSniTestL7).toBe(true)
    expect(project.vhostSniTestL4).toBe(true)
    expect(project.vhostSniInjectDiscovered).toBe(true)
    expect(project.vhostSniUseDefaultWordlist).toBe(true)
    expect(project.vhostSniUseGraphCandidates).toBe(true)
    expect(project.vhostSniCustomWordlist).toBe('')
    expect(project.vhostSniMaxCandidatesPerIp).toBe(2000)
  })

  test('round-trip: write all 11 fields, read them back exactly', async () => {
    const updated = await prisma.project.update({
      where: { id: testProjectId },
      data: {
        vhostSniEnabled: true,
        vhostSniTimeout: 7,
        vhostSniConcurrency: 50,
        vhostSniBaselineSizeTolerance: 200,
        vhostSniTestL7: true,
        vhostSniTestL4: false,
        vhostSniInjectDiscovered: false,
        vhostSniUseDefaultWordlist: false,
        vhostSniUseGraphCandidates: true,
        vhostSniCustomWordlist: 'admin\nstaging\ninternal',
        vhostSniMaxCandidatesPerIp: 5000,
      },
    })

    expect(updated.vhostSniEnabled).toBe(true)
    expect(updated.vhostSniTimeout).toBe(7)
    expect(updated.vhostSniConcurrency).toBe(50)
    expect(updated.vhostSniBaselineSizeTolerance).toBe(200)
    expect(updated.vhostSniTestL7).toBe(true)
    expect(updated.vhostSniTestL4).toBe(false)
    expect(updated.vhostSniInjectDiscovered).toBe(false)
    expect(updated.vhostSniUseDefaultWordlist).toBe(false)
    expect(updated.vhostSniUseGraphCandidates).toBe(true)
    expect(updated.vhostSniCustomWordlist).toBe('admin\nstaging\ninternal')
    expect(updated.vhostSniMaxCandidatesPerIp).toBe(5000)

    // Re-read fresh from DB to be paranoid about ORM-level caching
    const reread = await prisma.project.findUniqueOrThrow({ where: { id: testProjectId } })
    expect(reread.vhostSniCustomWordlist).toBe('admin\nstaging\ninternal')
    expect(reread.vhostSniMaxCandidatesPerIp).toBe(5000)
  })

  test('large custom wordlist (Text column, not Varchar) survives round-trip', async () => {
    // 50KB wordlist — would fail if the column were Varchar(255).
    const big = Array.from({ length: 5000 }, (_, i) => `host${i.toString().padStart(4, '0')}`).join('\n')
    const updated = await prisma.project.update({
      where: { id: testProjectId },
      data: { vhostSniCustomWordlist: big },
    })
    expect(updated.vhostSniCustomWordlist.length).toBe(big.length)
    expect(updated.vhostSniCustomWordlist).toBe(big)
  })

  test('snake_case column names exposed via raw SQL match Prisma camelCase', async () => {
    const rows = await prisma.$queryRaw<Array<Record<string, unknown>>>`
      SELECT vhost_sni_enabled, vhost_sni_timeout, vhost_sni_concurrency,
             vhost_sni_baseline_size_tolerance, vhost_sni_test_l7, vhost_sni_test_l4,
             vhost_sni_inject_discovered, vhost_sni_use_default_wordlist,
             vhost_sni_use_graph_candidates, vhost_sni_custom_wordlist,
             vhost_sni_max_candidates_per_ip
      FROM projects WHERE id = ${testProjectId}
    `
    expect(rows.length).toBe(1)
    const row = rows[0]
    // Raw SQL returned snake_case columns — assert each present (not undefined)
    for (const col of [
      'vhost_sni_enabled', 'vhost_sni_timeout', 'vhost_sni_concurrency',
      'vhost_sni_baseline_size_tolerance', 'vhost_sni_test_l7', 'vhost_sni_test_l4',
      'vhost_sni_inject_discovered', 'vhost_sni_use_default_wordlist',
      'vhost_sni_use_graph_candidates', 'vhost_sni_custom_wordlist',
      'vhost_sni_max_candidates_per_ip',
    ]) {
      expect(row[col]).toBeDefined()
    }
  })
})
