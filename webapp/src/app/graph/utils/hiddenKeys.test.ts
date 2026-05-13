/**
 * Regression test: HIDDEN_KEYS was extracted from ExpandedRowDetail.tsx into a
 * shared util. This test pins the exact membership so a change is intentional,
 * and exercises the consumers (ExpandedRowDetail + NodeDetailsTable helpers)
 * to verify they still filter the same internal scoping fields.
 *
 * Run: npx vitest run src/app/graph/utils/hiddenKeys.test.ts
 */

import { describe, test, expect } from 'vitest'
import { HIDDEN_KEYS } from './hiddenKeys'
import { deriveDynamicColumnKeys } from '../components/NodeDetailsTable/nodeDetailsHelpers'
import type { TableRow } from '../hooks/useTableData'

describe('HIDDEN_KEYS shared util', () => {
  test('contains exactly the internal scoping fields (project_id, user_id)', () => {
    // Pin the membership so any addition/removal is an explicit, reviewed change.
    expect(Array.from(HIDDEN_KEYS).sort()).toEqual(['project_id', 'user_id'])
  })

  test('NodeDetailsTable column derivation strips HIDDEN_KEYS', () => {
    const rows: TableRow[] = [
      {
        node: {
          id: 'd1',
          name: 'example.com',
          type: 'Domain',
          properties: {
            name: 'example.com',
            project_id: 'p1',
            user_id: 'u1',
            registrar: 'GoDaddy',
          },
        },
        connectionsIn: [],
        connectionsOut: [],
        getLevel2: () => [],
        getLevel3: () => [],
      },
    ]
    const cols = deriveDynamicColumnKeys(rows)
    expect(cols).toEqual(['registrar'])
    expect(cols).not.toContain('project_id')
    expect(cols).not.toContain('user_id')
  })

  test('every member of HIDDEN_KEYS is filtered (not just project_id)', () => {
    // Build a node whose properties include EVERY HIDDEN key. None should appear
    // in derived columns. Using forEach to stay correct if HIDDEN_KEYS grows.
    const properties: Record<string, unknown> = { keep_me: 'visible' }
    HIDDEN_KEYS.forEach(k => {
      properties[k] = 'should_not_appear'
    })
    const rows: TableRow[] = [
      {
        node: { id: '1', name: 'n', type: 'X', properties },
        connectionsIn: [],
        connectionsOut: [],
        getLevel2: () => [],
        getLevel3: () => [],
      },
    ]
    const cols = deriveDynamicColumnKeys(rows)
    expect(cols).toEqual(['keep_me'])
    HIDDEN_KEYS.forEach(k => {
      expect(cols).not.toContain(k)
    })
  })
})
