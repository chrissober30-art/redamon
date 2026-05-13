/**
 * Unit tests for NodeDetails export builders.
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/exportNodeDetails.test.ts
 *
 * Tests the pure data-shaping logic (`buildExportData`, `slugForType`) plus
 * the CSV / JSON / Markdown download paths (downloadBlob is exercised via a
 * mocked URL/anchor pair so we can assert the emitted blob content).
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import type { TableRow } from '../../hooks/useTableData'
import type { GraphNode } from '../../types'
import {
  __testing,
  exportNodeDetailsCsv,
  exportNodeDetailsJson,
  exportNodeDetailsMarkdown,
} from './exportNodeDetails'

const { buildExportData, slugForType } = __testing

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeNode(
  type: string,
  id: string,
  properties: Record<string, unknown> = {},
  name?: string
): GraphNode {
  return { id, name: name ?? id, type, properties }
}

function makeRow(node: GraphNode, inCount = 0, outCount = 0): TableRow {
  return {
    node,
    connectionsIn: Array.from({ length: inCount }, (_, i) => ({
      nodeId: `in-${i}`,
      nodeName: `in-${i}`,
      nodeType: 'X',
      relationType: 'r',
    })),
    connectionsOut: Array.from({ length: outCount }, (_, i) => ({
      nodeId: `out-${i}`,
      nodeName: `out-${i}`,
      nodeType: 'X',
      relationType: 'r',
    })),
    getLevel2: () => [],
    getLevel3: () => [],
  }
}

// ---------------------------------------------------------------------------
// slugForType
// ---------------------------------------------------------------------------

describe('slugForType', () => {
  test('lowercases simple type', () => {
    expect(slugForType('Domain')).toBe('domain')
  })
  test('replaces non-alphanumeric chars with dashes', () => {
    expect(slugForType('Chain Step')).toBe('chain-step')
    expect(slugForType('Github::Repo')).toBe('github-repo')
  })
  test('falls back to "nodes" for empty/all-symbols input', () => {
    expect(slugForType('')).toBe('nodes')
    expect(slugForType('!!!')).toBe('nodes')
  })
})

// ---------------------------------------------------------------------------
// buildExportData
// ---------------------------------------------------------------------------

describe('buildExportData', () => {
  test('headers include Name + visible dynamic keys + In + Out (when both visible)', () => {
    const r = makeRow(makeNode('Domain', 'd1', { registrar: 'GoDaddy', country: 'US' }), 1, 2)
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['country', 'registrar'],
      showIn: true,
      showOut: true,
    })
    expect(built.headers).toEqual(['Name', 'country', 'registrar', 'In', 'Out'])
    expect(built.rows[0]).toEqual({
      Name: 'd1',
      country: 'US',
      registrar: 'GoDaddy',
      In: 1,
      Out: 2,
    })
  })

  test('omits hidden dynamic columns', () => {
    const r = makeRow(makeNode('Domain', 'd1', { registrar: 'GoDaddy', country: 'US', city: 'NYC' }))
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['country'], // city + registrar hidden
      showIn: true,
      showOut: true,
    })
    expect(built.headers).toEqual(['Name', 'country', 'In', 'Out'])
    expect(built.rows[0]).toEqual({ Name: 'd1', country: 'US', In: 0, Out: 0 })
  })

  test('omits In column when showIn=false', () => {
    const r = makeRow(makeNode('Domain', 'd1'), 5)
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: [],
      showIn: false,
      showOut: true,
    })
    expect(built.headers).toEqual(['Name', 'Out'])
    expect(built.rows[0]).not.toHaveProperty('In')
  })

  test('omits Out column when showOut=false', () => {
    const r = makeRow(makeNode('Domain', 'd1'), 0, 5)
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: [],
      showIn: true,
      showOut: false,
    })
    expect(built.headers).toEqual(['Name', 'In'])
    expect(built.rows[0]).not.toHaveProperty('Out')
  })

  test('Name column is always present even when no dynamic keys + In + Out hidden', () => {
    const r = makeRow(makeNode('X', 'only-name'))
    const built = buildExportData({
      nodeType: 'X',
      rows: [r],
      visibleDynamicKeys: [],
      showIn: false,
      showOut: false,
    })
    expect(built.headers).toEqual(['Name'])
    expect(built.rows[0]).toEqual({ Name: 'only-name' })
  })

  test('handles empty rows (e.g. filter excluded everything)', () => {
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [],
      visibleDynamicKeys: ['country'],
      showIn: true,
      showOut: true,
    })
    expect(built.headers).toEqual(['Name', 'country', 'In', 'Out'])
    expect(built.rows).toEqual([])
  })

  test('handles missing properties gracefully (cell is undefined)', () => {
    // d2 lacks "registrar" — common when a property exists on some rows of a type but not all
    const r1 = makeRow(makeNode('Domain', 'd1', { registrar: 'GoDaddy' }))
    const r2 = makeRow(makeNode('Domain', 'd2', {}))
    const built = buildExportData({
      nodeType: 'Domain',
      rows: [r1, r2],
      visibleDynamicKeys: ['registrar'],
      showIn: false,
      showOut: false,
    })
    expect(built.rows[0]).toEqual({ Name: 'd1', registrar: 'GoDaddy' })
    expect(built.rows[1]).toEqual({ Name: 'd2', registrar: undefined })
  })

  test('preserves row order (no implicit sort)', () => {
    const rows = [
      makeRow(makeNode('X', 'z')),
      makeRow(makeNode('X', 'a')),
      makeRow(makeNode('X', 'm')),
    ]
    const built = buildExportData({
      nodeType: 'X',
      rows,
      visibleDynamicKeys: [],
      showIn: false,
      showOut: false,
    })
    expect(built.rows.map(r => r.Name)).toEqual(['z', 'a', 'm'])
  })
})

// ---------------------------------------------------------------------------
// JSON / Markdown export — exercise downloadBlob path
// ---------------------------------------------------------------------------

describe('exportNodeDetailsJson / Markdown', () => {
  // Per-test capture: blob + filename pairs, captured synchronously at click time
  // so revokeObjectURL (which downloadBlob calls right after click) doesn't lose them.
  let blobsByHref: Map<string, Blob>
  let filenamesByHref: Map<string, string>
  let originalClick: () => void
  let originalCreate: typeof URL.createObjectURL
  let originalRevoke: typeof URL.revokeObjectURL

  beforeEach(() => {
    blobsByHref = new Map()
    filenamesByHref = new Map()
    let counter = 0

    originalCreate = globalThis.URL.createObjectURL
    originalRevoke = globalThis.URL.revokeObjectURL
    originalClick = HTMLAnchorElement.prototype.click

    globalThis.URL.createObjectURL = ((blob: Blob) => {
      const href = `blob:test-${counter++}`
      blobsByHref.set(href, blob)
      return href
    }) as typeof URL.createObjectURL

    // No-op revoke so the blob reference stays alive until we read it post-test.
    globalThis.URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL

    // Synchronously record the click target's href + download attribute.
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      filenamesByHref.set(this.href, this.download)
    }
  })

  afterEach(() => {
    globalThis.URL.createObjectURL = originalCreate
    globalThis.URL.revokeObjectURL = originalRevoke
    HTMLAnchorElement.prototype.click = originalClick
  })

  async function getDownloads(): Promise<{ content: string; filename: string; mimeType: string }[]> {
    const out: { content: string; filename: string; mimeType: string }[] = []
    for (const [href, blob] of blobsByHref) {
      const filename = filenamesByHref.get(href)
      if (!filename) continue // anchor was created but never clicked
      const content = await blob.text()
      out.push({ content, filename, mimeType: blob.type })
    }
    return out
  }

  test('exportNodeDetailsJson emits a JSON file with ordered columns + rows', async () => {
    const r = makeRow(makeNode('Domain', 'example.com', { registrar: 'GoDaddy' }), 2, 3)
    await exportNodeDetailsJson({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['registrar'],
      showIn: true,
      showOut: true,
    })

    const downloads = await getDownloads()
    expect(downloads).toHaveLength(1)
    expect(downloads[0].filename).toMatch(/^redamon-domain-\d{4}-\d{2}-\d{2}.*\.json$/)
    expect(downloads[0].mimeType).toBe('application/json;charset=utf-8')
    const parsed = JSON.parse(downloads[0].content)
    expect(parsed.nodeType).toBe('Domain')
    expect(parsed.columns).toEqual(['Name', 'registrar', 'In', 'Out'])
    expect(parsed.rows).toEqual([{ Name: 'example.com', registrar: 'GoDaddy', In: 2, Out: 3 }])
    expect(parsed.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  test('exportNodeDetailsMarkdown emits a markdown table with header + separator + rows', async () => {
    const r1 = makeRow(makeNode('Domain', 'a.com', { registrar: 'GoDaddy' }))
    const r2 = makeRow(makeNode('Domain', 'b|c.com', { registrar: 'Name|cheap' })) // pipe must be escaped
    await exportNodeDetailsMarkdown({
      nodeType: 'Domain',
      rows: [r1, r2],
      visibleDynamicKeys: ['registrar'],
      showIn: false,
      showOut: false,
    })

    const downloads = await getDownloads()
    expect(downloads).toHaveLength(1)
    expect(downloads[0].filename).toMatch(/^redamon-domain-\d{4}-\d{2}-\d{2}.*\.md$/)
    expect(downloads[0].mimeType).toBe('text/markdown;charset=utf-8')
    const md = downloads[0].content
    expect(md).toContain('# Domain - Node Inspector Export')
    expect(md).toContain('Rows: 2')
    expect(md).toContain('| Name | registrar |')
    expect(md).toContain('| --- | --- |')
    expect(md).toContain('| a.com | GoDaddy |')
    // Pipes escaped in cell
    expect(md).toContain('| b\\|c.com | Name\\|cheap |')
  })

  test('JSON export converts undefined cells to null (valid JSON)', async () => {
    const r = makeRow(makeNode('Domain', 'd1', {}))
    await exportNodeDetailsJson({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['missing_prop'],
      showIn: false,
      showOut: false,
    })
    const downloads = await getDownloads()
    const parsed = JSON.parse(downloads[0].content)
    expect(parsed.rows[0]).toEqual({ Name: 'd1', missing_prop: null })
  })
})

// ---------------------------------------------------------------------------
// CSV export — relies on the same mocked URL.createObjectURL anchor pair
// installed in the JSON/Markdown describe block above. Re-installed here so
// these tests can run in isolation (vitest --testNamePattern Csv).
// ---------------------------------------------------------------------------

describe('exportNodeDetailsCsv', () => {
  let blobsByHref: Map<string, Blob>
  let filenamesByHref: Map<string, string>
  let originalClick: () => void
  let originalCreate: typeof URL.createObjectURL
  let originalRevoke: typeof URL.revokeObjectURL

  beforeEach(() => {
    blobsByHref = new Map()
    filenamesByHref = new Map()
    let counter = 0
    originalCreate = globalThis.URL.createObjectURL
    originalRevoke = globalThis.URL.revokeObjectURL
    originalClick = HTMLAnchorElement.prototype.click
    globalThis.URL.createObjectURL = ((blob: Blob) => {
      const href = `blob:test-${counter++}`
      blobsByHref.set(href, blob)
      return href
    }) as typeof URL.createObjectURL
    globalThis.URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      filenamesByHref.set(this.href, this.download)
    }
  })

  afterEach(() => {
    globalThis.URL.createObjectURL = originalCreate
    globalThis.URL.revokeObjectURL = originalRevoke
    HTMLAnchorElement.prototype.click = originalClick
  })

  async function getDownload() {
    for (const [href, blob] of blobsByHref) {
      const filename = filenamesByHref.get(href)
      if (!filename) continue
      return { filename, content: await blob.text(), mimeType: blob.type }
    }
    throw new Error('no download captured')
  }

  test('emits a CSV file with header + one row per node', async () => {
    const r = makeRow(makeNode('Domain', 'example.com', { registrar: 'GoDaddy' }), 1, 0)
    await exportNodeDetailsCsv({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['registrar'],
      showIn: true,
      showOut: false,
    })
    const dl = await getDownload()
    expect(dl.filename).toMatch(/^redamon-domain-\d{4}-\d{2}-\d{2}.*\.csv$/)
    expect(dl.mimeType).toBe('text/csv;charset=utf-8')
    // Strip BOM, split CRLF
    const lines = dl.content.replace(/^\uFEFF/, '').trimEnd().split('\r\n')
    expect(lines[0]).toBe('Name,registrar,In')
    expect(lines[1]).toBe('example.com,GoDaddy,1')
  })

  test('quotes cells containing commas, quotes, and newlines', async () => {
    const r = makeRow(
      makeNode('Domain', 'tricky.com', {
        note: 'a, b "c"\nnewline',
      }),
    )
    await exportNodeDetailsCsv({
      nodeType: 'Domain',
      rows: [r],
      visibleDynamicKeys: ['note'],
      showIn: false,
      showOut: false,
    })
    const dl = await getDownload()
    const body = dl.content.replace(/^\uFEFF/, '').trimEnd()
    // The note cell must be wrapped in quotes and have its " doubled
    expect(body).toContain('"a, b ""c""\nnewline"')
  })
})
