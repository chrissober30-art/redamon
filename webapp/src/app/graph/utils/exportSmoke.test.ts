/**
 * End-to-end smoke tests for every export format on every page table.
 *
 * Validates:
 *   - No exceptions on representative sample data
 *   - Filename slugs and timestamp suffix are correct
 *   - Output payloads (CSV, JSON, MD) are well-formed
 *
 * Browser DOM bits (URL.createObjectURL, anchor click) are intercepted so we
 * can read the emitted Blob content back.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

import {
  exportToCsv,
  exportToJson,
  exportToMarkdown,
} from './exportCsv'
import {
  exportRedZoneCsv,
  exportRedZoneJson,
  exportRedZoneMarkdown,
} from '../components/RedZoneTables/exportCsv'
import {
  exportJsReconCsv,
  exportJsReconJson,
  exportJsReconMarkdown,
  type JsReconData,
} from '../components/JsReconTable/JsReconTable'
import type { TableRow } from '../hooks/useTableData'

// ============================================================
// DOM interception helpers
// ============================================================

interface CapturedDownload {
  filename: string
  text: string
  mimeType: string
}

let downloads: CapturedDownload[] = []
let originalCreateObjectURL: typeof URL.createObjectURL
let originalRevokeObjectURL: typeof URL.revokeObjectURL

async function flush() {
  // anchor.click is async (await blob.text()) and our streaming exports
  // chain a handful of microtasks per chunk. Pump generously so even
  // multi-section exports settle before assertions run.
  for (let i = 0; i < 64; i++) await Promise.resolve()
}

beforeEach(() => {
  downloads = []

  const blobs = new Map<string, Blob>()
  originalCreateObjectURL = URL.createObjectURL
  originalRevokeObjectURL = URL.revokeObjectURL
  let counter = 0
  URL.createObjectURL = vi.fn((blob: Blob) => {
    const url = `blob:test/${++counter}`
    blobs.set(url, blob)
    return url
  })
  URL.revokeObjectURL = vi.fn()

  const originalCreate = document.createElement.bind(document)
  vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
    const el = originalCreate(tag)
    if (tag.toLowerCase() === 'a') {
      const a = el as HTMLAnchorElement
      a.click = async () => {
        const blob = blobs.get(a.href)
        if (blob) {
          const text = await blob.text()
          downloads.push({ filename: a.download, text, mimeType: blob.type })
        }
      }
    }
    return el
  }) as typeof document.createElement)
})

afterEach(() => {
  URL.createObjectURL = originalCreateObjectURL
  URL.revokeObjectURL = originalRevokeObjectURL
  vi.restoreAllMocks()
})

const TS_SUFFIX_RE = /-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.(csv|json|md)$/

// ============================================================
// Tiny CSV parser (handles RFC 4180 quoting) -- avoids pulling
// in a full dep just for the smoke check.
// ============================================================

function parseCsv(text: string): string[][] {
  const stripped = text.replace(/^\uFEFF/, '')
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQuotes = false
  for (let i = 0; i < stripped.length; i++) {
    const ch = stripped[i]
    if (inQuotes) {
      if (ch === '"') {
        if (stripped[i + 1] === '"') { cell += '"'; i++ } else { inQuotes = false }
      } else {
        cell += ch
      }
    } else {
      if (ch === '"') inQuotes = true
      else if (ch === ',') { row.push(cell); cell = '' }
      else if (ch === '\r') { /* skip */ }
      else if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = '' }
      else cell += ch
    }
  }
  if (cell.length || row.length) { row.push(cell); rows.push(row) }
  return rows
}

// ============================================================
// Sample fixtures
// ============================================================

function makeTableRows(): TableRow[] {
  return [
    {
      node: {
        id: 'sub-1',
        type: 'Subdomain',
        name: 'admin.example.com',
        properties: {
          subdomain: 'admin.example.com',
          tags: ['live', 'auth'],
          banner: 'HTTP/1.1 200 OK\u0000\u0007 evil-binary',
          response_size: 12345,
          is_alive: true,
          long_text: 'X'.repeat(40000),
          project_id: 'should-be-skipped',
          user_id: 'should-be-skipped',
        },
      } as any,
      connectionsIn: [
        { nodeId: 'd-1', nodeName: 'example.com', nodeType: 'Domain', relationType: 'PART_OF' },
      ],
      connectionsOut: [
        { nodeId: 'ep-1', nodeName: '/login', nodeType: 'Endpoint', relationType: 'HAS_ENDPOINT' },
      ],
      getLevel2: () => [
        { nodeId: 'tld-1', nodeName: 'example', nodeType: 'TLD', relationType: '2 hops' },
      ],
      getLevel3: () => [],
    },
    {
      node: {
        id: 'ep-1',
        type: 'Endpoint',
        name: '/login',
        properties: { method: 'POST', path: '/login', is_alive: false },
      } as any,
      connectionsIn: [],
      connectionsOut: [],
      getLevel2: () => [],
      getLevel3: () => [],
    },
  ]
}

function makeRedZoneRows() {
  return [
    {
      severity: 'critical',
      hostname: 'admin.example.com',
      port: 443,
      isCdn: true,
      tags: ['production', 'auth'],
      cveCount: 12,
      lastSeen: null,
      payload: { method: 'GET', path: '/admin' },
      garbled: 'header\u0000binary\u0007junk',
    },
    {
      severity: 'low',
      hostname: 'cdn.example.com',
      port: 80,
      isCdn: false,
      tags: [],
      cveCount: 0,
      lastSeen: '2026-04-29',
      payload: null,
      garbled: 'normal text',
    },
  ]
}

const RED_ZONE_COLUMNS = [
  { key: 'severity', header: 'Severity' },
  { key: 'hostname', header: 'Hostname' },
  { key: 'port', header: 'Port' },
  { key: 'isCdn', header: 'CDN' },
  { key: 'tags', header: 'Tags' },
  { key: 'cveCount', header: 'CVEs' },
  { key: 'lastSeen', header: 'Last Seen' },
  { key: 'payload', header: 'Payload' },
  { key: 'garbled', header: 'Garbled' },
]

function makeJsReconData(): JsReconData {
  return {
    scan_metadata: { js_files_analyzed: 3 },
    secrets: [
      {
        severity: 'critical',
        name: 'AWS Access Key',
        redacted_value: 'AKIA…X',
        matched_text: 'AKIAFAKE\u0001binary',
        category: 'cloud',
        source_url: 'https://example.com/app.js',
        line_number: 42,
        context: 'var k = "AKIA…X"',
        detection_method: 'regex',
        validation: { status: 'validated' },
        confidence: 'high',
        validator_ref: 'aws',
      },
    ],
    endpoints: [
      {
        severity: 'info',
        method: 'POST',
        path: '/api/v1/users',
        full_url: 'https://api.example.com/api/v1/users',
        type: 'rest',
        category: 'user',
        base_url: 'https://api.example.com',
        source_js: 'https://example.com/app.js',
        parameters: ['id', 'name'],
        line_number: 156,
      },
    ],
    discovered_subdomains: ['admin.example.com', 'api.example.com'],
    external_domains: [{ domain: 'cdn.example.net', times_seen: 5 }],
  }
}

// ============================================================
// All-Nodes (page-level)
// ============================================================

describe('All-Nodes table exports', () => {
  test('CSV: produces a parseable file, sanitizes binary chars, skips internal fields', async () => {
    const rows = makeTableRows()
    exportToCsv(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)
    expect(dl.mimeType).toBe('text/csv;charset=utf-8')

    const grid = parseCsv(dl.text)
    const headers = grid[0]
    expect(headers).toContain('Type')
    expect(headers).toContain('Name')
    // Internal fields are filtered out at row-build time
    expect(headers).not.toContain('project_id')
    expect(headers).not.toContain('user_id')

    // Row 1 = first node = admin.example.com
    const dataRows = grid.slice(1).filter(r => r.length > 1)
    expect(dataRows).toHaveLength(2)
    const nameIdx = headers.indexOf('Name')
    const typeIdx = headers.indexOf('Type')
    expect(dataRows[0][typeIdx]).toBe('Subdomain')
    expect(dataRows[0][nameIdx]).toBe('admin.example.com')

    // banner had \u0000 and \u0007 -- must be stripped
    const bannerIdx = headers.indexOf('banner')
    expect(dataRows[0][bannerIdx]).not.toMatch(/[\u0000\u0007]/)
    // Long text passed through (CSV has no XLSX-style 32767 cap)
    const longIdx = headers.indexOf('long_text')
    expect(dataRows[0][longIdx].length).toBe(40000)
  })

  test('JSON: produces parseable JSON with all expected fields', async () => {
    const rows = makeTableRows()
    exportToJson(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Type).toBe('Subdomain')
    expect(data[0].Name).toBe('admin.example.com')
    expect(data[0]['Connections In']).toBe(1)
  })

  test('Markdown: produces a valid GFM table', async () => {
    const rows = makeTableRows()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# Nodes Export')
    expect(md).toContain('| Type |')
    expect(md).toMatch(/\| --- \|/)
    expect(md).toContain('admin.example.com')
    expect(md).toContain('Subdomain')
    const lines = md.split('\n')
    const dataLines = lines.filter(l => l.startsWith('| ') && !l.includes(' --- '))
    const pipeCounts = dataLines.map(l => (l.match(/\|/g) || []).length)
    expect(new Set(pipeCounts).size).toBe(1)
  })
})

// ============================================================
// Red Zone tables (e.g. Blast Radius / Secrets / etc.)
// ============================================================

describe('Red Zone table exports', () => {
  test('CSV: produces a parseable file with the configured headers', async () => {
    exportRedZoneCsv(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)

    const grid = parseCsv(dl.text)
    expect(grid[0]).toEqual([
      'Severity', 'Hostname', 'Port', 'CDN', 'Tags', 'CVEs', 'Last Seen', 'Payload', 'Garbled',
    ])
    const data = grid.slice(1).filter(r => r.length > 1)
    expect(data).toHaveLength(2)
    expect(data[0][0]).toBe('critical')
    expect(data[0][1]).toBe('admin.example.com')
    expect(data[0][2]).toBe('443')
    expect(data[0][3]).toBe('true')
    // Arrays joined
    expect(data[0][4]).toBe('production, auth')
    // Object stringified
    expect(data[0][7]).toContain('"method":"GET"')
    // Binary chars stripped
    expect(data[0][8]).not.toMatch(/[\u0000\u0007]/)
    // Null cell empty
    expect(data[0][6]).toBe('')
  })

  test('JSON: produces parseable JSON, keeps native objects/arrays', async () => {
    exportRedZoneJson(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Severity).toBe('critical')
    expect(typeof data[0].Port).toBe('number')
    expect(typeof data[0].CDN).toBe('boolean')
    expect(Array.isArray(data[0].Tags)).toBe(true)
    expect(data[0].Payload.method).toBe('GET')
    expect(data[0]['Last Seen']).toBeNull()
  })

  test('Markdown: produces a GFM table with proper escaping', async () => {
    exportRedZoneMarkdown(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# Blast-Radius')
    expect(md).toMatch(/\| Severity \| Hostname \|/)
    expect(md).toContain('admin.example.com')
    expect(md).toContain('production, auth')
  })
})

// ============================================================
// JS Recon (multi-section)
// ============================================================

describe('JS Recon table exports', () => {
  test('CSV: writes one section per non-empty bucket separated by section markers', async () => {
    await exportJsReconCsv(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)

    const text = dl.text
    expect(text).toContain('# Section: Secrets')
    expect(text).toContain('# Section: Endpoints')
    expect(text).toContain('# Section: Subdomains')
    expect(text).toContain('# Section: External Domains')
    // Sections that are empty (e.g. dependencies, source maps) must be absent
    expect(text).not.toContain('# Section: Dependencies')
    expect(text).not.toContain('# Section: Source Maps')

    // Drill into the Secrets section: the row after its header should contain the secret name
    expect(text).toContain('AWS Access Key')
    // \u0001 in matched_text must be stripped
    expect(text).not.toMatch(/[\u0000-\u0008]/)
  })

  test('JSON: produces a parseable object keyed by section name', async () => {
    await exportJsReconJson(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data['Secrets'])).toBe(true)
    expect(data['Secrets']).toHaveLength(1)
    expect(data['Secrets'][0].name).toBe('AWS Access Key')
    expect(data['Secrets'][0]['validation.status']).toBe('validated')
    expect(data['Dependencies']).toBeUndefined()
    expect(data['Source Maps']).toBeUndefined()
    expect(data['Subdomains']).toEqual([
      { subdomain: 'admin.example.com' },
      { subdomain: 'api.example.com' },
    ])
  })

  test('Markdown: produces a multi-section markdown doc', async () => {
    await exportJsReconMarkdown(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# JS Recon Findings')
    expect(md).toContain('## Secrets (1)')
    expect(md).toContain('## Endpoints (1)')
    expect(md).toContain('## Subdomains (2)')
    expect(md).toContain('## External Domains (1)')
    expect(md).not.toContain('## Dependencies')
    expect(md).not.toContain('## Source Maps')
    expect(md).toContain('AWS Access Key')
  })
})

// ============================================================
// Sequential exports
// ============================================================

describe('Multiple sequential exports', () => {
  test('Each call produces an independent download with the right extension', async () => {
    const rows = makeTableRows()
    exportToCsv(rows)
    await flush()
    exportToJson(rows)
    await flush()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(3)
    expect(downloads[0].filename).toMatch(/\.csv$/)
    expect(downloads[1].filename).toMatch(/\.json$/)
    expect(downloads[2].filename).toMatch(/\.md$/)
  })
})

// ============================================================
// Large-dataset streaming
// ============================================================
//
// Regression guard for the >2000-row browser-crash bug: build a 5000-row
// dataset and assert that all three formats stream to completion without
// throwing, produce well-formed output, and preserve every row.

describe('Large-dataset streaming exports', () => {
  function makeLargeRows(n: number): TableRow[] {
    const rows: TableRow[] = []
    for (let i = 0; i < n; i++) {
      rows.push({
        node: {
          id: `n-${i}`,
          type: 'Subdomain',
          name: `host-${i}.example.com`,
          properties: {
            idx: i,
            tag: i % 7 === 0 ? 'live' : 'unknown',
            payload: { i, k: `v-${i}` },
          },
        } as any,
        connectionsIn: [],
        connectionsOut: [],
        getLevel2: () => [],
        getLevel3: () => [],
      })
    }
    return rows
  }

  test('CSV streams 5000 rows without crashing and is parseable end-to-end', async () => {
    const rows = makeLargeRows(5000)
    await exportToCsv(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const grid = parseCsv(downloads[0].text)
    // header + 5000 data rows
    const dataRows = grid.slice(1).filter(r => r.length > 1)
    expect(dataRows).toHaveLength(5000)
    const nameIdx = grid[0].indexOf('Name')
    expect(dataRows[0][nameIdx]).toBe('host-0.example.com')
    expect(dataRows[4999][nameIdx]).toBe('host-4999.example.com')
  })

  test('JSON streams 5000 rows and round-trips through JSON.parse', async () => {
    const rows = makeLargeRows(5000)
    await exportToJson(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const data = JSON.parse(downloads[0].text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(5000)
    expect(data[0].Name).toBe('host-0.example.com')
    expect(data[4999].Name).toBe('host-4999.example.com')
    // Nested objects survive per-row stringification
    expect(data[0].payload).toEqual({ i: 0, k: 'v-0' })
  })

  test('Markdown streams 5000 rows into a valid GFM table', async () => {
    const rows = makeLargeRows(5000)
    await exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const md = downloads[0].text
    const dataLines = md.split('\n').filter(l => l.startsWith('| ') && !l.includes(' --- ') && !l.startsWith('| Type |'))
    expect(dataLines.length).toBe(5000)
    expect(dataLines[0]).toContain('host-0.example.com')
    expect(dataLines[4999]).toContain('host-4999.example.com')
  })
})

describe('downloadBlob back-compat shim', () => {
  test('downloadBlob and downloadBlobParts produce identical bytes', async () => {
    const { downloadBlob, downloadBlobParts } = await import('./exportHelpers')
    downloadBlob('hello world', 'a.txt', 'text/plain')
    await flush()
    downloadBlobParts(['hello world'], 'b.txt', 'text/plain')
    await flush()
    expect(downloads).toHaveLength(2)
    expect(downloads[0].text).toBe(downloads[1].text)
    expect(downloads[0].mimeType).toBe(downloads[1].mimeType)
  })
})

// ============================================================
// Red Zone large-dataset streaming
// ============================================================

describe('Red Zone large-dataset streaming exports', () => {
  function makeManyRedZoneRows(n: number) {
    return Array.from({ length: n }, (_, i) => ({
      severity: i % 5 === 0 ? 'critical' : 'low',
      hostname: `host-${i}.example.com`,
      port: 443,
      isCdn: i % 3 === 0,
      tags: i % 7 === 0 ? ['live', 'auth'] : [],
      cveCount: i,
      lastSeen: i % 11 === 0 ? null : '2026-04-29',
      payload: { i, k: `v-${i}` },
      garbled: i === 1234 ? 'edge\u0001case\u0007chunk' : `r${i}`,
    }))
  }

  test('CSV: 5000 rows survive every chunk boundary', async () => {
    const rows = makeManyRedZoneRows(5000)
    await exportRedZoneCsv(rows, 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const grid = parseCsv(downloads[0].text)
    const data = grid.slice(1).filter(r => r.length > 1)
    expect(data).toHaveLength(5000)
    // Sentinel cell with binary chars (from row 1234) must survive sanitization
    const garbledIdx = grid[0].indexOf('Garbled')
    expect(data[1234][garbledIdx]).not.toMatch(/[\u0000-\u0008]/)
    expect(data[1234][garbledIdx]).toContain('edge')
    expect(data[4999][grid[0].indexOf('Hostname')]).toBe('host-4999.example.com')
  })

  test('JSON: 5000 rows produce valid pretty-printed JSON with native types preserved', async () => {
    const rows = makeManyRedZoneRows(5000)
    await exportRedZoneJson(rows, 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const data = JSON.parse(downloads[0].text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(5000)
    expect(typeof data[0].Port).toBe('number')
    expect(typeof data[100].CDN).toBe('boolean')
    expect(Array.isArray(data[7].Tags)).toBe(true)
    expect(data[11]['Last Seen']).toBeNull()
    expect(data[4999].Hostname).toBe('host-4999.example.com')
  })

  test('Markdown: 5000 rows produce a GFM table with one data line per row', async () => {
    const rows = makeManyRedZoneRows(5000)
    await exportRedZoneMarkdown(rows, 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const md = downloads[0].text
    const dataLines = md
      .split('\n')
      .filter(l => l.startsWith('| ') && !l.includes(' --- ') && !l.startsWith('| Severity '))
    expect(dataLines).toHaveLength(5000)
    expect(dataLines[0]).toContain('host-0.example.com')
    expect(dataLines[4999]).toContain('host-4999.example.com')
  })
})

// ============================================================
// Node Details envelope (large) -- exercises the JSON envelope wrap
// around streamJsonArray with outerIndent
// ============================================================

describe('Node Details envelope under load', () => {
  test('JSON envelope { nodeType, generatedAt, columns, rows } survives 5000 rows', async () => {
    const { exportNodeDetailsJson } = await import(
      '../components/NodeDetailsTable/exportNodeDetails'
    )
    const rows: TableRow[] = Array.from({ length: 5000 }, (_, i) => ({
      node: {
        id: `d-${i}`,
        type: 'Domain',
        name: `dom-${i}.example.com`,
        properties: {
          registrar: i % 2 === 0 ? 'GoDaddy' : 'Cloudflare',
          country: 'US',
          ttl: 300 + (i % 1000),
        },
      } as any,
      connectionsIn: Array.from({ length: i % 4 }, (_, j) => ({
        nodeId: `c-${j}`, nodeName: `c-${j}`, nodeType: 'X', relationType: 'r',
      })),
      connectionsOut: [],
      getLevel2: () => [],
      getLevel3: () => [],
    }))
    await exportNodeDetailsJson({
      nodeType: 'Domain',
      rows,
      visibleDynamicKeys: ['registrar', 'country', 'ttl'],
      showIn: true,
      showOut: false,
    })
    await flush()
    expect(downloads).toHaveLength(1)
    const data = JSON.parse(downloads[0].text)
    expect(data.nodeType).toBe('Domain')
    expect(data.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(data.columns).toEqual(['Name', 'registrar', 'country', 'ttl', 'In'])
    expect(data.rows).toHaveLength(5000)
    expect(data.rows[0]).toEqual({
      Name: 'dom-0.example.com',
      registrar: 'GoDaddy',
      country: 'US',
      ttl: 300,
      In: 0,
    })
    expect(data.rows[4999].Name).toBe('dom-4999.example.com')
    expect(data.rows[4999].In).toBe(3) // 4999 % 4
  })
})

// ============================================================
// JS Recon multi-chunk per section + section-ordering preservation
// ============================================================

describe('JS Recon under load and ordering', () => {
  function makeBigSecrets(n: number) {
    return Array.from({ length: n }, (_, i) => ({
      severity: i % 4 === 0 ? 'critical' : 'low',
      name: `Secret ${i}`,
      redacted_value: `R${i}`,
      matched_text: i === 777 ? 'has\u0001binary' : `m${i}`,
      category: 'cloud',
      source_url: `https://example.com/${i}.js`,
      line_number: i,
      context: `ctx-${i}`,
      detection_method: 'regex',
      validation: { status: 'unvalidated' },
      confidence: 'high',
      validator_ref: 'aws',
    }))
  }

  test('CSV: large Secrets section streams across many chunks; binary chars survive sanitization', async () => {
    const data: JsReconData = {
      secrets: makeBigSecrets(2000),
      endpoints: [{ severity: 'info', method: 'GET', path: '/x', full_url: 'https://x', type: 'rest', category: 'x', base_url: 'https://x', source_js: 'a.js', parameters: [], line_number: 1 }],
      discovered_subdomains: ['x.example.com'],
    }
    await exportJsReconCsv(data)
    await flush()
    expect(downloads).toHaveLength(1)
    const text = downloads[0].text
    expect(text).toContain('# Section: Secrets')
    expect(text).toContain('# Section: Endpoints')
    expect(text).toContain('# Section: Subdomains')
    expect(text).not.toMatch(/[\u0000-\u0008]/)
    // Section integrity: the marker should appear ONCE per non-empty section
    expect((text.match(/# Section: Secrets/g) || []).length).toBe(1)
    expect((text.match(/# Section: Endpoints/g) || []).length).toBe(1)
    // The Secrets section should have all 2000 rows (search for last sentinel)
    expect(text).toContain('Secret 1999')
    expect(text).toContain('Secret 0')
  })

  test('JSON: large multi-section payload is parseable and preserves section order', async () => {
    const data: JsReconData = {
      secrets: makeBigSecrets(1500),
      endpoints: [
        { severity: 'info', method: 'GET', path: '/a', full_url: 'https://a', type: 'rest', category: 'a', base_url: 'https://a', source_js: 'a.js', parameters: [], line_number: 1 },
      ],
      discovered_subdomains: ['admin.example.com', 'api.example.com'],
      external_domains: [{ domain: 'cdn.example.net', times_seen: 10 }],
    }
    await exportJsReconJson(data)
    await flush()
    const parsed = JSON.parse(downloads[0].text)
    // Order of keys must follow buildJsReconSheets order: Secrets, Endpoints, ..., Subdomains, External Domains
    const keys = Object.keys(parsed)
    expect(keys).toEqual(['Secrets', 'Endpoints', 'Subdomains', 'External Domains'])
    expect(parsed.Secrets).toHaveLength(1500)
    expect(parsed.Secrets[0].name).toBe('Secret 0')
    expect(parsed.Secrets[1499].name).toBe('Secret 1499')
    expect(parsed.Subdomains).toEqual([
      { subdomain: 'admin.example.com' },
      { subdomain: 'api.example.com' },
    ])
  })

  test('JSON: empty data produces "{}" not malformed JSON', async () => {
    await exportJsReconJson({})
    await flush()
    const parsed = JSON.parse(downloads[0].text)
    expect(parsed).toEqual({})
  })

  test('Markdown: section count matches non-empty sheet count', async () => {
    const data: JsReconData = {
      secrets: makeBigSecrets(1100),
      endpoints: [],
      discovered_subdomains: ['admin.example.com'],
    }
    await exportJsReconMarkdown(data)
    await flush()
    const md = downloads[0].text
    expect(md).toContain('## Secrets (1100)')
    expect(md).toContain('## Subdomains (1)')
    expect(md).not.toContain('## Endpoints')
    // 1100 data lines for the Secrets table (header / sep are excluded)
    const secretsSection = md.split('## Secrets (1100)')[1].split('## ')[0]
    const dataLines = secretsSection
      .split('\n')
      .filter(l => l.startsWith('| ') && !l.includes(' --- ') && !l.startsWith('| severity '))
    expect(dataLines).toHaveLength(1100)
  })
})
