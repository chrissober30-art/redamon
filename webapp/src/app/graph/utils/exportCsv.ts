import type { TableRow } from '../hooks/useTableData'
import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from './exportHelpers'

interface NodeExportRow {
  Type: string
  Name: string
  ID: string
  'Connections In': number
  'Connections Out': number
  'Connections In Detail': string
  'Connections Out Detail': string
  'Level 2': number
  'Level 2 Detail': string
  'Level 3': number
  'Level 3 Detail': string
  [extra: string]: unknown
}

const FIXED_HEADERS: (keyof NodeExportRow)[] = [
  'Type',
  'Name',
  'ID',
  'Connections In',
  'Connections Out',
  'Connections In Detail',
  'Connections Out Detail',
  'Level 2',
  'Level 2 Detail',
  'Level 3',
  'Level 3 Detail',
]

function buildOneRow(row: TableRow): NodeExportRow {
  const base: NodeExportRow = {
    Type: row.node.type,
    Name: row.node.name,
    ID: row.node.id,
    'Connections In': row.connectionsIn.length,
    'Connections Out': row.connectionsOut.length,
    'Connections In Detail': row.connectionsIn
      .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
      .join('; '),
    'Connections Out Detail': row.connectionsOut
      .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
      .join('; '),
    'Level 2': row.getLevel2().length,
    'Level 2 Detail': row.getLevel2()
      .map(c => `${c.nodeType}: ${c.nodeName}`)
      .join('; '),
    'Level 3': row.getLevel3().length,
    'Level 3 Detail': row.getLevel3()
      .map(c => `${c.nodeType}: ${c.nodeName}`)
      .join('; '),
  }
  for (const [key, value] of Object.entries(row.node.properties)) {
    if (key === 'project_id' || key === 'user_id') continue
    base[key] = value
  }
  return base
}

/**
 * Discover the dynamic-property header set without materializing the
 * full export array. Touches each row's `properties` object only.
 */
function collectDynamicHeaders(rows: TableRow[]): string[] {
  const dynamic = new Set<string>()
  for (const r of rows) {
    for (const k of Object.keys(r.node.properties)) {
      if (k === 'project_id' || k === 'user_id') continue
      dynamic.add(k)
    }
  }
  return [...(FIXED_HEADERS as string[]), ...Array.from(dynamic).sort()]
}

/** Lazy iterator: builds one export row at a time, never the full array. */
function* lazyExportRows(rows: TableRow[]): Iterable<NodeExportRow> {
  for (const row of rows) yield buildOneRow(row)
}

export async function exportToCsv(rows: TableRow[], filename?: string): Promise<void> {
  const headers = collectDynamicHeaders(rows)
  const slug = filename || 'redamon-data'
  await downloadStreaming(
    `${slug}-${timestampSlug()}.csv`,
    CSV_MIME,
    () => streamCsvChunks(headers, lazyExportRows(rows) as Iterable<Record<string, unknown>>),
  )
}

export async function exportToJson(rows: TableRow[], filename?: string): Promise<void> {
  const slug = filename || 'redamon-data'
  await downloadStreaming(
    `${slug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => streamJsonArrayChunks(lazyExportRows(rows)),
  )
}

export async function exportToMarkdown(rows: TableRow[], filename?: string): Promise<void> {
  const headers = collectDynamicHeaders(rows)
  const slug = filename || 'redamon-data'

  // Markdown export wraps the streaming table in a small preamble.
  const preamble = `# Nodes Export\n\nGenerated: ${new Date().toISOString()}\nRows: ${rows.length}\n\n`

  async function* combined(): AsyncGenerator<string> {
    yield preamble
    yield* streamMarkdownTableChunks(
      headers,
      lazyExportRows(rows),
      (row, h) => (row as Record<string, unknown>)[h],
    )
    yield '\n'
  }

  await downloadStreaming(
    `${slug}-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}
