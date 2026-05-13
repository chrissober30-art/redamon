import type { TableRow } from '../../hooks/useTableData'
import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from '../../utils/exportHelpers'

export interface NodeDetailsExportInput {
  nodeType: string
  rows: TableRow[]
  /** Sorted list of visible dynamic property keys (after applying user hide prefs). */
  visibleDynamicKeys: string[]
  /** Whether the In count column is currently visible. */
  showIn: boolean
  /** Whether the Out count column is currently visible. */
  showOut: boolean
}

interface BuiltExport {
  headers: string[]
  rows: Record<string, unknown>[]
}

function slugForType(nodeType: string): string {
  return nodeType.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'nodes'
}

function buildHeaders(input: NodeDetailsExportInput): string[] {
  const headers: string[] = ['Name', ...input.visibleDynamicKeys]
  if (input.showIn) headers.push('In')
  if (input.showOut) headers.push('Out')
  return headers
}

function buildOneRow(row: TableRow, input: NodeDetailsExportInput): Record<string, unknown> {
  const out: Record<string, unknown> = { Name: row.node.name }
  for (const key of input.visibleDynamicKeys) {
    out[key] = row.node.properties[key]
  }
  if (input.showIn) out.In = row.connectionsIn.length
  if (input.showOut) out.Out = row.connectionsOut.length
  return out
}

function buildExportData(input: NodeDetailsExportInput): BuiltExport {
  const headers = buildHeaders(input)
  const rows = input.rows.map(row => buildOneRow(row, input))
  return { headers, rows }
}

function* lazyRows(input: NodeDetailsExportInput): Iterable<Record<string, unknown>> {
  for (const r of input.rows) yield buildOneRow(r, input)
}

/** Project a row through the headers, replacing undefined with null. */
function* projectedJsonRows(input: NodeDetailsExportInput): Iterable<Record<string, unknown>> {
  const headers = buildHeaders(input)
  for (const r of input.rows) {
    const built = buildOneRow(r, input)
    const projected: Record<string, unknown> = {}
    for (const h of headers) projected[h] = built[h] ?? null
    yield projected
  }
}

export async function exportNodeDetailsCsv(input: NodeDetailsExportInput): Promise<void> {
  const headers = buildHeaders(input)
  await downloadStreaming(
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.csv`,
    CSV_MIME,
    () => streamCsvChunks(headers, lazyRows(input)),
  )
}

export async function exportNodeDetailsJson(input: NodeDetailsExportInput): Promise<void> {
  const headers = buildHeaders(input)
  const envelopeOpen =
    `{\n` +
    `  "nodeType": ${JSON.stringify(input.nodeType)},\n` +
    `  "generatedAt": ${JSON.stringify(new Date().toISOString())},\n` +
    `  "columns": ${JSON.stringify(headers)},\n` +
    `  "rows": `
  const envelopeClose = `\n}\n`

  async function* combined(): AsyncGenerator<string> {
    yield envelopeOpen
    yield* streamJsonArrayChunks(projectedJsonRows(input), { outerIndent: 2 })
    yield envelopeClose
  }

  await downloadStreaming(
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => combined(),
  )
}

export async function exportNodeDetailsMarkdown(input: NodeDetailsExportInput): Promise<void> {
  const headers = buildHeaders(input)
  const preamble =
    `# ${input.nodeType} - Node Inspector Export\n\n` +
    `Generated: ${new Date().toISOString()}\n` +
    `Rows: ${input.rows.length}\n\n`

  async function* combined(): AsyncGenerator<string> {
    yield preamble
    yield* streamMarkdownTableChunks(
      headers,
      lazyRows(input),
      (row, h) => (row as Record<string, unknown>)[h],
    )
    yield '\n'
  }

  await downloadStreaming(
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}

// Exposed for unit tests (no DOM I/O).
export const __testing = { buildExportData, slugForType }
