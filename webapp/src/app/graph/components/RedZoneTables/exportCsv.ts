import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from '../../utils/exportHelpers'

export interface RedZoneExportColumn {
  key: string
  header: string
}

export interface RedZoneExportConfig {
  rows: object[]
  sheetName: string
  fileSlug: string
  columns: RedZoneExportColumn[]
}

function* lazyDictRows(rows: object[], columns: RedZoneExportColumn[]): Iterable<Record<string, unknown>> {
  for (const row of rows) {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      out[col.header] = (row as Record<string, unknown>)[col.key]
    }
    yield out
  }
}

function* lazyDictRowsForJson(rows: object[], columns: RedZoneExportColumn[]): Iterable<Record<string, unknown>> {
  for (const row of rows) {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      const v = (row as Record<string, unknown>)[col.key]
      out[col.header] = v ?? null
    }
    yield out
  }
}

export async function exportRedZoneCsv<T extends object>(
  rows: T[],
  _sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  const headers = columns.map(c => c.header)
  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.csv`,
    CSV_MIME,
    () => streamCsvChunks(headers, lazyDictRows(rows, columns)),
  )
}

export async function exportRedZoneJson<T extends object>(
  rows: T[],
  _sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => streamJsonArrayChunks(lazyDictRowsForJson(rows, columns)),
  )
}

export async function exportRedZoneMarkdown<T extends object>(
  rows: T[],
  sheetName: string,
  columns: RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  const headers = columns.map(c => c.header)
  const preamble = `# ${sheetName}\n\nGenerated: ${new Date().toISOString()}\nRows: ${rows.length}\n\n`

  async function* combined(): AsyncGenerator<string> {
    yield preamble
    yield* streamMarkdownTableChunks(
      headers,
      rows,
      (row, h) => {
        const col = columns.find(c => c.header === h)
        return col ? (row as Record<string, unknown>)[col.key] : undefined
      },
    )
    yield '\n'
  }

  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}

export async function runRedZoneExport(
  format: 'csv' | 'json' | 'md',
  config: RedZoneExportConfig,
) {
  if (format === 'csv') return exportRedZoneCsv(config.rows, config.sheetName, config.columns, config.fileSlug)
  if (format === 'json') return exportRedZoneJson(config.rows, config.sheetName, config.columns, config.fileSlug)
  return exportRedZoneMarkdown(config.rows, config.sheetName, config.columns, config.fileSlug)
}
