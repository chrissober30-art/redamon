export function timestampSlug(): string {
  return new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
}

/**
 * Default chunk size for streaming exports. Chosen so that 2000-row exports
 * see ~4 yields and 50000-row exports see ~100 yields -- enough to keep the
 * tab responsive without paying setTimeout overhead per row.
 */
export const EXPORT_CHUNK_ROWS = 500

/** Yield to the browser event loop so Chromium's "page unresponsive" watchdog never fires. */
const yieldToUi = (): Promise<void> =>
  new Promise(resolve => setTimeout(resolve, 0))

export function downloadBlob(content: string, filename: string, mimeType: string) {
  downloadBlobParts([content], filename, mimeType)
}

/**
 * Download a Blob assembled from an array of parts -- avoids forcing the
 * browser to allocate one giant string for huge exports. The Blob constructor
 * stores parts internally without re-concatenating.
 */
export function downloadBlobParts(parts: BlobPart[], filename: string, mimeType: string) {
  const blob = new Blob(parts, { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function flattenCellValue(raw: unknown): string {
  if (raw == null) return ''
  if (Array.isArray(raw)) {
    return raw
      .map(v => (typeof v === 'object' && v !== null ? safeStringify(v) : String(v)))
      .join(', ')
  }
  if (typeof raw === 'object') return safeStringify(raw)
  return String(raw)
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function escapeMarkdownCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

const CSV_BINARY_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g

export function escapeCsvCell(value: unknown): string {
  const flat = flattenCellValue(value).replace(CSV_BINARY_CHARS, '')
  if (/[",\r\n]/.test(flat)) return `"${flat.replace(/"/g, '""')}"`
  return flat
}

/**
 * Build a CSV string for the given headers + rows.
 *
 * - RFC 4180 quoting: cells containing comma / quote / CR / LF are quoted,
 *   internal quotes are doubled.
 * - Streams row-by-row into an array then joins once -- avoids the O(n²)
 *   string concatenation that crashes browsers on huge exports.
 * - Adds a UTF-8 BOM so Excel auto-detects encoding.
 * - CRLF line endings (Excel-friendly).
 */
export function toCsv(headers: string[], rows: Array<Record<string, unknown>>): string {
  const lines: string[] = [headers.map(h => escapeCsvCell(h)).join(',')]
  for (const row of rows) {
    lines.push(headers.map(h => escapeCsvCell(row[h])).join(','))
  }
  return '\uFEFF' + lines.join('\r\n') + '\r\n'
}

export const CSV_MIME = 'text/csv;charset=utf-8'

// ============================================================
// Streaming primitives for large-dataset exports
// ============================================================
//
// Each `streamX` returns a Promise<string[]> of Blob parts. Callers concatenate
// any wrapper text (envelopes, section headers) and pass the final array to
// `downloadBlobParts`. The streaming primitives:
//
//   1. stringify each row in isolation (never the whole array at once),
//   2. group rows into chunks and yield to the event loop between chunks,
//   3. emit one BlobPart per chunk so `new Blob(parts)` references the parts
//      in place rather than allocating a single huge string.
//
// All three formats keep byte-identical output to their non-streaming cousins
// for small inputs (the smoke tests pin this), so existing fixtures stay green.

/**
 * Stream CSV body (headers + rows) as Blob parts, with UTF-8 BOM and CRLF.
 * Output format matches `toCsv` exactly.
 */
export async function streamCsv(
  headers: string[],
  rows: Array<Record<string, unknown>>,
  chunkSize: number = EXPORT_CHUNK_ROWS,
): Promise<string[]> {
  const parts: string[] = []
  parts.push('\uFEFF', headers.map(h => escapeCsvCell(h)).join(','))
  for (let i = 0; i < rows.length; i += chunkSize) {
    const slice = rows.slice(i, i + chunkSize)
    const lines = slice.map(row => headers.map(h => escapeCsvCell(row[h])).join(','))
    parts.push('\r\n' + lines.join('\r\n'))
    if (i + chunkSize < rows.length) await yieldToUi()
  }
  parts.push('\r\n')
  return parts
}

/**
 * Stream a JSON array body (`[\n  {...},\n  {...}\n]`) as Blob parts,
 * pretty-printed at 2-space indent. Each element is stringified individually
 * so the heap never holds a `JSON.stringify(allRows, null, 2)` intermediate.
 *
 * `outerIndent` shifts the entire array by N spaces -- use when nesting the
 * streamed array inside a wrapping object.
 */
export async function streamJsonArray(
  rows: unknown[],
  options: { chunkSize?: number; outerIndent?: number } = {},
): Promise<string[]> {
  const { chunkSize = EXPORT_CHUNK_ROWS, outerIndent = 0 } = options
  const pad = ' '.repeat(outerIndent)
  const innerPad = ' '.repeat(outerIndent + 2)

  const parts: string[] = []
  if (rows.length === 0) {
    parts.push('[]')
    return parts
  }
  parts.push('[\n')
  for (let i = 0; i < rows.length; i += chunkSize) {
    const slice = rows.slice(i, i + chunkSize)
    const chunkLines = slice.map((row, j) => {
      const stringified = JSON.stringify(row, null, 2)
      const indented = stringified.split('\n').map(line => innerPad + line).join('\n')
      const trailingComma = i + j === rows.length - 1 ? '' : ','
      return indented + trailingComma
    })
    parts.push(chunkLines.join('\n'))
    if (i + chunkSize < rows.length) {
      parts.push('\n')
      await yieldToUi()
    }
  }
  parts.push('\n' + pad + ']')
  return parts
}

/**
 * Stream a Markdown table (header + separator + rows) as Blob parts.
 *
 * `cellOf(row, header)` extracts the raw cell value; the helper handles
 * `flattenCellValue` + `escapeMarkdownCell` itself.
 */
export async function streamMarkdownTable(
  headers: string[],
  rows: unknown[],
  cellOf: (row: unknown, header: string) => unknown,
  chunkSize: number = EXPORT_CHUNK_ROWS,
): Promise<string[]> {
  const parts: string[] = []
  parts.push(`| ${headers.join(' | ')} |\n`)
  parts.push(`| ${headers.map(() => '---').join(' | ')} |`)
  for (let i = 0; i < rows.length; i += chunkSize) {
    const slice = rows.slice(i, i + chunkSize)
    const chunkLines = slice.map(row =>
      `| ${headers.map(h => escapeMarkdownCell(flattenCellValue(cellOf(row, h)))).join(' | ')} |`,
    )
    parts.push('\n' + chunkLines.join('\n'))
    if (i + chunkSize < rows.length) await yieldToUi()
  }
  return parts
}

/**
 * Stream a list of pre-built lines (e.g. an AI session transcript) as Blob
 * parts joined by '\n', yielding to the UI between chunks.
 */
export async function streamLines(
  lines: string[],
  chunkSize: number = EXPORT_CHUNK_ROWS * 4,
): Promise<string[]> {
  const parts: string[] = []
  for (let i = 0; i < lines.length; i += chunkSize) {
    const slice = lines.slice(i, i + chunkSize)
    parts.push((i === 0 ? '' : '\n') + slice.join('\n'))
    if (i + chunkSize < lines.length) await yieldToUi()
  }
  return parts
}

// ============================================================
// Async-generator variants for direct-to-disk streaming
// ============================================================
//
// The Promise<string[]> primitives above still hold every chunk in memory
// before download. For genuinely huge exports (>50k rows) that pins
// hundreds of MB and crashes Chrome's renderer (SIGILL on the 4GB ceiling).
//
// These async-generator variants emit one chunk at a time, so a consumer
// that pipes them straight into a FileSystemWritableFileStream (Chrome /
// Edge `showSaveFilePicker`) writes each chunk to disk and frees it
// immediately -- peak memory stays at one chunk's worth of text.
//
// The Promise variants above are kept so existing callers / tests don't
// break; they're now thin wrappers that drain the generator.

export async function* streamCsvChunks(
  headers: string[],
  rows: Iterable<Record<string, unknown>> | AsyncIterable<Record<string, unknown>>,
  chunkSize: number = EXPORT_CHUNK_ROWS,
): AsyncGenerator<string> {
  yield '\uFEFF'
  yield headers.map(h => escapeCsvCell(h)).join(',')
  let buffer: string[] = []
  for await (const row of rows as AsyncIterable<Record<string, unknown>>) {
    buffer.push(headers.map(h => escapeCsvCell(row[h])).join(','))
    if (buffer.length >= chunkSize) {
      yield '\r\n' + buffer.join('\r\n')
      buffer = []
      await yieldToUi()
    }
  }
  if (buffer.length) yield '\r\n' + buffer.join('\r\n')
  yield '\r\n'
}

export async function* streamJsonArrayChunks(
  rows: Iterable<unknown> | AsyncIterable<unknown>,
  options: { chunkSize?: number; outerIndent?: number } = {},
): AsyncGenerator<string> {
  const { chunkSize = EXPORT_CHUNK_ROWS, outerIndent = 0 } = options
  const pad = ' '.repeat(outerIndent)
  const innerPad = ' '.repeat(outerIndent + 2)

  // Buffer a small look-ahead so we know when a row is "the last one" and
  // can omit its trailing comma without materializing the whole array.
  let opened = false
  let buffer: string[] = []
  let pending: unknown = undefined
  let havePending = false

  const flushChunk = (last: boolean): string | null => {
    if (buffer.length === 0) return null
    const text = buffer.map((s, j) => {
      const isFinal = last && j === buffer.length - 1
      return s + (isFinal ? '' : ',')
    }).join('\n')
    buffer = []
    return text
  }

  const stringifyOne = (row: unknown): string => {
    const stringified = JSON.stringify(row, null, 2)
    return stringified.split('\n').map(line => innerPad + line).join('\n')
  }

  for await (const row of rows as AsyncIterable<unknown>) {
    if (havePending) {
      buffer.push(stringifyOne(pending))
      if (buffer.length >= chunkSize) {
        if (!opened) { yield '[\n'; opened = true }
        const text = flushChunk(false)
        if (text !== null) yield text + '\n'
        await yieldToUi()
      }
    }
    pending = row
    havePending = true
  }
  // Flush the last buffered row + the pending one as the final, comma-less rows.
  if (havePending) {
    buffer.push(stringifyOne(pending))
    if (!opened) { yield '[\n'; opened = true }
    const text = flushChunk(true)
    if (text !== null) yield text
    yield '\n' + pad + ']'
    return
  }
  // No rows at all
  yield '[]'
}

export async function* streamMarkdownTableChunks(
  headers: string[],
  rows: Iterable<unknown> | AsyncIterable<unknown>,
  cellOf: (row: unknown, header: string) => unknown,
  chunkSize: number = EXPORT_CHUNK_ROWS,
): AsyncGenerator<string> {
  yield `| ${headers.join(' | ')} |\n`
  yield `| ${headers.map(() => '---').join(' | ')} |`
  let buffer: string[] = []
  for await (const row of rows as AsyncIterable<unknown>) {
    buffer.push(`| ${headers.map(h => escapeMarkdownCell(flattenCellValue(cellOf(row, h)))).join(' | ')} |`)
    if (buffer.length >= chunkSize) {
      yield '\n' + buffer.join('\n')
      buffer = []
      await yieldToUi()
    }
  }
  if (buffer.length) yield '\n' + buffer.join('\n')
}

// ============================================================
// downloadStreaming: showSaveFilePicker fast path + Blob fallback
// ============================================================

/**
 * Browser type guard for the File System Access API. Available on Chrome,
 * Edge, and Opera; not Firefox or Safari at time of writing.
 */
function hasFileSystemAccess(): boolean {
  return typeof window !== 'undefined' && 'showSaveFilePicker' in window
}

interface SaveFilePickerType {
  description?: string
  accept: Record<string, string[]>
}

interface SaveFilePickerOptions {
  suggestedName?: string
  types?: SaveFilePickerType[]
}

interface FileSystemFileHandle {
  createWritable: () => Promise<FileSystemWritableFileStream>
}

interface FileSystemWritableFileStream {
  write: (data: BufferSource | Blob | string) => Promise<void>
  close: () => Promise<void>
  abort: () => Promise<void>
}

function pickerTypeFor(mime: string, ext: string): SaveFilePickerType {
  return { description: `${ext.toUpperCase()} file`, accept: { [mime]: [`.${ext}`] } }
}

function extFromFilename(filename: string): string {
  const dot = filename.lastIndexOf('.')
  return dot >= 0 ? filename.slice(dot + 1) : 'txt'
}

/**
 * Stream chunks to a user-chosen disk location via showSaveFilePicker, with
 * automatic Blob-download fallback for browsers without File System Access.
 *
 * `makeChunks` is a factory (not a single generator) so the chain can be
 * re-iterated if the disk path fails partway. The factory should be cheap
 * to call -- typically `() => streamCsvChunks(headers, rows)`.
 *
 * Returns true on success, false if user cancelled. Re-throws unexpected errors.
 */
export async function downloadStreaming(
  filename: string,
  mimeType: string,
  makeChunks: () => AsyncGenerator<string>,
): Promise<boolean> {
  if (hasFileSystemAccess()) {
    let handle: FileSystemFileHandle | null = null
    try {
      const win = window as unknown as {
        showSaveFilePicker: (opts: SaveFilePickerOptions) => Promise<FileSystemFileHandle>
      }
      handle = await win.showSaveFilePicker({
        suggestedName: filename,
        types: [pickerTypeFor(mimeType, extFromFilename(filename))],
      })
    } catch (err) {
      const e = err as { name?: string }
      if (e?.name === 'AbortError') return false // user cancelled, no fallback
      // SecurityError (cross-origin iframe etc) or other: fall through to Blob.
      handle = null
    }
    if (handle) {
      const writable = await handle.createWritable()
      const encoder = new TextEncoder()
      try {
        for await (const chunk of makeChunks()) {
          await writable.write(encoder.encode(chunk))
        }
        await writable.close()
        return true
      } catch (err) {
        try { await writable.abort() } catch { /* ignore */ }
        throw err
      }
    }
  }

  // Fallback: collect chunks into Blob parts. Memory peak ~= total file size,
  // but that's the best a Blob-based download can do. Browsers without disk
  // streaming will still benefit from the per-row stringify + chunked Blob
  // construction we did before.
  const parts: BlobPart[] = []
  for await (const chunk of makeChunks()) parts.push(chunk)
  downloadBlobParts(parts, filename, mimeType)
  return true
}

/**
 * Convenience: prepend / append wrapper text around an inner generator
 * (used to wrap a streamed JSON array in a `{ ..., "rows": <array> }` envelope).
 */
export async function* withWrap(
  before: string,
  inner: AsyncGenerator<string>,
  after: string,
): AsyncGenerator<string> {
  yield before
  for await (const chunk of inner) yield chunk
  yield after
}

/**
 * Concatenate multiple async generators into one, with optional separator
 * between them (used by JsRecon's multi-section CSV / MD output).
 */
export async function* concatChunks(
  generators: Array<AsyncGenerator<string>>,
  separator?: string,
): AsyncGenerator<string> {
  let first = true
  for (const gen of generators) {
    if (!first && separator) yield separator
    first = false
    for await (const chunk of gen) yield chunk
  }
}
