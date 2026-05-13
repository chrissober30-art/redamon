/**
 * Unit tests for the streaming primitives that back every CSV / JSON / MD
 * export in the graph page. These exercise the primitives directly (no DOM,
 * no Blob) so we can isolate edge cases the smoke tests can only observe
 * end-to-end.
 *
 * Pin-down list:
 *   - empty input
 *   - exact chunk boundaries (chunkSize, off-by-one)
 *   - special-character survival across chunk boundaries
 *   - JSON output round-trips through JSON.parse
 *   - outerIndent nesting for the NodeDetails envelope
 *   - async-generator variants used by downloadStreaming
 *   - downloadStreaming honors showSaveFilePicker (Chrome / Edge fast path)
 *     and falls back gracefully to Blob downloads otherwise
 */
import { describe, test, expect } from 'vitest'
import {
  streamCsv,
  streamJsonArray,
  streamMarkdownTable,
  streamLines,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  downloadStreaming,
  EXPORT_CHUNK_ROWS,
  escapeCsvCell,
  flattenCellValue,
  escapeMarkdownCell,
} from './exportHelpers'

// ============================================================
// streamCsv (Promise<string[]>)
// ============================================================

describe('streamCsv', () => {
  test('empty rows produces just BOM + header + trailing CRLF', async () => {
    const parts = await streamCsv(['a', 'b'], [])
    expect(parts.join('')).toBe('\uFEFFa,b\r\n')
  })

  test('single row matches the non-streaming toCsv output', async () => {
    const parts = await streamCsv(['a', 'b'], [{ a: '1', b: '2' }])
    expect(parts.join('')).toBe('\uFEFFa,b\r\n1,2\r\n')
  })

  test('exact chunk boundary (chunkSize rows) does not emit a trailing yield-chunk', async () => {
    const rows = Array.from({ length: 10 }, (_, i) => ({ a: String(i) }))
    const parts = await streamCsv(['a'], rows, 10)
    const lines = parts.join('').replace(/^\uFEFF/, '').trimEnd().split('\r\n')
    expect(lines).toHaveLength(11)
    expect(lines[10]).toBe('9')
  })

  test('off-by-one (chunkSize+1) splits across two chunks but joins cleanly', async () => {
    const rows = Array.from({ length: 11 }, (_, i) => ({ a: String(i) }))
    const parts = await streamCsv(['a'], rows, 10)
    const lines = parts.join('').replace(/^\uFEFF/, '').trimEnd().split('\r\n')
    expect(lines).toHaveLength(12)
    expect(lines[11]).toBe('10')
  })

  test('special characters escape across chunk boundaries', async () => {
    const rows = [
      ...Array.from({ length: 4 }, (_, i) => ({ note: `r${i}` })),
      { note: 'has,comma' },
      { note: 'has"quote' },
      { note: 'has\nnewline' },
    ]
    const text = (await streamCsv(['note'], rows, 5)).join('')
    expect(text).toContain('"has,comma"')
    expect(text).toContain('"has""quote"')
    expect(text).toContain('"has\nnewline"')
  })

  test('default chunk size is EXPORT_CHUNK_ROWS', async () => {
    expect(EXPORT_CHUNK_ROWS).toBe(500)
    const rows = Array.from({ length: 1500 }, (_, i) => ({ a: String(i) }))
    const lines = (await streamCsv(['a'], rows)).join('').replace(/^\uFEFF/, '').trimEnd().split('\r\n')
    expect(lines).toHaveLength(1501)
  })
})

// ============================================================
// streamJsonArray (Promise<string[]>)
// ============================================================

describe('streamJsonArray', () => {
  test('empty array produces literal []', async () => {
    expect((await streamJsonArray([])).join('')).toBe('[]')
  })

  test('5000 rows round-trip through JSON.parse', async () => {
    const rows = Array.from({ length: 5000 }, (_, i) => ({ idx: i, nested: { k: `v-${i}` } }))
    const parsed = JSON.parse((await streamJsonArray(rows)).join(''))
    expect(parsed).toHaveLength(5000)
    expect(parsed[2500]).toEqual({ idx: 2500, nested: { k: 'v-2500' } })
  })

  test('outerIndent nests cleanly inside a wrapping object', async () => {
    const arrayParts = await streamJsonArray([{ a: 1 }, { a: 2 }], { outerIndent: 2 })
    const wrapped = '{\n  "data": ' + arrayParts.join('') + '\n}\n'
    expect(JSON.parse(wrapped)).toEqual({ data: [{ a: 1 }, { a: 2 }] })
  })

  test('chunk seam never produces double commas', async () => {
    const rows = Array.from({ length: 11 }, (_, i) => ({ i }))
    const text = (await streamJsonArray(rows, { chunkSize: 10 })).join('')
    expect(text).not.toMatch(/,\s*,/)
    expect(JSON.parse(text)).toHaveLength(11)
  })
})

// ============================================================
// streamMarkdownTable (Promise<string[]>)
// ============================================================

describe('streamMarkdownTable', () => {
  test('empty rows yields header + separator only', async () => {
    const parts = await streamMarkdownTable(['a', 'b'], [], () => '')
    expect(parts.join('')).toBe('| a | b |\n| --- | --- |')
  })

  test('5000 rows produce 5001 table lines (header + 5000 data)', async () => {
    const rows = Array.from({ length: 5000 }, (_, i) => ({ a: String(i) }))
    const parts = await streamMarkdownTable(['a'], rows, (row, h) => (row as Record<string, unknown>)[h])
    const lines = parts.join('').split('\n').filter(l => l.startsWith('| ') && !l.includes(' --- '))
    expect(lines).toHaveLength(5001)
  })

  test('pipes are escaped in cell values', async () => {
    const rows = [{ s: 'has|pipe' }]
    const text = (await streamMarkdownTable(['s'], rows, (row, h) => (row as Record<string, unknown>)[h])).join('')
    expect(text).toContain('| has\\|pipe |')
  })
})

// ============================================================
// streamLines
// ============================================================

describe('streamLines', () => {
  test('empty array', async () => {
    expect((await streamLines([])).join('')).toBe('')
  })

  test('many lines split across chunks join back to the original', async () => {
    const lines = Array.from({ length: 5000 }, (_, i) => `line-${i}`)
    expect((await streamLines(lines, 250)).join('')).toBe(lines.join('\n'))
  })
})

// ============================================================
// Re-exported escape helpers
// ============================================================

describe('escape helpers', () => {
  test('escapeCsvCell quotes commas, doubles quotes, swallows null', () => {
    expect(escapeCsvCell('a,b')).toBe('"a,b"')
    expect(escapeCsvCell('a"b')).toBe('"a""b"')
    expect(escapeCsvCell(null)).toBe('')
  })

  test('escapeMarkdownCell escapes pipes, flattens newlines', () => {
    expect(escapeMarkdownCell('a|b')).toBe('a\\|b')
    expect(escapeMarkdownCell('a\nb')).toBe('a b')
  })

  test('flattenCellValue handles arrays / objects / null', () => {
    expect(flattenCellValue([1, 2, 3])).toBe('1, 2, 3')
    expect(flattenCellValue({ a: 1 })).toBe('{"a":1}')
    expect(flattenCellValue(null)).toBe('')
  })
})

// ============================================================
// Async-generator variants
// ============================================================

async function collect(gen: AsyncGenerator<string>): Promise<string> {
  let out = ''
  for await (const chunk of gen) out += chunk
  return out
}

describe('streamCsvChunks (async generator)', () => {
  test('empty rows', async () => {
    expect(await collect(streamCsvChunks(['a', 'b'], []))).toBe('\uFEFFa,b\r\n')
  })

  test('matches streamCsv array output for 100-row dataset', async () => {
    const rows = Array.from({ length: 100 }, (_, i) => ({ a: i, b: `r${i}` }))
    const generated = await collect(streamCsvChunks(['a', 'b'], rows))
    const arrayBased = (await streamCsv(['a', 'b'], rows)).join('')
    expect(generated).toBe(arrayBased)
  })

  test('produces multiple chunks (memory streamability proof)', async () => {
    const rows = Array.from({ length: 1500 }, (_, i) => ({ a: i }))
    let chunkCount = 0
    for await (const _c of streamCsvChunks(['a'], rows, 250)) chunkCount++
    expect(chunkCount).toBeGreaterThan(5)
  })

  test('accepts a sync generator as the row source (no array materialization)', async () => {
    function* lazy() {
      for (let i = 0; i < 50; i++) yield { a: i }
    }
    const text = await collect(streamCsvChunks(['a'], lazy()))
    const lines = text.replace(/^\uFEFF/, '').trimEnd().split('\r\n')
    expect(lines).toHaveLength(51)
    expect(lines[50]).toBe('49')
  })
})

describe('streamJsonArrayChunks (async generator)', () => {
  test('empty', async () => {
    expect(await collect(streamJsonArrayChunks([]))).toBe('[]')
  })

  test('single row', async () => {
    const text = await collect(streamJsonArrayChunks([{ a: 1 }]))
    expect(JSON.parse(text)).toEqual([{ a: 1 }])
  })

  test('1000 rows round-trip through JSON.parse', async () => {
    const rows = Array.from({ length: 1000 }, (_, i) => ({ i, sq: i * i }))
    expect(JSON.parse(await collect(streamJsonArrayChunks(rows)))).toEqual(rows)
  })

  test('outerIndent nests inside a wrapper object', async () => {
    const text = await collect(streamJsonArrayChunks([{ a: 1 }, { b: 2 }], { outerIndent: 2 }))
    const wrapped = '{\n  "data": ' + text + '\n}\n'
    expect(JSON.parse(wrapped)).toEqual({ data: [{ a: 1 }, { b: 2 }] })
  })

  test('chunk seam does not produce double commas (off-by-one)', async () => {
    const rows = Array.from({ length: 11 }, (_, i) => ({ i }))
    const text = await collect(streamJsonArrayChunks(rows, { chunkSize: 5 }))
    expect(text).not.toMatch(/,\s*,/)
    expect(JSON.parse(text)).toHaveLength(11)
  })

  test('accepts sync generator (no full-array materialization)', async () => {
    function* lazy() { for (let i = 0; i < 30; i++) yield { i } }
    const parsed = JSON.parse(await collect(streamJsonArrayChunks(lazy())))
    expect(parsed).toHaveLength(30)
    expect(parsed[29]).toEqual({ i: 29 })
  })
})

describe('streamMarkdownTableChunks (async generator)', () => {
  test('empty rows: header + separator only', async () => {
    expect(await collect(streamMarkdownTableChunks(['a'], [], () => ''))).toBe('| a |\n| --- |')
  })

  test('5000 rows produce 5000 data lines + header', async () => {
    const rows = Array.from({ length: 5000 }, (_, i) => ({ a: String(i) }))
    const text = await collect(streamMarkdownTableChunks(
      ['a'], rows, (row, h) => (row as Record<string, unknown>)[h],
    ))
    const dataLines = text.split('\n').filter(l => l.startsWith('| ') && !l.includes(' --- '))
    expect(dataLines).toHaveLength(5001)
  })
})

// ============================================================
// downloadStreaming -- showSaveFilePicker fast path + Blob fallback
// ============================================================

describe('downloadStreaming with showSaveFilePicker (Chrome / Edge fast path)', () => {
  test('writes each chunk to disk and never assembles a Blob', async () => {
    const writes: Uint8Array[] = []
    let closed = false
    const handle = {
      createWritable: async () => ({
        write: async (data: Uint8Array) => { writes.push(data) },
        close: async () => { closed = true },
        abort: async () => { /* noop */ },
      }),
    }
    const win = window as unknown as { showSaveFilePicker?: unknown }
    const originalPicker = win.showSaveFilePicker
    win.showSaveFilePicker = async () => handle

    let blobCreated = false
    const originalBlob = global.Blob
    class TrackingBlob extends originalBlob {
      constructor(...args: ConstructorParameters<typeof Blob>) {
        super(...args)
        blobCreated = true
      }
    }
    global.Blob = TrackingBlob as unknown as typeof Blob

    try {
      const rows = Array.from({ length: 100 }, (_, i) => ({ a: i }))
      const ok = await downloadStreaming(
        'big.csv', 'text/csv;charset=utf-8',
        () => streamCsvChunks(['a'], rows),
      )
      expect(ok).toBe(true)
      expect(closed).toBe(true)
      expect(writes.length).toBeGreaterThan(2)
      expect(blobCreated).toBe(false)
      const decoder = new TextDecoder()
      const reassembled = writes.map(w => decoder.decode(w)).join('')
      const lines = reassembled.replace(/^\uFEFF/, '').trimEnd().split('\r\n')
      expect(lines[0]).toBe('a')
      expect(lines).toHaveLength(101)
    } finally {
      win.showSaveFilePicker = originalPicker
      global.Blob = originalBlob
    }
  })

  test('user cancellation (AbortError) returns false and skips Blob fallback', async () => {
    const win = window as unknown as { showSaveFilePicker?: unknown }
    const originalPicker = win.showSaveFilePicker
    win.showSaveFilePicker = async () => {
      const err = new Error('cancelled') as Error & { name: string }
      err.name = 'AbortError'
      throw err
    }

    let blobCreated = false
    const originalBlob = global.Blob
    class TrackingBlob extends originalBlob {
      constructor(...args: ConstructorParameters<typeof Blob>) {
        super(...args)
        blobCreated = true
      }
    }
    global.Blob = TrackingBlob as unknown as typeof Blob

    try {
      const ok = await downloadStreaming(
        'cancel.csv', 'text/csv;charset=utf-8',
        () => streamCsvChunks(['a'], [{ a: 1 }]),
      )
      expect(ok).toBe(false)
      expect(blobCreated).toBe(false)
    } finally {
      win.showSaveFilePicker = originalPicker
      global.Blob = originalBlob
    }
  })

  test('non-Abort picker error falls back to Blob download', async () => {
    const win = window as unknown as { showSaveFilePicker?: unknown }
    const originalPicker = win.showSaveFilePicker
    win.showSaveFilePicker = async () => {
      const err = new Error('cross-origin frame') as Error & { name: string }
      err.name = 'SecurityError'
      throw err
    }

    let blobCreated = false
    const originalBlob = global.Blob
    class TrackingBlob extends originalBlob {
      constructor(...args: ConstructorParameters<typeof Blob>) {
        super(...args)
        blobCreated = true
      }
    }
    global.Blob = TrackingBlob as unknown as typeof Blob

    const originalCreate = URL.createObjectURL
    URL.createObjectURL = (() => 'blob:test/0') as typeof URL.createObjectURL
    const originalRevoke = URL.revokeObjectURL
    URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL
    const originalClick = HTMLAnchorElement.prototype.click
    HTMLAnchorElement.prototype.click = function () { /* noop */ }

    try {
      const ok = await downloadStreaming(
        'fallback.csv', 'text/csv;charset=utf-8',
        () => streamCsvChunks(['a'], [{ a: 1 }]),
      )
      expect(ok).toBe(true)
      expect(blobCreated).toBe(true)
    } finally {
      win.showSaveFilePicker = originalPicker
      global.Blob = originalBlob
      URL.createObjectURL = originalCreate
      URL.revokeObjectURL = originalRevoke
      HTMLAnchorElement.prototype.click = originalClick
    }
  })

  test('Blob fallback triggers when showSaveFilePicker is undefined', async () => {
    const win = window as unknown as { showSaveFilePicker?: unknown }
    const originalPicker = win.showSaveFilePicker
    delete win.showSaveFilePicker

    let blobCreated = false
    const originalBlob = global.Blob
    class TrackingBlob extends originalBlob {
      constructor(...args: ConstructorParameters<typeof Blob>) {
        super(...args)
        blobCreated = true
      }
    }
    global.Blob = TrackingBlob as unknown as typeof Blob

    const originalCreate = URL.createObjectURL
    URL.createObjectURL = (() => 'blob:test/0') as typeof URL.createObjectURL
    const originalRevoke = URL.revokeObjectURL
    URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL
    const originalClick = HTMLAnchorElement.prototype.click
    HTMLAnchorElement.prototype.click = function () { /* noop */ }

    try {
      const ok = await downloadStreaming(
        'plain.csv', 'text/csv;charset=utf-8',
        () => streamCsvChunks(['a'], [{ a: 1 }]),
      )
      expect(ok).toBe(true)
      expect(blobCreated).toBe(true)
    } finally {
      if (originalPicker !== undefined) win.showSaveFilePicker = originalPicker
      global.Blob = originalBlob
      URL.createObjectURL = originalCreate
      URL.revokeObjectURL = originalRevoke
      HTMLAnchorElement.prototype.click = originalClick
    }
  })
})

// ============================================================
// 50k-row regression: peak memory bounded by chunk size, not dataset size
// ============================================================

describe('50k-row streaming (memory-bounded regression for the SIGILL crash)', () => {
  test('streamCsvChunks completes for 50000 rows (does not blow heap)', async () => {
    const rows = Array.from({ length: 50000 }, (_, i) => ({ a: i, b: `host-${i}.example.com`, c: i * 2 }))
    let chunkCount = 0
    let lineCount = 0
    let lastSeen = ''
    for await (const chunk of streamCsvChunks(['a', 'b', 'c'], rows, 1000)) {
      chunkCount++
      // Each chunk is bounded by chunk size, not total dataset size
      expect(chunk.length).toBeLessThan(2_000_000) // < 2MB per chunk for these rows
      // Count lines in this chunk
      lineCount += (chunk.match(/\n/g) || []).length
      lastSeen = chunk
    }
    expect(chunkCount).toBeGreaterThan(40)
    // Final chunk is the trailing CRLF
    expect(lastSeen).toBe('\r\n')
    // Total newlines = 1 (after header) + 50000 (after each row) + 1 (trailing)
    // But our implementation puts \r\n at the start of each batch chunk, so each
    // batch chunk has chunkSize newlines. Total = ~50001 + framing.
    expect(lineCount).toBeGreaterThan(49999)
  })

  test('streamJsonArrayChunks completes for 50000 rows and round-trips', async () => {
    const rows = Array.from({ length: 50000 }, (_, i) => ({ i, k: `v-${i}` }))
    let totalChars = 0
    let chunkCount = 0
    const collected: string[] = []
    for await (const chunk of streamJsonArrayChunks(rows, { chunkSize: 1000 })) {
      chunkCount++
      totalChars += chunk.length
      collected.push(chunk)
    }
    expect(chunkCount).toBeGreaterThan(40)
    const parsed = JSON.parse(collected.join(''))
    expect(parsed).toHaveLength(50000)
    expect(parsed[49999]).toEqual({ i: 49999, k: 'v-49999' })
    expect(totalChars).toBeGreaterThan(1_000_000)
  })
})

// ============================================================
// Yielding behavior
// ============================================================

describe('streaming primitives yield to the event loop', () => {
  test('streamCsv with > chunkSize rows actually yields (interleaves with setTimeout)', async () => {
    let interleaved = false
    setTimeout(() => { interleaved = true }, 0)
    const rows = Array.from({ length: 600 }, (_, i) => ({ a: String(i) }))
    await streamCsv(['a'], rows, 100)
    expect(interleaved).toBe(true)
  })

  test('streamCsv with <= chunkSize rows does NOT yield (synchronous fast path for tiny exports)', async () => {
    let interleaved = false
    setTimeout(() => { interleaved = true }, 0)
    const rows = Array.from({ length: 50 }, (_, i) => ({ a: String(i) }))
    await streamCsv(['a'], rows, 100)
    expect(interleaved).toBe(false)
    await new Promise(r => setTimeout(r, 0))
    expect(interleaved).toBe(true)
  })
})
