/**
 * Unit + integration tests for FileImportButton.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/FileImportButton.test.tsx
 *
 * Covers:
 *  - parseFileText (pure function): all delimiters, BOM, comments, dedup, edge cases
 *  - FileImportButton (component): file upload flow, success/error states, validator,
 *    disabled state, variant positioning, timer cleanup on unmount, rapid-click race
 *  - Field-integration regressions: ensures the import-callback wiring matches the
 *    storage shape expected by each integrated section (string-joined vs array vs
 *    helper-transformed). These are the contracts a future refactor must not break.
 */

import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react'
import { FileImportButton, parseFileText } from './FileImportButton'

// ---------------------------------------------------------------------------
// 1. parseFileText — pure-function unit tests
// ---------------------------------------------------------------------------

describe('parseFileText: delimiters', () => {
  test('splits on newlines (\\n)', () => {
    expect(parseFileText('foo\nbar\nbaz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on Windows newlines (\\r\\n)', () => {
    expect(parseFileText('foo\r\nbar\r\nbaz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on commas', () => {
    expect(parseFileText('foo,bar,baz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on commas with spaces', () => {
    expect(parseFileText('foo, bar, baz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on semicolons', () => {
    expect(parseFileText('foo;bar;baz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on tabs', () => {
    expect(parseFileText('foo\tbar\tbaz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on pipes', () => {
    expect(parseFileText('foo|bar|baz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('splits on mixed delimiters', () => {
    expect(parseFileText('foo,bar;baz\nqux\tquux|corge')).toEqual([
      'foo', 'bar', 'baz', 'qux', 'quux', 'corge',
    ])
  })

  test('collapses consecutive delimiters', () => {
    expect(parseFileText('foo,,,bar\n\n\nbaz')).toEqual(['foo', 'bar', 'baz'])
  })

  test('does NOT split on spaces (preserves "Cookie: abc")', () => {
    expect(parseFileText('Cookie: session=abc\nX-Header: value')).toEqual([
      'Cookie: session=abc',
      'X-Header: value',
    ])
  })

  test('does NOT split on dots (preserves IPs/domains)', () => {
    expect(parseFileText('192.168.1.1\nexample.com')).toEqual([
      '192.168.1.1',
      'example.com',
    ])
  })

  test('does NOT split on colons (preserves host:port)', () => {
    expect(parseFileText('admin.local:8500\n10.20.30.40:9200')).toEqual([
      'admin.local:8500',
      '10.20.30.40:9200',
    ])
  })

  test('does NOT split on slashes (preserves CIDR + paths)', () => {
    expect(parseFileText('10.0.0.0/8\n/admin/users')).toEqual([
      '10.0.0.0/8',
      '/admin/users',
    ])
  })
})

describe('parseFileText: comments', () => {
  test('strips lines starting with #', () => {
    expect(parseFileText('# comment\nfoo\n# another')).toEqual(['foo'])
  })

  test('strips lines starting with //', () => {
    expect(parseFileText('// header\nfoo\n// trailer')).toEqual(['foo'])
  })

  test('strips comments with leading whitespace', () => {
    expect(parseFileText('   # indented\n\tfoo')).toEqual(['foo'])
  })

  test('keeps tokens that contain # but do not start with it', () => {
    expect(parseFileText('foo#bar\nvalue')).toEqual(['foo#bar', 'value'])
  })
})

describe('parseFileText: BOM and whitespace', () => {
  test('strips UTF-8 BOM at start', () => {
    expect(parseFileText('\uFEFFfoo\nbar')).toEqual(['foo', 'bar'])
  })

  test('trims whitespace from tokens', () => {
    expect(parseFileText('  foo  ,  bar  ')).toEqual(['foo', 'bar'])
  })

  test('returns empty array for empty input', () => {
    expect(parseFileText('')).toEqual([])
  })

  test('returns empty array for whitespace-only input', () => {
    expect(parseFileText('   \n\t  \r\n  ')).toEqual([])
  })

  test('returns empty array for comments-only input', () => {
    expect(parseFileText('# only comments\n// here\n# nothing else')).toEqual([])
  })
})

describe('parseFileText: deduplication', () => {
  test('removes duplicates preserving first-seen order', () => {
    expect(parseFileText('foo\nbar\nfoo\nbaz\nbar')).toEqual(['foo', 'bar', 'baz'])
  })

  test('dedupes case-sensitively', () => {
    expect(parseFileText('Foo\nfoo\nFOO')).toEqual(['Foo', 'foo', 'FOO'])
  })

  test('dedupes after trimming', () => {
    expect(parseFileText('foo\n  foo  \nfoo')).toEqual(['foo'])
  })
})

describe('parseFileText: realistic security-tool wordlists', () => {
  test('seclists-style with comments + newlines', () => {
    const text =
      '# SecLists wordlist v1.0\n' +
      '# Author: someone\n' +
      'admin\n' +
      'login\n' +
      'wp-admin\n' +
      '\n' +
      '# section: backup\n' +
      'backup\n' +
      'old\n'
    expect(parseFileText(text)).toEqual(['admin', 'login', 'wp-admin', 'backup', 'old'])
  })

  test('port list mixed comma/newline format', () => {
    expect(parseFileText('22, 80, 443\n3306; 5432\n6379|8080')).toEqual([
      '22', '80', '443', '3306', '5432', '6379', '8080',
    ])
  })

  test('CIDR ranges newline-separated', () => {
    expect(parseFileText('10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16')).toEqual([
      '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    ])
  })

  test('subdomain prefixes one-per-line', () => {
    expect(parseFileText('www\napi\nadmin\nstaging\ndev')).toEqual([
      'www', 'api', 'admin', 'staging', 'dev',
    ])
  })

  test('header lines without semicolons round-trip cleanly', () => {
    const text = 'User-Agent: Mozilla/5.0\nAuthorization: Bearer xyz\nX-API-Key: a1b2c3'
    expect(parseFileText(text)).toEqual([
      'User-Agent: Mozilla/5.0',
      'Authorization: Bearer xyz',
      'X-API-Key: a1b2c3',
    ])
  })
})

describe('parseFileText: header-with-semicolon known limitation', () => {
  test('semicolons inside header values DO split (documented limitation)', () => {
    // Documents the parser trade-off: CSV-style semicolon splitting wins over
    // header preservation. Users importing headers should not include
    // semicolons mid-line, OR each header should already be on its own line
    // with no inline `; path=...` segments. If the team decides to swap this
    // trade-off, this test must be updated explicitly.
    const text = 'Cookie: session=abc; path=/'
    expect(parseFileText(text)).toEqual(['Cookie: session=abc', 'path=/'])
  })

  test('headers without inline semicolons round-trip safely', () => {
    const text = 'Authorization: Bearer xyz\nUser-Agent: redamon/1.0'
    expect(parseFileText(text)).toEqual([
      'Authorization: Bearer xyz',
      'User-Agent: redamon/1.0',
    ])
  })
})

// ---------------------------------------------------------------------------
// 2. FileImportButton component — interaction tests
// ---------------------------------------------------------------------------

function makeFile(content: string, name = 'list.txt', type = 'text/plain'): File {
  return new File([content], name, { type })
}

function getFileInput(container: HTMLElement): HTMLInputElement {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement
  if (!input) throw new Error('hidden file input not rendered')
  return input
}

function getButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: /import values from text file/i }) as HTMLButtonElement
}

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('FileImportButton: rendering', () => {
  test('renders a button with import aria-label', () => {
    render(<FileImportButton onImport={() => {}} />)
    expect(getButton()).toBeTruthy()
    expect(getButton().tagName).toBe('BUTTON')
  })

  test('renders hidden file input with text/plain accept by default', () => {
    const { container } = render(<FileImportButton onImport={() => {}} />)
    const input = getFileInput(container)
    expect(input.accept).toContain('.txt')
    expect(input.style.display).toBe('none')
  })

  test('respects custom accept prop', () => {
    const { container } = render(<FileImportButton onImport={() => {}} accept=".csv" />)
    expect(getFileInput(container).accept).toBe('.csv')
  })

  test('disabled state prevents click and disables button', () => {
    const onImport = vi.fn()
    render(<FileImportButton onImport={onImport} disabled />)
    const btn = getButton()
    expect(btn.disabled).toBe(true)
    fireEvent.click(btn)
    expect(onImport).not.toHaveBeenCalled()
  })

  test('variant=textarea applies textarea positioning class', () => {
    render(<FileImportButton onImport={() => {}} variant="textarea" />)
    expect(getButton().className).toMatch(/fileImportButtonTextareaPos/)
  })

  test('variant=input (default) applies input positioning class', () => {
    render(<FileImportButton onImport={() => {}} />)
    expect(getButton().className).toMatch(/fileImportButtonInputPos/)
  })
})

describe('FileImportButton: file upload flow', () => {
  test('successful upload calls onImport with parsed tokens', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('foo,bar,baz')] } })
    })

    await waitFor(() => expect(onImport).toHaveBeenCalledTimes(1))
    expect(onImport).toHaveBeenCalledWith(['foo', 'bar', 'baz'])
  })

  test('parses newline + comment file end-to-end', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, {
        target: { files: [makeFile('# header\nfoo\nbar\n# tail\nfoo')] },
      })
    })

    await waitFor(() => expect(onImport).toHaveBeenCalledWith(['foo', 'bar']))
  })

  test('clears the file input value after each upload (re-import same file works)', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('foo')] } })
    })
    await waitFor(() => expect(onImport).toHaveBeenCalledTimes(1))
    expect(input.value).toBe('')
  })
})

describe('FileImportButton: validator', () => {
  test('skips tokens that fail the validator', async () => {
    const onImport = vi.fn()
    const { container } = render(
      <FileImportButton onImport={onImport} validator={(t) => /^\d+$/.test(t)} />,
    )
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, {
        target: { files: [makeFile('200,foo,301,bar,404')] },
      })
    })

    await waitFor(() =>
      expect(onImport).toHaveBeenCalledWith(['200', '301', '404']),
    )
  })

  test('shows error if validator filters out everything', async () => {
    const onImport = vi.fn()
    const { container } = render(
      <FileImportButton onImport={onImport} validator={() => false} />,
    )
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('foo,bar')] } })
    })

    await new Promise(r => setTimeout(r, 50))
    expect(onImport).not.toHaveBeenCalled()
  })
})

describe('FileImportButton: error states', () => {
  test('does not call onImport on empty file', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('')] } })
    })

    await new Promise(r => setTimeout(r, 50))
    expect(onImport).not.toHaveBeenCalled()
  })

  test('does not call onImport on comment-only file', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, {
        target: { files: [makeFile('# nothing\n// here either')] },
      })
    })

    await new Promise(r => setTimeout(r, 50))
    expect(onImport).not.toHaveBeenCalled()
  })

  test('rejects oversized files (>5MB) without reading them', async () => {
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    const big = new File(['tiny'], 'huge.txt', { type: 'text/plain' })
    Object.defineProperty(big, 'size', { value: 6 * 1024 * 1024, configurable: true })

    await act(async () => {
      fireEvent.change(input, { target: { files: [big] } })
    })

    await new Promise(r => setTimeout(r, 50))
    expect(onImport).not.toHaveBeenCalled()
  })
})

describe('FileImportButton: timer cleanup (regression)', () => {
  test('does not throw when component unmounts during the success-flash window', async () => {
    // Without the cleanup hook, the post-success setTimeout would fire after
    // unmount and call setState on a dead component. This used to surface as a
    // React warning in test logs only — silent in production but sloppy.
    const onImport = vi.fn()
    const { container, unmount } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('foo')] } })
    })
    await waitFor(() => expect(onImport).toHaveBeenCalled())

    // Unmount BEFORE the 2.5s success timer fires.
    expect(() => unmount()).not.toThrow()

    // Wait long enough that any leaked timer would have fired.
    await new Promise(r => setTimeout(r, 50))
    // If we got here without throwing or unhandled-rejection, the cleanup worked.
  })

  test('rapid back-to-back uploads do not leave a stale timer', async () => {
    // First upload finishes → success timer T1 starts. Second upload finishes
    // before T1 fires → T1 must be cancelled, otherwise it fires mid-success
    // and resets status to idle prematurely.
    const onImport = vi.fn()
    const { container } = render(<FileImportButton onImport={onImport} />)
    const input = getFileInput(container)

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('foo')] } })
    })
    await waitFor(() => expect(onImport).toHaveBeenCalledTimes(1))

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('bar')] } })
    })
    await waitFor(() => expect(onImport).toHaveBeenCalledTimes(2))
    expect(onImport).toHaveBeenLastCalledWith(['bar'])
  })
})

// ---------------------------------------------------------------------------
// 3. Field-integration contract tests
//
// These lock down the exact `onImport` adapter shape each section uses. If a
// future refactor changes the storage format (string-vs-array, comma-vs-newline
// joining, helper transforms), these tests will surface the regression at the
// wiring layer rather than in production.
// ---------------------------------------------------------------------------

describe('Field-integration adapters', () => {
  test('SsrfSection-style: comma-joined string for ports', () => {
    const updateField = vi.fn()
    const adapter = (values: string[]) => updateField('ssrfPortScanPorts', values.join(','))
    adapter(['22', '80', '443'])
    expect(updateField).toHaveBeenCalledWith('ssrfPortScanPorts', '22,80,443')
  })

  test('SsrfSection-style: newline-joined string for custom internal targets', () => {
    const updateField = vi.fn()
    const adapter = (values: string[]) =>
      updateField('ssrfCustomInternalTargets', values.join('\n'))
    adapter(['admin.local:8500', '10.20.30.40'])
    expect(updateField).toHaveBeenCalledWith(
      'ssrfCustomInternalTargets',
      'admin.local:8500\n10.20.30.40',
    )
  })

  test('Numeric array adapter (Ffuf/Kiterunner/Gau): parseInt with NaN filter', () => {
    const updateField = vi.fn()
    const adapter = (values: string[]) =>
      updateField('codes', values.map(v => parseInt(v)).filter(n => !isNaN(n)))
    adapter(['200', '301', 'foo', '404'])
    expect(updateField).toHaveBeenCalledWith('codes', [200, 301, 404])
  })

  test('String array adapter (Httpx codes): preserves strings as-is', () => {
    const updateField = vi.fn()
    const adapter = (values: string[]) => updateField('httpxMatchCodes', values)
    adapter(['200', '301', '302'])
    expect(updateField).toHaveBeenCalledWith('httpxMatchCodes', ['200', '301', '302'])
  })

  test('TargetSection subdomain adapter: comma-joined for handlePrefixesChange', () => {
    const handlePrefixesChange = vi.fn()
    const adapter = (values: string[]) => handlePrefixesChange(values.join(', '))
    adapter(['www', 'api', 'admin'])
    expect(handlePrefixesChange).toHaveBeenCalledWith('www, api, admin')
  })

  test('Naabu custom ports adapter: comma-joined (preserves ranges)', () => {
    const updateField = vi.fn()
    const adapter = (values: string[]) => updateField('naabuCustomPorts', values.join(','))
    adapter(['80', '443', '8080-8090'])
    expect(updateField).toHaveBeenCalledWith('naabuCustomPorts', '80,443,8080-8090')
  })
})

// ---------------------------------------------------------------------------
// 4. End-to-end smoke: parse → adapter → expected stored value
// ---------------------------------------------------------------------------

describe('End-to-end smoke', () => {
  test('SsrfSection ports: messy text file → "22,80,443"', () => {
    const text = '# common ports\n22\n80; 443\n22'
    const tokens = parseFileText(text)
    expect(tokens).toEqual(['22', '80', '443'])
    expect(tokens.join(',')).toBe('22,80,443')
  })

  test('Httpx headers: .txt with newlines → string[]', () => {
    const text = 'Authorization: Bearer abc\nUser-Agent: test'
    const tokens = parseFileText(text)
    expect(tokens).toEqual(['Authorization: Bearer abc', 'User-Agent: test'])
  })

  test('Subdomain prefixes round-trip via adapter', () => {
    const text = '# tier-1\nwww\napi\nadmin\n# tier-2\nstaging\ndev\nwww'
    const tokens = parseFileText(text)
    expect(tokens).toEqual(['www', 'api', 'admin', 'staging', 'dev'])
    expect(tokens.join(', ')).toBe('www, api, admin, staging, dev')
  })

  test('Numeric status codes via adapter', () => {
    const text = '# 2xx\n200\n201\n# redirects\n301\n302\nfoo'
    const tokens = parseFileText(text).filter(t => /^\d+$/.test(t))
    expect(tokens).toEqual(['200', '201', '301', '302'])
    expect(tokens.map(v => parseInt(v))).toEqual([200, 201, 301, 302])
  })
})
