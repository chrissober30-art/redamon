/**
 * Stage-D deep review.
 *
 *  - selectAll handler is wired (or documented as dead)
 *  - Selection persists across filter/sort changes
 *  - Hidden-by-filter entries stay in selection -> bulk actions still
 *    include them (intentional - locks regression)
 *  - Bulk download archiveName: nested path -> last segment used as name
 *  - Filter + sort composition (filter narrows, sort orders within)
 *  - Bulk delete loading state prevents double-confirm
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/FileSystemDrawer.stageD.review.test.tsx
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react'
import { FileSystemDrawer } from './FileSystemDrawer'

vi.mock('@/components/ui/Drawer', () => ({
  Drawer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="drawer">{children}</div>
  ),
}))

interface FetchCall { url: string; init?: RequestInit }
let fetchCalls: FetchCall[] = []
let fetchHandler: (url: string, init?: RequestInit) => Promise<Response>

beforeEach(() => {
  fetchCalls = []
  fetchHandler = async (url) => {
    if (url.includes('/api/agent/workspace/list')) {
      return new Response(JSON.stringify({ entries: mixedSample }), { status: 200 })
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  }
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    fetchCalls.push({ url: urlStr, init })
    return fetchHandler(urlStr, init)
  }) as unknown as typeof fetch
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

const mixedSample = [
  { name: 'alpha.txt', path: 'alpha.txt', isDir: false, isSymlink: false, size: 50, mtime: '2026-05-15T10:00:00Z' },
  { name: 'beta.txt', path: 'beta.txt', isDir: false, isSymlink: false, size: 200, mtime: '2026-05-13T10:00:00Z' },
  { name: 'gamma.bin', path: 'gamma.bin', isDir: false, isSymlink: false, size: 100, mtime: '2026-05-14T10:00:00Z' },
]


// =============================================================================
// (1) selectAll wiring (or dead-code documentation)
// =============================================================================

describe('FileSystemDrawer Stage D: selectAll wiring', () => {
  test('there is no UI affordance for select-all (yet)', async () => {
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    // Each entry has one checkbox -> 3 total. No additional "select all" box.
    expect(screen.getAllByRole('checkbox')).toHaveLength(3)
    // The bulk bar only renders when something is selected, so no select-all
    // affordance is visible from a fresh state. Document this as the
    // intended v1 behaviour. Selecting requires clicking individual rows.
  })
})


// =============================================================================
// (2) Selection persists across filter / sort
// =============================================================================

describe('FileSystemDrawer Stage D: selection persistence', () => {
  test('selection survives a filter change (hidden entries stay selected)', async () => {
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])  // alpha.txt
    fireEvent.click(screen.getAllByRole('checkbox')[1])  // beta.txt
    expect(screen.getByText('2 selected')).toBeInTheDocument()

    // Filter to hide beta.txt
    fireEvent.change(screen.getByPlaceholderText('Filter files…'), {
      target: { value: 'alpha' },
    })
    // beta.txt is hidden but STILL selected (counter unchanged)
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    expect(screen.queryByText('beta.txt')).not.toBeInTheDocument()
  })

  test('selection survives a sort change', async () => {
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])  // alpha.txt
    expect(screen.getByText('1 selected')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^Size/ }))
    expect(screen.getByText('1 selected')).toBeInTheDocument()
  })

  test('bulk delete includes filtered-out selected entries', async () => {
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])  // alpha.txt
    fireEvent.click(screen.getAllByRole('checkbox')[1])  // beta.txt
    // Filter so only alpha visible
    fireEvent.change(screen.getByPlaceholderText('Filter files…'), {
      target: { value: 'alpha' },
    })
    fireEvent.click(screen.getByTitle(/Delete selected/))
    // Modal opens for 2 (NOT 1 - hidden beta still counts)
    await screen.findByText(/Delete 2 entries\?/)
  })

  test('bulk download includes filtered-out selected entries', async () => {
    const clickSpy = vi.fn()
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = origCreate(tag)
      if (tag === 'a') (el as HTMLAnchorElement).click = clickSpy
      return el
    })
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/list')) {
        return new Response(JSON.stringify({ entries: mixedSample }), { status: 200 })
      }
      if (url.includes('/api/agent/workspace/bulk-archive')) {
        return new Response(new Uint8Array([0]), {
          status: 200,
          headers: { 'Content-Disposition': 'attachment; filename="bundle.tar.gz"' },
        })
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }

    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])  // alpha.txt
    fireEvent.click(screen.getAllByRole('checkbox')[1])  // beta.txt
    fireEvent.change(screen.getByPlaceholderText('Filter files…'), {
      target: { value: 'alpha' },
    })
    fireEvent.click(screen.getByTitle(/Download selected/))
    await waitFor(() => {
      const bulk = fetchCalls.find(c => c.url.includes('/workspace/bulk-archive'))
      const body = JSON.parse(bulk!.init!.body as string)
      // Both alpha + beta in the payload, even though beta is filtered out visually
      expect(body.paths.sort()).toEqual(['alpha.txt', 'beta.txt'])
    })
  })
})


// =============================================================================
// (3) Bulk download archiveName with single entry / nested path
// =============================================================================

describe('FileSystemDrawer Stage D: bulk archive name', () => {
  test('single nested path uses the last segment as archive name', async () => {
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/list')) {
        return new Response(JSON.stringify({
          entries: [
            { name: 'report.md', path: 'notes/2026-05/report.md', isDir: false, isSymlink: false, size: 1, mtime: '2026-05-14T10:00:00Z' },
          ],
        }), { status: 200 })
      }
      if (url.includes('/api/agent/workspace/bulk-archive')) {
        return new Response(new Uint8Array([0]), {
          status: 200,
          headers: { 'Content-Disposition': 'attachment; filename="report.md.tar.gz"' },
        })
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = origCreate(tag)
      if (tag === 'a') (el as HTMLAnchorElement).click = vi.fn()
      return el
    })

    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('report.md')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])
    fireEvent.click(screen.getByTitle(/Download selected/))
    await waitFor(() => {
      const bulk = fetchCalls.find(c => c.url.includes('/workspace/bulk-archive'))
      const body = JSON.parse(bulk!.init!.body as string)
      // archiveName is "report.md" (last segment), NOT "notes" or full path
      expect(body.archiveName).toBe('report.md')
    })
  })

  test('multi-select uses generic bundle name', async () => {
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = origCreate(tag)
      if (tag === 'a') (el as HTMLAnchorElement).click = vi.fn()
      return el
    })
    fetchHandler = async (url) => {
      if (url.includes('/api/agent/workspace/list')) {
        return new Response(JSON.stringify({ entries: mixedSample }), { status: 200 })
      }
      if (url.includes('/api/agent/workspace/bulk-archive')) {
        return new Response(new Uint8Array([0]), {
          status: 200,
          headers: { 'Content-Disposition': 'attachment; filename="bundle.tar.gz"' },
        })
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }

    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])
    fireEvent.click(screen.getAllByRole('checkbox')[1])
    fireEvent.click(screen.getByTitle(/Download selected/))
    await waitFor(() => {
      const bulk = fetchCalls.find(c => c.url.includes('/workspace/bulk-archive'))
      const body = JSON.parse(bulk!.init!.body as string)
      expect(body.archiveName).toBe('bundle')
    })
  })
})


// =============================================================================
// (4) Filter + sort composition
// =============================================================================

describe('FileSystemDrawer Stage D: filter + sort compose', () => {
  test('sort applies AFTER filter (filtered subset is sorted)', async () => {
    // Three .txt files (different sizes). Filter to .txt only (drops .bin),
    // then sort by Size asc -> alpha(50), beta(200).
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText('Filter files…'), {
      target: { value: '.txt' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^Size/ }))
    const names = Array.from(document.querySelectorAll('[data-name]'))
      .map(el => el.getAttribute('data-name'))
    expect(names).toEqual(['alpha.txt', 'beta.txt'])
    expect(screen.queryByText('gamma.bin')).not.toBeInTheDocument()
  })
})


// =============================================================================
// (5) Loading-state prevents double-fire on bulk actions
// =============================================================================

describe('FileSystemDrawer Stage D: bulk loading guard', () => {
  test('bulk Delete button is disabled while delete is in flight', async () => {
    // Slow DELETE response so we can observe the loading state
    fetchHandler = async (url, init) => {
      if (url.includes('/api/agent/workspace/list')) {
        return new Response(JSON.stringify({ entries: mixedSample }), { status: 200 })
      }
      if (init?.method === 'DELETE') {
        await new Promise(r => setTimeout(r, 100))
        return new Response(JSON.stringify({ deleted: true }), { status: 200 })
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('alpha.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])
    fireEvent.click(screen.getByTitle(/Delete selected/))
    await screen.findByText(/Delete 1 entry\?/)
    const confirmBtn = screen.getByRole('button', { name: /^Delete 1/ })
    fireEvent.click(confirmBtn)
    // Immediately the button text reflects loading state
    await waitFor(() => {
      expect(screen.getByText(/Deleting…/)).toBeInTheDocument()
    })
    // And it's disabled
    expect(confirmBtn).toBeDisabled()
  })
})
