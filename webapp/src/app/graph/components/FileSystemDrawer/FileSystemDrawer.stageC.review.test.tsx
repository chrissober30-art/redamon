/**
 * Stage-C deep review.
 *
 *  - previewing state must reset when the drawer closes (and is reopened)
 *  - propertiesFor must reset on close+reopen
 *  - Changing projectId must clear preview/properties (stale content from
 *    a different project would otherwise display)
 *  - Switching tabs preserves preview (intentional UX - regression lock)
 *  - Clicking SAME file twice in a row fires preview fetch each time
 *    (no accidental memoization that would hide content changes)
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/FileSystemDrawer.stageC.review.test.tsx
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
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
  fetchHandler = async () => new Response(JSON.stringify({ entries: [] }), { status: 200 })
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    fetchCalls.push({ url: urlStr, init })
    return fetchHandler(urlStr, init)
  }) as unknown as typeof fetch
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const oneFile = [
  { name: 'a.txt', path: 'a.txt', isDir: false, isSymlink: false, size: 5, mtime: '2026-05-14T10:00:00Z' },
]

function setLayered(payloads: { list?: any[]; preview?: any; props?: any }) {
  fetchHandler = async (url) => {
    if (url.includes('/api/agent/workspace/list')) {
      return new Response(JSON.stringify({ entries: payloads.list ?? oneFile }), { status: 200 })
    }
    if (url.includes('/api/agent/workspace/preview')) {
      return new Response(JSON.stringify(payloads.preview ?? {
        path: 'a.txt', content: 'OLD-CONTENT', isBinary: false,
        truncated: false, mime: 'text/plain', size: 11,
      }), { status: 200 })
    }
    if (url.includes('/api/agent/workspace/properties')) {
      return new Response(JSON.stringify(payloads.props ?? {
        path: 'a.txt', type: 'file', size: 5,
        mtime: '2026-05-14T10:00:00+00:00', mode: '0o666',
        sha256: 'STALEHASHFROMOLDPROJECT',
      }), { status: 200 })
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  }
}


// =============================================================================
// (1) Stale preview survives drawer close+reopen
// =============================================================================

describe('FileSystemDrawer Stage C: stale preview on reopen', () => {
  test('closing then reopening the drawer must clear preview state', async () => {
    setLayered({})
    const { rerender } = render(
      <FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />
    )
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByText('a.txt'))
    await waitFor(() => expect(screen.getByText(/OLD-CONTENT/)).toBeInTheDocument())

    // Close
    rerender(<FileSystemDrawer isOpen={false} onClose={() => {}} projectId="p1" />)
    // Reopen
    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)

    // Listing visible, preview must NOT be (stale from previous session)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    expect(screen.queryByText(/OLD-CONTENT/)).not.toBeInTheDocument()
    expect(screen.queryByTitle('Back to files')).not.toBeInTheDocument()
  })

  test('closing then reopening must clear properties modal', async () => {
    setLayered({})
    const { rerender } = render(
      <FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />
    )
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByTitle(/Properties/))
    await waitFor(() => expect(screen.getByText('Properties')).toBeInTheDocument())

    rerender(<FileSystemDrawer isOpen={false} onClose={() => {}} projectId="p1" />)
    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)

    // Properties modal should be gone on reopen
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    expect(screen.queryByText('Properties')).not.toBeInTheDocument()
  })
})


// =============================================================================
// (2) Switching project clears stale preview/properties
// =============================================================================

describe('FileSystemDrawer Stage C: projectId switch clears state', () => {
  test('changing projectId while open clears any open preview', async () => {
    setLayered({})
    const { rerender } = render(
      <FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />
    )
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByText('a.txt'))
    await waitFor(() => expect(screen.getByText(/OLD-CONTENT/)).toBeInTheDocument())

    // Now switch to a different project. Listing for p2 still returns oneFile
    // (in the mock) but the preview is from p1 and must NOT carry over.
    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p2" />)

    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    expect(screen.queryByText(/OLD-CONTENT/)).not.toBeInTheDocument()
  })

  test('changing projectId while open clears any open properties', async () => {
    setLayered({})
    const { rerender } = render(
      <FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />
    )
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByTitle(/Properties/))
    await waitFor(() => expect(screen.getByText(/STALEHASHFROMOLDPROJECT/)).toBeInTheDocument())

    rerender(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p2" />)

    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    expect(screen.queryByText(/STALEHASHFROMOLDPROJECT/)).not.toBeInTheDocument()
  })
})


// =============================================================================
// (3) Tab switch preserves preview (intended UX - regression lock)
// =============================================================================

describe('FileSystemDrawer Stage C: tab switch preserves preview', () => {
  test('switching to Jobs and back keeps the preview open', async () => {
    setLayered({})
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByText('a.txt'))
    await waitFor(() => expect(screen.getByText(/OLD-CONTENT/)).toBeInTheDocument())

    fireEvent.click(screen.getByText('Jobs'))
    await waitFor(() => expect(screen.getByText('No background jobs.')).toBeInTheDocument())

    fireEvent.click(screen.getByText('Files'))
    // Preview still visible after returning to Files tab
    await waitFor(() => expect(screen.getByText(/OLD-CONTENT/)).toBeInTheDocument())
  })
})


// =============================================================================
// (4) Clicking same file twice fires preview each time (no memoization)
// =============================================================================

describe('FileSystemDrawer Stage C: re-clicking refetches', () => {
  test('preview fetch fires for each file click, even on the same file', async () => {
    setLayered({})
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getByText('a.txt'))
    await waitFor(() => expect(screen.getByText(/OLD-CONTENT/)).toBeInTheDocument())
    fireEvent.click(screen.getByTitle('Back to files'))
    await waitFor(() => expect(screen.queryByText(/OLD-CONTENT/)).not.toBeInTheDocument())

    // Click again - new fetch must fire (file might have changed since)
    const previewCallsBefore = fetchCalls.filter(c => c.url.includes('/workspace/preview')).length
    fireEvent.click(screen.getByText('a.txt'))
    await waitFor(() => {
      const previewCallsAfter = fetchCalls.filter(c => c.url.includes('/workspace/preview')).length
      expect(previewCallsAfter).toBe(previewCallsBefore + 1)
    })
  })
})
