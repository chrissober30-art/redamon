/**
 * Unit tests for useUserPreferences hook.
 *
 * Run: npx vitest run src/hooks/useUserPreferences.test.tsx
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import {
  useUserPreferences,
  useNodeDetailsPrefs,
  useGraphTypeFilterPrefs,
  useGraphViewPrefs,
  useThemePref,
  GRAPH_VIEW_DEFAULTS,
} from './useUserPreferences'

// ---------------------------------------------------------------------------
// Test wrapper: fresh QueryClient per test (no shared cache between tests)
// ---------------------------------------------------------------------------

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

interface FetchCall {
  url: string
  init?: RequestInit
}

function installFetchMock(handler: (call: FetchCall) => Promise<Response>) {
  const calls: FetchCall[] = []
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    calls.push({ url: u, init })
    return handler({ url: u, init })
  })
  globalThis.fetch = fn
  return { fn, calls }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('useUserPreferences', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  test('hydrates prefs via GET /api/user/preferences on mount', async () => {
    const { calls } = installFetchMock(async ({ url }) => {
      if (url === '/api/user/preferences') {
        return jsonResponse({ nodeDetailsTable: { Domain: { hiddenColumns: ['x'] } } })
      }
      return new Response('not found', { status: 404 })
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })

    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.prefs).toEqual({
      nodeDetailsTable: { Domain: { hiddenColumns: ['x'] } },
    })
    expect(calls.filter(c => c.init?.method !== 'PATCH')).toHaveLength(1)
  })

  test('updatePref applies optimistic update immediately (before debounce fires)', async () => {
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && init?.method === 'PATCH') {
        return jsonResponse({ nodeDetailsTable: { Domain: { hiddenColumns: ['col1'] } } })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    await act(async () => {
      result.current.updatePref('nodeDetailsTable', {
        Domain: { hiddenColumns: ['col1'] },
      })
      // Flush React Query's observer notification microtask without advancing past debounce.
      await vi.advanceTimersByTimeAsync(0)
    })

    // Optimistic update is visible BEFORE the 400ms debounce fires.
    expect(result.current.prefs).toEqual({
      nodeDetailsTable: { Domain: { hiddenColumns: ['col1'] } },
    })
  })

  test('debounces multiple rapid updates into a single PATCH after 400ms', async () => {
    const { calls } = installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && init?.method === 'PATCH') {
        const body = JSON.parse(init.body as string)
        return jsonResponse({ [body.featureKey]: body.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    // 5 rapid updates within the debounce window
    act(() => {
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['a'] } })
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['a', 'b'] } })
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['a', 'b', 'c'] } })
      vi.advanceTimersByTime(100)
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['x'] } })
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['final'] } })
    })

    const patchesBefore = calls.filter(c => c.init?.method === 'PATCH')
    expect(patchesBefore).toHaveLength(0)

    // Advance past debounce
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    const patchesAfter = calls.filter(c => c.init?.method === 'PATCH')
    expect(patchesAfter).toHaveLength(1)
    const sentBody = JSON.parse(patchesAfter[0].init!.body as string)
    expect(sentBody.featureKey).toBe('nodeDetailsTable')
    // Only the LAST value should be sent (debouncing collapses)
    expect(sentBody.value).toEqual({ Domain: { hiddenColumns: ['final'] } })
  })

  test('separate featureKeys are debounced independently', async () => {
    const { calls } = installFetchMock(async ({ url, init }) => {
      if (init?.method === 'PATCH' && url === '/api/user/preferences') {
        const body = JSON.parse(init.body as string)
        return jsonResponse({ [body.featureKey]: body.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => {
      result.current.updatePref('featureA', { v: 1 })
      result.current.updatePref('featureB', { v: 2 })
    })

    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    const patches = calls.filter(c => c.init?.method === 'PATCH')
    expect(patches).toHaveLength(2)
    const keysSent = patches.map(p => JSON.parse(p.init!.body as string).featureKey).sort()
    expect(keysSent).toEqual(['featureA', 'featureB'])
  })

  test('PATCH failure does NOT roll back if a newer optimistic write is queued', async () => {
    vi.useRealTimers()
    let patchHits = 0
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({ nodeDetailsTable: { Domain: { hiddenColumns: ['orig'] } } })
      }
      if (init?.method === 'PATCH') {
        patchHits++
        // First PATCH fails (slow + 500), subsequent succeed
        if (patchHits === 1) {
          await new Promise(r => setTimeout(r, 100))
          return new Response('boom', { status: 500 })
        }
        const body = JSON.parse(init.body as string)
        return jsonResponse({ [body.featureKey]: body.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isLoading).toBe(false))

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    // First write (will fail)
    await act(async () => {
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['BAD'] } })
    })
    // Wait until that PATCH is in-flight (debounce fired)
    await waitFor(() => expect(patchHits).toBeGreaterThanOrEqual(1), { timeout: 1000 })

    // Queue a newer optimistic write while the first is still in-flight
    await act(async () => {
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['NEWER'] } })
    })

    // Wait for the second PATCH (which succeeds) to complete
    await waitFor(() => expect(patchHits).toBe(2), { timeout: 2000 })

    // Final state must be NEWER — the failed first PATCH must NOT clobber it
    await waitFor(() => {
      const next = result.current.prefs.nodeDetailsTable as { Domain: { hiddenColumns: string[] } }
      expect(next.Domain.hiddenColumns).toEqual(['NEWER'])
    }, { timeout: 1000 })

    errSpy.mockRestore()
  })

  test('PATCH failure rolls back the optimistic value', async () => {
    // Use real timers throughout this test — fake timers fight React Query's
    // observer-notification scheduling for the post-rollback re-render.
    vi.useRealTimers()

    let patchHits = 0
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({ nodeDetailsTable: { Domain: { hiddenColumns: ['orig'] } } })
      }
      if (init?.method === 'PATCH') {
        patchHits++
        return new Response('boom', { status: 500 })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useUserPreferences(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isLoading).toBe(false))

    // Suppress noisy console.error from rollback path
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    await act(async () => {
      result.current.updatePref('nodeDetailsTable', { Domain: { hiddenColumns: ['BAD'] } })
    })

    // Optimistic value visible immediately
    await waitFor(() => {
      const cur = result.current.prefs.nodeDetailsTable as { Domain: { hiddenColumns: string[] } }
      expect(cur.Domain.hiddenColumns).toEqual(['BAD'])
    })

    // Wait past 400ms debounce + fetch + rollback
    await waitFor(() => expect(patchHits).toBe(1), { timeout: 2000 })

    await waitFor(() => {
      const next = result.current.prefs.nodeDetailsTable as
        | { Domain: { hiddenColumns: string[] } }
        | undefined
      expect(next?.Domain?.hiddenColumns).toEqual(['orig'])
    }, { timeout: 2000 })

    errSpy.mockRestore()
  })
})

describe('useNodeDetailsPrefs', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  test('returns empty hidden list when nodeType has no entry', async () => {
    installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useNodeDetailsPrefs('Domain'), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.hiddenColumns).toEqual([]))
  })

  test('returns nodeType-specific hidden list', async () => {
    installFetchMock(async () =>
      jsonResponse({
        nodeDetailsTable: {
          Domain: { hiddenColumns: ['a', 'b'] },
          IP: { hiddenColumns: ['c'] },
        },
      })
    )
    const { result } = renderHook(() => useNodeDetailsPrefs('IP'), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.hiddenColumns).toEqual(['c']))
  })

  test('setHiddenColumns updates only the given nodeType subkey, preserving others', async () => {
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({
          nodeDetailsTable: {
            Domain: { hiddenColumns: ['origDomain'] },
            IP: { hiddenColumns: ['origIp'] },
          },
        })
      }
      if (init?.method === 'PATCH') {
        lastPatchBody = JSON.parse(init.body as string)
        return jsonResponse({ nodeDetailsTable: lastPatchBody!.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useNodeDetailsPrefs('Domain'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.hiddenColumns).toEqual(['origDomain']))

    act(() => {
      result.current.setHiddenColumns(['newCol1', 'newCol2'])
    })
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(lastPatchBody).not.toBeNull()
    expect(lastPatchBody!.featureKey).toBe('nodeDetailsTable')
    expect(lastPatchBody!.value).toEqual({
      Domain: { hiddenColumns: ['newCol1', 'newCol2'] },
      IP: { hiddenColumns: ['origIp'] }, // preserved!
    })
  })

  test('null nodeType is a no-op (does not throw, no PATCH)', async () => {
    const { calls } = installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useNodeDetailsPrefs(null), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.hiddenColumns).toEqual([]))

    act(() => {
      result.current.setHiddenColumns(['foo'])
    })
    await act(async () => {
      vi.advanceTimersByTime(1000)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0)
  })
})

describe('useGraphTypeFilterPrefs', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  test('returns empty hidden list when project has no saved entry', async () => {
    installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useGraphTypeFilterPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.hiddenTypes).toEqual([])
  })

  test('returns project-specific hidden types', async () => {
    installFetchMock(async () =>
      jsonResponse({
        graphTypeFilter: {
          'proj-1': { hiddenTypes: ['Vulnerability', 'AttackChain'] },
          'proj-2': { hiddenTypes: ['IP'] },
        },
      })
    )
    const { result } = renderHook(() => useGraphTypeFilterPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.hiddenTypes).toEqual(['Vulnerability', 'AttackChain']))
  })

  test('switching projectId returns the correct per-project hidden list from the same prefs cache', async () => {
    installFetchMock(async () =>
      jsonResponse({
        graphTypeFilter: {
          'proj-1': { hiddenTypes: ['A'] },
          'proj-2': { hiddenTypes: ['B', 'C'] },
        },
      })
    )

    const { result, rerender } = renderHook(
      ({ pid }: { pid: string }) => useGraphTypeFilterPrefs(pid),
      { wrapper: makeWrapper(), initialProps: { pid: 'proj-1' } }
    )
    await vi.waitFor(() => expect(result.current.hiddenTypes).toEqual(['A']))

    rerender({ pid: 'proj-2' })
    await vi.waitFor(() => expect(result.current.hiddenTypes).toEqual(['B', 'C']))
  })

  test('setHiddenTypes updates only the given project subkey, preserving others', async () => {
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({
          graphTypeFilter: {
            'proj-1': { hiddenTypes: ['origA'] },
            'proj-2': { hiddenTypes: ['origB'] },
          },
        })
      }
      if (init?.method === 'PATCH') {
        lastPatchBody = JSON.parse(init.body as string)
        return jsonResponse({ graphTypeFilter: lastPatchBody!.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useGraphTypeFilterPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.hiddenTypes).toEqual(['origA']))

    act(() => {
      result.current.setHiddenTypes(['Vulnerability'])
    })
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(lastPatchBody).not.toBeNull()
    expect(lastPatchBody!.featureKey).toBe('graphTypeFilter')
    expect(lastPatchBody!.value).toEqual({
      'proj-1': { hiddenTypes: ['Vulnerability'] },
      'proj-2': { hiddenTypes: ['origB'] }, // preserved!
    })
  })

  test('null projectId is a no-op (does not throw, no PATCH)', async () => {
    const { calls } = installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useGraphTypeFilterPrefs(null), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.hiddenTypes).toEqual([]))

    act(() => {
      result.current.setHiddenTypes(['Foo'])
    })
    await act(async () => {
      vi.advanceTimersByTime(1000)
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0)
  })

  test('exposes isLoading=true while initial GET is pending', async () => {
    let resolveGet!: (r: Response) => void
    installFetchMock(
      () =>
        new Promise<Response>(resolve => {
          resolveGet = resolve
        })
    )
    const { result } = renderHook(() => useGraphTypeFilterPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    expect(result.current.isLoading).toBe(true)

    resolveGet(jsonResponse({ graphTypeFilter: { 'proj-1': { hiddenTypes: ['Z'] } } }))
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.hiddenTypes).toEqual(['Z'])
  })
})

describe('useGraphViewPrefs', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  test('returns sensible defaults when project has no saved entry', async () => {
    installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useGraphViewPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.is3D).toBe(GRAPH_VIEW_DEFAULTS.is3D)
    expect(result.current.showLabels).toBe(GRAPH_VIEW_DEFAULTS.showLabels)
  })

  test('returns project-specific saved values', async () => {
    installFetchMock(async () =>
      jsonResponse({
        graphView: {
          'proj-1': { is3D: false, showLabels: false },
          'proj-2': { is3D: true, showLabels: true },
        },
      })
    )
    const { result } = renderHook(() => useGraphViewPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.is3D).toBe(false))
    expect(result.current.showLabels).toBe(false)
  })

  test('partial saved entry uses defaults for missing fields', async () => {
    installFetchMock(async () =>
      jsonResponse({
        graphView: {
          'proj-1': { is3D: false }, // showLabels missing → should default true
        },
      })
    )
    const { result } = renderHook(() => useGraphViewPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.is3D).toBe(false))
    expect(result.current.showLabels).toBe(true) // default
  })

  test('switching projectId returns the correct per-project saved values', async () => {
    installFetchMock(async () =>
      jsonResponse({
        graphView: {
          'proj-1': { is3D: false, showLabels: true },
          'proj-2': { is3D: true, showLabels: false },
        },
      })
    )
    const { result, rerender } = renderHook(
      ({ pid }: { pid: string }) => useGraphViewPrefs(pid),
      { wrapper: makeWrapper(), initialProps: { pid: 'proj-1' } }
    )
    await vi.waitFor(() => expect(result.current.is3D).toBe(false))
    expect(result.current.showLabels).toBe(true)

    rerender({ pid: 'proj-2' })
    await vi.waitFor(() => expect(result.current.is3D).toBe(true))
    expect(result.current.showLabels).toBe(false)
  })

  test('setIs3D persists only the is3D field, preserving showLabels for the project', async () => {
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({
          graphView: {
            'proj-1': { is3D: true, showLabels: false },
            'proj-2': { is3D: true, showLabels: true },
          },
        })
      }
      if (init?.method === 'PATCH') {
        lastPatchBody = JSON.parse(init.body as string)
        return jsonResponse({ graphView: lastPatchBody!.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useGraphViewPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    // Wait for isLoading=false rather than value=true, since true is also the
    // default — a value-based wait would falsely pass before the GET completes.
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => {
      result.current.setIs3D(false)
    })
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(lastPatchBody!.featureKey).toBe('graphView')
    expect(lastPatchBody!.value).toEqual({
      'proj-1': { is3D: false, showLabels: false }, // is3D updated, showLabels preserved
      'proj-2': { is3D: true, showLabels: true },   // other project untouched
    })
  })

  test('setShowLabels persists only the showLabels field', async () => {
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({
          graphView: { 'proj-1': { is3D: false, showLabels: true } },
        })
      }
      if (init?.method === 'PATCH') {
        lastPatchBody = JSON.parse(init.body as string)
        return jsonResponse({ graphView: lastPatchBody!.value })
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useGraphViewPrefs('proj-1'), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => {
      result.current.setShowLabels(false)
    })
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(lastPatchBody!.value).toEqual({
      'proj-1': { is3D: false, showLabels: false },
    })
  })

  test('null projectId returns defaults and is a no-op for setters (no PATCH)', async () => {
    const { calls } = installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useGraphViewPrefs(null), {
      wrapper: makeWrapper(),
    })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.is3D).toBe(GRAPH_VIEW_DEFAULTS.is3D)

    act(() => {
      result.current.setIs3D(false)
      result.current.setShowLabels(false)
    })
    await act(async () => {
      vi.advanceTimersByTime(1000)
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0)
  })
})

describe('useThemePref', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  test('returns null when no theme is saved', async () => {
    installFetchMock(async () => jsonResponse({}))
    const { result } = renderHook(() => useThemePref(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.theme).toBeNull()
  })

  test('returns saved theme value', async () => {
    installFetchMock(async () => jsonResponse({ theme: 'light' }))
    const { result } = renderHook(() => useThemePref(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.theme).toBe('light'))
  })

  test('returns null for invalid stored values (defensive)', async () => {
    installFetchMock(async () => jsonResponse({ theme: 'rainbow' }))
    const { result } = renderHook(() => useThemePref(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))
    expect(result.current.theme).toBeNull()
  })

  test('setTheme writes a flat top-level key (not project-scoped)', async () => {
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({ theme: 'dark', nodeDetailsTable: { keep: 'me' } })
      }
      if (init?.method === 'PATCH') {
        lastPatchBody = JSON.parse(init.body as string)
        return jsonResponse({})
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useThemePref(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.theme).toBe('dark'))

    act(() => {
      result.current.setTheme('light')
    })
    await act(async () => {
      vi.advanceTimersByTime(500)
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(lastPatchBody).toEqual({ featureKey: 'theme', value: 'light' })
  })

  test('accepts all three valid theme values', async () => {
    const patches: { featureKey: string; value: unknown }[] = []
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
        return jsonResponse({})
      }
      if (init?.method === 'PATCH') {
        patches.push(JSON.parse(init.body as string))
        return jsonResponse({})
      }
      return jsonResponse({})
    })

    const { result } = renderHook(() => useThemePref(), { wrapper: makeWrapper() })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    for (const t of ['light', 'dark', 'system'] as const) {
      act(() => {
        result.current.setTheme(t)
      })
      await act(async () => {
        vi.advanceTimersByTime(500)
        await vi.advanceTimersByTimeAsync(0)
      })
    }

    // Last patch should win per debounced featureKey — but each call here is
    // individually awaited past the debounce, so all three are sent.
    expect(patches.map(p => p.value)).toEqual(['light', 'dark', 'system'])
  })
})
