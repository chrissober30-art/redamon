/**
 * Smoke + integration tests for ThemeDbBridge.
 *
 * Run: npx vitest run src/components/ThemeDbBridge/ThemeDbBridge.test.tsx
 *
 * Verifies:
 *   - DB → local: applying a saved theme on first prefs load updates the DOM
 *   - local → DB: changing the data-theme attribute (simulating a user click
 *     in a separate ThemeToggle) triggers a PATCH with the new value
 *   - No PATCH is fired if the user is not signed in
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, waitFor, cleanup, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { ThemeDbBridge } from './ThemeDbBridge'
import { AuthProvider } from '@/providers/AuthProvider'

// ---------------------------------------------------------------------------
// Test wrapper: AuthProvider + fresh QueryClient
// ---------------------------------------------------------------------------

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
    },
  })
  return ({ children }: { children: ReactNode }) =>
    createElement(
      QueryClientProvider,
      { client },
      createElement(AuthProvider, null, children)
    )
}

interface FetchCall {
  url: string
  init?: RequestInit
}

function installFetchMock(handler: (call: FetchCall) => Promise<Response>) {
  const calls: FetchCall[] = []
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    calls.push({ url: u, init })
    return handler({ url: u, init })
  }) as typeof fetch
  return { calls }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function setDomTheme(theme: 'light' | 'dark') {
  document.documentElement.setAttribute('data-theme', theme)
}

function getDomTheme(): string | null {
  return document.documentElement.getAttribute('data-theme')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ThemeDbBridge', () => {
  beforeEach(() => {
    // jsdom doesn't implement matchMedia — useTheme calls it during init.
    if (!window.matchMedia) {
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: vi.fn().mockImplementation((query: string) => ({
          matches: false,
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        })),
      })
    }
    // Start each test with a clean DOM theme + clean localStorage
    setDomTheme('dark')
    localStorage.clear()
  })

  afterEach(() => {
    cleanup()
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('renders nothing (returns null)', () => {
    installFetchMock(async () => new Response('', { status: 401 }))
    const { container } = render(<ThemeDbBridge />, { wrapper: makeWrapper() })
    expect(container.innerHTML).toBe('')
  })

  test('skips both syncs when no user is signed in', async () => {
    const { calls } = installFetchMock(async ({ url }) => {
      if (url === '/api/auth/me') return new Response('', { status: 401 })
      if (url === '/api/user/preferences') return jsonResponse({ theme: 'light' })
      return new Response('', { status: 404 })
    })

    render(<ThemeDbBridge />, { wrapper: makeWrapper() })

    // Auth check should fire once and resolve to no user
    await waitFor(() => expect(calls.some(c => c.url === '/api/auth/me')).toBe(true))

    // Even if we change DOM theme, no PATCH should be sent
    act(() => setDomTheme('light'))
    await new Promise(r => setTimeout(r, 600)) // past debounce
    expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0)
    // DOM unchanged by bridge (still whatever we set)
    expect(getDomTheme()).toBe('light')
  })

  test('DB → local: applies saved theme to the DOM on first load', async () => {
    setDomTheme('dark') // current DOM
    installFetchMock(async ({ url }) => {
      if (url === '/api/auth/me') {
        return jsonResponse({ id: 'u1', name: 'u', email: 'u@e', role: 'standard' })
      }
      if (url === '/api/user/preferences') return jsonResponse({ theme: 'light' })
      return new Response('', { status: 404 })
    })

    render(<ThemeDbBridge />, { wrapper: makeWrapper() })

    // Bridge should detect dbTheme=light != resolvedTheme=dark and apply it
    await waitFor(() => expect(getDomTheme()).toBe('light'), { timeout: 2000 })
  })

  test('does NOT overwrite DOM when saved theme matches current resolved', async () => {
    setDomTheme('dark')
    const { calls } = installFetchMock(async ({ url }) => {
      if (url === '/api/auth/me') {
        return jsonResponse({ id: 'u1', name: 'u', email: 'u@e', role: 'standard' })
      }
      if (url === '/api/user/preferences') return jsonResponse({ theme: 'dark' })
      return new Response('', { status: 404 })
    })

    render(<ThemeDbBridge />, { wrapper: makeWrapper() })

    // Wait for prefs GET to fire so the bridge sees dbTheme
    await waitFor(() =>
      expect(calls.some(c => c.url === '/api/user/preferences' && (!c.init?.method || c.init.method === 'GET'))).toBe(true)
    )
    await new Promise(r => setTimeout(r, 100))

    expect(getDomTheme()).toBe('dark') // unchanged
    // No PATCH (no change to send)
    await new Promise(r => setTimeout(r, 600))
    expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0)
  })

  test('local → DB: persists a DOM theme change after initial sync', async () => {
    setDomTheme('dark')
    let lastPatchBody: { featureKey: string; value: unknown } | null = null
    installFetchMock(async ({ url, init }) => {
      if (url === '/api/auth/me') {
        return jsonResponse({ id: 'u1', name: 'u', email: 'u@e', role: 'standard' })
      }
      if (url === '/api/user/preferences') {
        if (!init?.method || init.method === 'GET') {
          return jsonResponse({ theme: 'dark' }) // matches current
        }
        if (init.method === 'PATCH') {
          lastPatchBody = JSON.parse(init.body as string)
          return jsonResponse({ theme: lastPatchBody!.value })
        }
      }
      return new Response('', { status: 404 })
    })

    render(<ThemeDbBridge />, { wrapper: makeWrapper() })

    // Wait for initial sync to complete
    await waitFor(() => expect(lastPatchBody).toBeNull())
    await new Promise(r => setTimeout(r, 100))

    // Simulate a ThemeToggle click — flips data-theme attribute
    act(() => setDomTheme('light'))

    // The MutationObserver inside useTheme is async; allow time to fire +
    // 400ms debounce in updatePref + fetch roundtrip.
    await waitFor(() => expect(lastPatchBody).not.toBeNull(), { timeout: 2000 })
    expect(lastPatchBody!.featureKey).toBe('theme')
    expect(lastPatchBody!.value).toBe('light')
  })

  test('local → DB: only one PATCH for the same value (no spam)', async () => {
    setDomTheme('dark')
    const { calls } = installFetchMock(async ({ url, init }) => {
      if (url === '/api/auth/me') {
        return jsonResponse({ id: 'u1', name: 'u', email: 'u@e', role: 'standard' })
      }
      if (url === '/api/user/preferences') {
        if (!init?.method || init.method === 'GET') return jsonResponse({ theme: 'dark' })
        if (init.method === 'PATCH') return jsonResponse({})
      }
      return new Response('', { status: 404 })
    })

    render(<ThemeDbBridge />, { wrapper: makeWrapper() })
    await waitFor(() =>
      expect(calls.some(c => c.url === '/api/user/preferences' && (!c.init?.method || c.init.method === 'GET'))).toBe(true)
    )
    await new Promise(r => setTimeout(r, 100))

    // Three rapid toggles to the SAME final value
    act(() => setDomTheme('light'))
    act(() => setDomTheme('dark'))
    act(() => setDomTheme('light'))

    await new Promise(r => setTimeout(r, 700)) // past debounce

    const patches = calls.filter(c => c.init?.method === 'PATCH')
    // Debouncing should collapse to ONE PATCH carrying the final value
    expect(patches).toHaveLength(1)
    expect(JSON.parse(patches[0].init!.body as string).value).toBe('light')
  })
})
