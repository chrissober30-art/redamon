'use client'

import { useCallback, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'

export type UiPreferences = Record<string, unknown>

const QUERY_KEY = ['user-preferences'] as const
const DEBOUNCE_MS = 400

async function fetchPrefs(): Promise<UiPreferences> {
  const res = await fetch('/api/user/preferences')
  if (!res.ok) throw new Error(`Failed to load preferences (${res.status})`)
  const data = await res.json()
  return (data ?? {}) as UiPreferences
}

async function patchPref(featureKey: string, value: unknown): Promise<UiPreferences> {
  const res = await fetch('/api/user/preferences', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ featureKey, value }),
  })
  if (!res.ok) throw new Error(`Failed to update preference (${res.status})`)
  return (await res.json()) as UiPreferences
}

export function useUserPreferences() {
  const queryClient = useQueryClient()
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())
  const pendingValuesRef = useRef<Map<string, unknown>>(new Map())

  const query = useQuery({
    queryKey: QUERY_KEY,
    queryFn: fetchPrefs,
    staleTime: 60_000,
    notifyOnChangeProps: ['data', 'error', 'isLoading'],
  })

  const prefs: UiPreferences = (query.data ?? {}) as UiPreferences

  const updatePref = useCallback(
    (featureKey: string, valueOrUpdater: unknown | ((prev: unknown) => unknown)) => {
      const current = (queryClient.getQueryData(QUERY_KEY) ?? {}) as UiPreferences
      const prevValue = current[featureKey]
      const nextValue =
        typeof valueOrUpdater === 'function'
          ? (valueOrUpdater as (prev: unknown) => unknown)(prevValue)
          : valueOrUpdater

      // Optimistic local update
      queryClient.setQueryData(QUERY_KEY, { ...current, [featureKey]: nextValue })
      pendingValuesRef.current.set(featureKey, nextValue)

      // Debounced PATCH per featureKey
      const existingTimer = timersRef.current.get(featureKey)
      if (existingTimer) clearTimeout(existingTimer)

      const timer = setTimeout(async () => {
        const valueToSend = pendingValuesRef.current.get(featureKey)
        pendingValuesRef.current.delete(featureKey)
        timersRef.current.delete(featureKey)
        try {
          const updated = await patchPref(featureKey, valueToSend)
          queryClient.setQueryData(QUERY_KEY, updated)
        } catch (error) {
          console.error(`Failed to persist preference "${featureKey}":`, error)
          // Rollback only if no newer write is queued for this featureKey.
          // (A subsequent updatePref call would have repopulated pendingValuesRef.)
          if (pendingValuesRef.current.has(featureKey)) return
          const stillCurrent = (queryClient.getQueryData(QUERY_KEY) ?? {}) as UiPreferences
          queryClient.setQueryData(QUERY_KEY, { ...stillCurrent, [featureKey]: prevValue })
        }
      }, DEBOUNCE_MS)
      timersRef.current.set(featureKey, timer)
    },
    [queryClient]
  )

  // Flush any pending writes on unmount
  useEffect(() => {
    const timers = timersRef.current
    return () => {
      timers.forEach(t => clearTimeout(t))
      timers.clear()
    }
  }, [])

  return { prefs, isLoading: query.isLoading, error: query.error, updatePref }
}

// ---- Feature-specific helpers ---------------------------------------------

const NODE_DETAILS_KEY = 'nodeDetailsTable'

interface NodeDetailsTablePrefs {
  [nodeType: string]: { hiddenColumns?: string[] }
}

export function useNodeDetailsPrefs(nodeType: string | null) {
  const { prefs, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[NODE_DETAILS_KEY] ?? {}) as NodeDetailsTablePrefs
  const hiddenColumns = nodeType ? featurePrefs[nodeType]?.hiddenColumns ?? [] : []

  const setHiddenColumns = useCallback(
    (next: string[]) => {
      if (!nodeType) return
      updatePref(NODE_DETAILS_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as NodeDetailsTablePrefs
        return { ...prevObj, [nodeType]: { ...prevObj[nodeType], hiddenColumns: next } }
      })
    },
    [nodeType, updatePref]
  )

  return { hiddenColumns, setHiddenColumns }
}

// ---- Graph node-type filter (bottom-bar chips) ---------------------------

const GRAPH_TYPE_FILTER_KEY = 'graphTypeFilter'

interface GraphTypeFilterPrefs {
  [projectId: string]: { hiddenTypes?: string[] }
}

/**
 * Per-project persistent set of node types the user has hidden via the
 * bottom-bar filter chips. Stored as HIDDEN (not visible) so newly discovered
 * types default to visible without any DB write.
 *
 * Returns isLoading so callers can defer first-render hydration of derived
 * state (e.g., activeNodeTypes) until prefs have loaded — otherwise the user's
 * saved selection is briefly overwritten by "all visible".
 */
export function useGraphTypeFilterPrefs(projectId: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[GRAPH_TYPE_FILTER_KEY] ?? {}) as GraphTypeFilterPrefs
  const hiddenTypes = projectId ? featurePrefs[projectId]?.hiddenTypes ?? [] : []

  const setHiddenTypes = useCallback(
    (next: string[]) => {
      if (!projectId) return
      updatePref(GRAPH_TYPE_FILTER_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as GraphTypeFilterPrefs
        return { ...prevObj, [projectId]: { ...prevObj[projectId], hiddenTypes: next } }
      })
    },
    [projectId, updatePref]
  )

  return { hiddenTypes, setHiddenTypes, isLoading }
}

// ---- Graph view toggles (2D/3D, labels) — per-project per-user -----------

const GRAPH_VIEW_KEY = 'graphView'

interface GraphViewPrefs {
  [projectId: string]: { is3D?: boolean; showLabels?: boolean }
}

export const GRAPH_VIEW_DEFAULTS = { is3D: true, showLabels: true } as const

/**
 * Per-project persistent values for the 2D/3D mode and label visibility
 * toggles. Defaults to { is3D: true, showLabels: true } when not yet set.
 */
export function useGraphViewPrefs(projectId: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[GRAPH_VIEW_KEY] ?? {}) as GraphViewPrefs
  const projectPrefs = projectId ? featurePrefs[projectId] : undefined
  const is3D = projectPrefs?.is3D ?? GRAPH_VIEW_DEFAULTS.is3D
  const showLabels = projectPrefs?.showLabels ?? GRAPH_VIEW_DEFAULTS.showLabels

  const writeProjectPref = useCallback(
    (patch: { is3D?: boolean; showLabels?: boolean }) => {
      if (!projectId) return
      updatePref(GRAPH_VIEW_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as GraphViewPrefs
        return { ...prevObj, [projectId]: { ...prevObj[projectId], ...patch } }
      })
    },
    [projectId, updatePref]
  )

  const setIs3D = useCallback((v: boolean) => writeProjectPref({ is3D: v }), [writeProjectPref])
  const setShowLabels = useCallback(
    (v: boolean) => writeProjectPref({ showLabels: v }),
    [writeProjectPref]
  )

  return { is3D, showLabels, setIs3D, setShowLabels, isLoading }
}

// ---- Theme — per-user only (no project scope) ----------------------------

const THEME_KEY = 'theme'

export type PersistedTheme = 'light' | 'dark' | 'system'

/**
 * Reads/writes the theme from user prefs. Used by the theme DB bridge to keep
 * localStorage (fast cache, prevents FOUC) and the DB (cross-device source of
 * truth) in sync. The actual application of the theme to the DOM stays in
 * `useTheme` — this hook is purely persistence.
 */
export function useThemePref() {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const stored = prefs[THEME_KEY]
  const theme: PersistedTheme | null =
    stored === 'light' || stored === 'dark' || stored === 'system' ? stored : null

  const setTheme = useCallback(
    (next: PersistedTheme) => {
      updatePref(THEME_KEY, next)
    },
    [updatePref]
  )

  return { theme, setTheme, isLoading }
}
