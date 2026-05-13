'use client'

import { useEffect, useRef } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { useThemePref } from '@/hooks/useUserPreferences'
import { useAuth } from '@/providers/AuthProvider'

/**
 * Bridges the localStorage-backed `useTheme` (fast cache, prevents FOUC) with
 * the DB-backed user-pref `theme`. Renders nothing.
 *
 *   DB → local: when user prefs load and contain a theme that differs from
 *               what the DOM is currently showing, apply it.
 *   local → DB: when the resolved theme on the DOM changes (i.e., the user
 *               clicked ThemeToggle), persist the new value to the DB.
 *
 * Implementation note: `useTheme.theme` (the user preference) is per-hook-
 * instance state — toggling in ThemeToggle does NOT update other useTheme
 * instances' `theme` value. What DOES propagate across instances is
 * `resolvedTheme`, which is kept in sync via a MutationObserver on the
 * `<html data-theme>` attribute. So the bridge watches `resolvedTheme`.
 *
 * Trade-off: we persist the resolved 'light' | 'dark' rather than the user's
 * 'system' preference. ThemeToggle only offers dark↔light anyway, so 'system'
 * isn't reachable from the UI today; if a future UI surfaces it, this bridge
 * needs to switch to a shared store (or watch localStorage) to capture it.
 */
export function ThemeDbBridge() {
  const { user } = useAuth()
  const { resolvedTheme, setTheme } = useTheme()
  const { theme: dbTheme, isLoading, setTheme: setDbTheme } = useThemePref()
  const initialSyncDone = useRef(false)
  const lastSyncedToDb = useRef<'light' | 'dark' | null>(null)

  // Single effect handles both directions to avoid a same-pass race where the
  // local→DB branch would see a stale resolvedTheme right after the DB→local
  // branch called setTheme, and would fire a redundant PATCH for the OLD value.
  useEffect(() => {
    if (!user || isLoading) return

    if (!initialSyncDone.current) {
      // First sync: DB → local. If the saved theme differs, apply it; the
      // ensuing DOM mutation re-runs this effect with the new resolvedTheme.
      if (dbTheme && dbTheme !== resolvedTheme) {
        setTheme(dbTheme)
      }
      lastSyncedToDb.current =
        dbTheme === 'light' || dbTheme === 'dark'
          ? dbTheme
          : (resolvedTheme as 'light' | 'dark')
      initialSyncDone.current = true
      return
    }

    // Subsequent: local → DB. Triggered by a DOM data-theme change (user
    // clicking ThemeToggle elsewhere → MutationObserver in useTheme updates
    // this instance's resolvedTheme).
    if (resolvedTheme === lastSyncedToDb.current) return
    lastSyncedToDb.current = resolvedTheme as 'light' | 'dark'
    setDbTheme(resolvedTheme as 'light' | 'dark')
  }, [user, isLoading, dbTheme, resolvedTheme, setTheme, setDbTheme])

  return null
}
