'use client'

import { Sparkles, Info } from 'lucide-react'

/**
 * Shared label renderer for AI-feature toggles.
 *
 * Every AI hook in the project form (Target master, FFuf, Nuclei tags,
 * Nuclei FP filter, WAF classifier, Takeover classifier, ...) uses this
 * component so the visual treatment is consistent: a violet Sparkles icon
 * marks the row as an AI feature, the label sits in the middle, and the
 * description renders as a native title-attribute tooltip on the trailing
 * Info icon (cursor: help).
 *
 * Why native `title` instead of a custom tooltip component:
 * - Zero new dependencies, zero portal/positioning code.
 * - Screen readers pick it up via `aria-label`.
 * - Works inside scrollable containers without z-index gymnastics.
 *
 * The violet (#a78bfa, Tailwind violet-400) is the established "AI"
 * accent color in modern UIs; it stands out against both light and dark
 * surfaces and is the same hue used by Sparkles icons elsewhere in the
 * recon drawer.
 */
const AI_ACCENT = '#a78bfa'

export interface AiToggleLabelProps {
  label: string
  /**
   * Long description shown on hover. Should explain what the AI hook
   * does, when it fires, and what it replaces / augments. Plain text
   * only -- the browser's title tooltip strips formatting.
   */
  tooltip: string
  /** Visual size of the leading AI accent icon. Defaults to 14px. */
  iconSize?: number
}

export function AiToggleLabel({ label, tooltip, iconSize = 14 }: AiToggleLabelProps) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        flex: 1,
        minWidth: 0,
      }}
    >
      <Sparkles
        size={iconSize}
        style={{ color: AI_ACCENT, flexShrink: 0 }}
        aria-hidden
      />
      <span style={{ fontWeight: 500 }}>{label}</span>
      <span
        title={tooltip}
        aria-label={tooltip}
        style={{
          display: 'inline-flex',
          cursor: 'help',
          color: 'var(--text-muted, #888)',
          flexShrink: 0,
        }}
      >
        <Info size={Math.max(12, iconSize - 2)} aria-hidden />
      </span>
    </span>
  )
}
