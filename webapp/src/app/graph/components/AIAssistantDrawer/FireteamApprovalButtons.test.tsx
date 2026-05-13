/**
 * Regression tests for the Allow/Deny buttons on fireteam member approval
 * cards.
 *
 * Bug (pre-fix, PR #106 territory): `toolConfirmationDisabled` was prop-
 * drilled from ChatArea bound to the global `isLoading` flag. In single-
 * agent mode `isLoading` flips to `false` when the WS sends
 * TOOL_CONFIRMATION_REQUEST, so the buttons were enabled. In fireteam
 * mode the dedicated FIRETEAM_MEMBER_AWAITING_CONFIRMATION handler does
 * NOT touch isLoading (other members keep streaming in parallel by
 * design), so isLoading stayed `true` and the Allow/Deny buttons of the
 * pending member's card were permanently disabled — operator could not
 * approve.
 *
 * Fix: removed the entire `toolConfirmationDisabled` / `confirmationDisabled`
 * prop chain (ChatArea → AgentTimeline → FireteamCard → FireteamMemberCard
 * → PlanWaveCard / ToolExecutionCard). The existing `status === 'pending_approval'`
 * status-based render gate at every level is sufficient to keep the buttons
 * out of unrelated states; the global isLoading was never the right signal
 * for a per-card per-member confirmation.
 *
 * These tests pin the post-fix behavior so the disabled binding can't
 * sneak back in.
 *
 * Run:
 *   cd webapp && npx vitest run src/app/graph/components/AIAssistantDrawer/FireteamApprovalButtons.test.tsx
 */

import React from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { PlanWaveCard } from './PlanWaveCard'
import { ToolExecutionCard } from './ToolExecutionCard'
import type { ToolExecutionItem, PlanWaveItem } from './AgentTimeline'

afterEach(cleanup)

function makeTool(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: `tool-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    tool_name: 'execute_nuclei',
    tool_args: { target: 'example.com' },
    status: 'pending_approval',
    output_chunks: [],
    ...overrides,
  }
}

function makeWave(overrides: Partial<PlanWaveItem> = {}): PlanWaveItem {
  return {
    type: 'plan_wave',
    id: `wave-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    wave_id: 'wave-1-abc',
    plan_rationale: 'fireteam member escalation',
    tool_count: 1,
    tools: [makeTool()],
    status: 'pending_approval',
    isFireteamEscalation: true,
    ...overrides,
  }
}

describe('PlanWaveCard Allow/Deny buttons (fireteam member approval)', () => {
  test('renders Allow + Deny when status === pending_approval AND onApprove is provided', () => {
    render(
      <PlanWaveCard
        item={makeWave()}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    expect(screen.getByRole('button', { name: /^allow$/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^deny$/i })).toBeTruthy()
  })

  test('REGRESSION: Allow button is NOT disabled — pre-fix it was permanently disabled in fireteam mode', () => {
    render(
      <PlanWaveCard
        item={makeWave()}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    const allow = screen.getByRole('button', { name: /^allow$/i }) as HTMLButtonElement
    const deny = screen.getByRole('button', { name: /^deny$/i }) as HTMLButtonElement
    expect(allow.disabled).toBe(false)
    expect(deny.disabled).toBe(false)
  })

  test('clicking Allow fires onApprove and does NOT toggle expand (stopPropagation)', () => {
    const onApprove = vi.fn()
    const onToggleExpand = vi.fn()
    render(
      <PlanWaveCard
        item={makeWave()}
        isExpanded={false}
        onToggleExpand={onToggleExpand}
        onApprove={onApprove}
        onReject={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /^allow$/i }))
    expect(onApprove).toHaveBeenCalledTimes(1)
    expect(onToggleExpand).not.toHaveBeenCalled()
  })

  test('clicking Deny fires onReject and does NOT toggle expand', () => {
    const onReject = vi.fn()
    const onToggleExpand = vi.fn()
    render(
      <PlanWaveCard
        item={makeWave()}
        isExpanded={false}
        onToggleExpand={onToggleExpand}
        onApprove={vi.fn()}
        onReject={onReject}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /^deny$/i }))
    expect(onReject).toHaveBeenCalledTimes(1)
    expect(onToggleExpand).not.toHaveBeenCalled()
  })

  test('does NOT render Allow/Deny when status !== pending_approval', () => {
    render(
      <PlanWaveCard
        item={makeWave({ status: 'running' })}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    expect(screen.queryByRole('button', { name: /^allow$/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^deny$/i })).toBeNull()
  })

  test('does NOT render Allow/Deny when onApprove is not provided (status-based gating at parent)', () => {
    render(
      <PlanWaveCard
        item={makeWave()}
        isExpanded={false}
        onToggleExpand={() => {}}
      />,
    )
    expect(screen.queryByRole('button', { name: /^allow$/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^deny$/i })).toBeNull()
  })
})

describe('ToolExecutionCard Allow/Deny buttons (single-tool approval)', () => {
  test('renders Allow + Deny when status === pending_approval AND onApprove is provided', () => {
    render(
      <ToolExecutionCard
        item={makeTool()}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    expect(screen.getByRole('button', { name: /^allow$/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^deny$/i })).toBeTruthy()
  })

  test('REGRESSION: Allow + Deny are NOT disabled', () => {
    render(
      <ToolExecutionCard
        item={makeTool()}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    const allow = screen.getByRole('button', { name: /^allow$/i }) as HTMLButtonElement
    const deny = screen.getByRole('button', { name: /^deny$/i }) as HTMLButtonElement
    expect(allow.disabled).toBe(false)
    expect(deny.disabled).toBe(false)
  })

  test('clicking Allow fires onApprove', () => {
    const onApprove = vi.fn()
    render(
      <ToolExecutionCard
        item={makeTool()}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={onApprove}
        onReject={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /^allow$/i }))
    expect(onApprove).toHaveBeenCalledTimes(1)
  })

  test('does NOT render Allow/Deny when status === running', () => {
    render(
      <ToolExecutionCard
        item={makeTool({ status: 'running' })}
        isExpanded={false}
        onToggleExpand={() => {}}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />,
    )
    expect(screen.queryByRole('button', { name: /^allow$/i })).toBeNull()
  })
})
