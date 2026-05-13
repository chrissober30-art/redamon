/**
 * Regression tests for FireteamMemberCard timeline rendering order.
 *
 * ## The bug
 *
 * `FireteamMemberCardProps.member` carries TWO parallel arrays:
 *  - `member.planWaves`: PlanWaveItem[] (multi-tool plan waves)
 *  - `member.tools`: ToolExecutionItem[] (standalone single-tool calls)
 *
 * Pre-fix the component rendered these in **fixed JSX order**:
 *   1. all `member.planWaves`
 *   2. then all `member.tools`
 *
 * That meant a plan wave created LATER than a standalone tool would
 * appear ABOVE the older standalone tool in the UI — breaking the
 * operator's chronological mental model of what the member did.
 *
 * The fix merges both arrays into a single list, sorts by `timestamp`
 * ascending (oldest first, same convention as the rest of the timeline),
 * and renders in that order.
 *
 * Run:
 *   cd webapp && npx vitest run \
 *     src/app/graph/components/AIAssistantDrawer/FireteamMemberCardTimelineOrder.test.tsx
 */

import React from 'react'
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { FireteamMemberCard } from './FireteamMemberCard'
import type {
  ToolExecutionItem,
  PlanWaveItem,
} from './AgentTimeline'
import type { FireteamMemberPanel } from './types'

afterEach(cleanup)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeTool(
  overrides: Partial<ToolExecutionItem> = {},
): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: `tool-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date('2026-05-11T17:00:00Z'),
    tool_name: 'execute_curl',
    tool_args: { url: 'https://example.com' },
    status: 'running',
    output_chunks: [],
    ...overrides,
  }
}

function makeWave(
  overrides: Partial<PlanWaveItem> = {},
): PlanWaveItem {
  return {
    type: 'plan_wave',
    id: `wave-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date('2026-05-11T17:00:00Z'),
    wave_id: `wid-${Math.random().toString(36).slice(2, 6)}`,
    plan_rationale: 'parallel recon',
    tool_count: 0,
    tools: [],
    status: 'running',
    ...overrides,
  }
}

function makeMember(
  overrides: Partial<FireteamMemberPanel> = {},
): FireteamMemberPanel {
  return {
    member_id: 'm1',
    name: 'Vulnerability Scanner',
    task: 'scan target',
    skills: [],
    status: 'running',
    started_at: new Date('2026-05-11T17:00:00Z'),
    tools: [],
    planWaves: [],
    iterations_used: 0,
    tokens_used: 0,
    input_tokens_used: 0,
    output_tokens_used: 0,
    findings_count: 0,
    ...overrides,
  }
}

/** Return ALL tool_name / plan_rationale labels in their DOM render order. */
function readRenderedOrder(): string[] {
  // The body of the card is collapsed by default — open it.
  // Each PlanWaveCard / ToolExecutionCard exposes its tool_name text in
  // the args/title area. We use the `data-testid` shortcut: every card
  // bears its id as a key, but the visible identity is the tool_name (for
  // standalone) or "Wave — N tools" header (for plan_wave). Easier and
  // more robust is to walk the rendered timeline by .timeline / .waves
  // / .tools / .body class structure, but jsdom doesn't expose
  // module-CSS scoped names directly. Instead we read the DOM tree
  // top-down and pull recognizable headers in source order.
  const all = Array.from(
    document.querySelectorAll('*'),
  ) as HTMLElement[]
  const labels: string[] = []
  for (const el of all) {
    const txt = el.textContent || ''
    // Plan wave header: "Wave — 2 tools" / "Wave — 1 tools"
    if (/^Wave — \d+ tool/.test(el.childNodes[0]?.textContent || '')) {
      labels.push(`wave:${el.childNodes[0]?.textContent}`)
    }
  }
  return labels
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FireteamMemberCard — timeline order', () => {
  test('REGRESSION: a wave created AFTER a standalone tool renders BELOW it (chronological)', () => {
    // Construct: standalone tool at T0, then a plan wave at T0 + 5min.
    const earlyTool = makeTool({
      id: 'tool-old',
      tool_name: 'execute_httpx',
      timestamp: new Date('2026-05-11T17:00:00Z'),
    })
    const lateWave = makeWave({
      id: 'wave-new',
      plan_rationale: 'nuclei + ffuf parallel',
      timestamp: new Date('2026-05-11T17:05:00Z'),
      tools: [makeTool({ tool_name: 'execute_nuclei', timestamp: new Date('2026-05-11T17:05:00Z') })],
      tool_count: 1,
    })
    const member = makeMember({
      tools: [earlyTool],
      planWaves: [lateWave],
    })

    render(<FireteamMemberCard member={member} />)

    // Expand the member panel.
    fireEvent.click(screen.getByText(/Vulnerability Scanner/))

    // Now find the tool card (by its tool_name text) and the wave card
    // (by its plan_rationale text) and assert tool appears BEFORE wave
    // in document order.
    const earlyEl = screen.getByText(/execute_httpx/)
    const lateEl = screen.getByText(/nuclei \+ ffuf parallel/)
    const pos = earlyEl.compareDocumentPosition(lateEl)
    // Node.DOCUMENT_POSITION_FOLLOWING = 4
    expect(pos & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  test('REGRESSION (mirror): a standalone tool created AFTER a wave renders BELOW it', () => {
    const earlyWave = makeWave({
      id: 'wave-old',
      plan_rationale: 'subfinder + amass passive',
      timestamp: new Date('2026-05-11T17:00:00Z'),
    })
    const lateTool = makeTool({
      id: 'tool-new',
      tool_name: 'execute_kali_shell',
      timestamp: new Date('2026-05-11T17:05:00Z'),
    })
    const member = makeMember({
      planWaves: [earlyWave],
      tools: [lateTool],
    })

    render(<FireteamMemberCard member={member} />)
    fireEvent.click(screen.getByText(/Vulnerability Scanner/))

    const earlyEl = screen.getByText(/subfinder \+ amass passive/)
    const lateEl = screen.getByText(/execute_kali_shell/)
    const pos = earlyEl.compareDocumentPosition(lateEl)
    expect(pos & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  test('mixed sequence of three items renders strictly by timestamp', () => {
    const t0 = new Date('2026-05-11T17:00:00Z')
    const t1 = new Date('2026-05-11T17:01:00Z')
    const t2 = new Date('2026-05-11T17:02:00Z')

    const member = makeMember({
      tools: [
        makeTool({ tool_name: 'execute_httpx', timestamp: t0 }),
        makeTool({ tool_name: 'kali_shell',  timestamp: t2 }),
      ],
      planWaves: [
        makeWave({
          plan_rationale: 'middle wave - dns enumeration',
          timestamp: t1,
        }),
      ],
    })

    render(<FireteamMemberCard member={member} />)
    fireEvent.click(screen.getByText(/Vulnerability Scanner/))

    const a = screen.getByText(/execute_httpx/)
    const b = screen.getByText(/middle wave - dns enumeration/)
    const c = screen.getByText(/kali_shell/)

    expect(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(b.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  test('empty member (no tools, no waves) still renders without crash', () => {
    const member = makeMember({ tools: [], planWaves: [] })
    render(<FireteamMemberCard member={member} />)
    // Just the header — no tools/waves region.
    expect(screen.getByText(/Vulnerability Scanner/)).toBeTruthy()
  })

  test('member with only standalone tools renders them in timestamp order', () => {
    const member = makeMember({
      tools: [
        makeTool({ tool_name: 'first_tool',  timestamp: new Date('2026-05-11T17:00:00Z') }),
        makeTool({ tool_name: 'second_tool', timestamp: new Date('2026-05-11T17:01:00Z') }),
      ],
    })
    render(<FireteamMemberCard member={member} />)
    fireEvent.click(screen.getByText(/Vulnerability Scanner/))
    const first = screen.getByText(/first_tool/)
    const second = screen.getByText(/second_tool/)
    expect(first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  test('member with only plan waves renders them in timestamp order', () => {
    const member = makeMember({
      planWaves: [
        makeWave({ plan_rationale: 'first wave plan',  timestamp: new Date('2026-05-11T17:00:00Z') }),
        makeWave({ plan_rationale: 'second wave plan', timestamp: new Date('2026-05-11T17:01:00Z') }),
      ],
    })
    render(<FireteamMemberCard member={member} />)
    fireEvent.click(screen.getByText(/Vulnerability Scanner/))
    const first = screen.getByText(/first wave plan/)
    const second = screen.getByText(/second wave plan/)
    expect(first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})
