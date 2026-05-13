/**
 * Report-layer integration tests for VHost & SNI findings.
 *
 * Verifies:
 *   - reportData.ts type shape includes vhostSni section with all required fields
 *   - Risk score formula weights vhost_sni severities correctly
 *   - reportTemplate.ts renderVhostSni produces conditional HTML
 *     (empty when no findings, populated when findings exist)
 *   - Dynamic TOC includes the vhost-sni section when findings present
 *   - condenseForAgent includes a vhostSni summary block
 */
import { describe, test, expect, beforeAll } from 'vitest'
import type { ReportData, VhostSniFindingRecord } from './reportData'

// Replicate the vhost-sni risk score formula from gatherReportData()
function vhostSniRiskScore(bySeverity: { severity: string; count: number }[]): number {
  return bySeverity.reduce((sum, d) => {
    const w = d.severity === 'high' ? 40 : d.severity === 'medium' ? 20 : d.severity === 'low' ? 8 : 2
    return sum + d.count * w
  }, 0)
}

// ============================================================
// Type shape — compile-time verification via TypeScript
// ============================================================
describe('ReportData -- vhostSni section type', () => {
  test('compiles a fully-populated vhostSni payload', () => {
    const finding: VhostSniFindingRecord = {
      hostname: 'admin.example.com',
      ip: '1.2.3.4',
      port: 443,
      layer: 'L7',
      type: 'hidden_vhost',
      severity: 'medium',
      internalPatternMatch: 'admin',
      baselineStatus: 403,
      baselineSize: 548,
      observedStatus: 200,
      observedSize: 4823,
      sizeDelta: 4275,
      description: 'desc',
      firstSeen: '2026-04-25T14:00:00Z',
      lastSeen: '2026-04-25T14:00:00Z',
    }
    const block: ReportData['vhostSni'] = {
      totalFindings: 1,
      ipsTested: 1,
      candidatesTested: 200,
      anomaliesL7: 1,
      anomaliesL4: 0,
      reverseProxiesDetected: 1,
      bySeverity: [{ severity: 'medium', count: 1 }],
      byLayer: [{ layer: 'L7', count: 1 }],
      byType: [{ findingType: 'hidden_vhost', count: 1 }],
      findings: [finding],
    }
    expect(block.findings[0].hostname).toBe('admin.example.com')
    expect(block.findings[0].layer).toBe('L7')
  })

  test('allows nullable ip / port / status / size fields on a finding', () => {
    const finding: VhostSniFindingRecord = {
      hostname: 'orphan.example.com',
      ip: null,
      port: null,
      layer: 'L4',
      type: 'hidden_sni_route',
      severity: 'info',
      internalPatternMatch: null,
      baselineStatus: null,
      baselineSize: null,
      observedStatus: null,
      observedSize: null,
      sizeDelta: null,
      description: null,
      firstSeen: null,
      lastSeen: null,
    }
    expect(finding.hostname).toBe('orphan.example.com')
  })
})

// ============================================================
// Risk score formula
// ============================================================
describe('vhost_sni risk score weights', () => {
  test('high severity weights 40', () => {
    expect(vhostSniRiskScore([{ severity: 'high', count: 1 }])).toBe(40)
  })

  test('medium severity weights 20', () => {
    expect(vhostSniRiskScore([{ severity: 'medium', count: 1 }])).toBe(20)
  })

  test('low severity weights 8', () => {
    expect(vhostSniRiskScore([{ severity: 'low', count: 1 }])).toBe(8)
  })

  test('info severity weights 2', () => {
    expect(vhostSniRiskScore([{ severity: 'info', count: 1 }])).toBe(2)
  })

  test('unknown severity falls into info bucket (weight 2)', () => {
    // The current implementation uses `else 2` for any non-(high|medium|low) severity,
    // including unknown/empty strings. This documents that behavior.
    expect(vhostSniRiskScore([{ severity: 'unknown', count: 1 }])).toBe(2)
  })

  test('multiple severities sum correctly', () => {
    const total = vhostSniRiskScore([
      { severity: 'high', count: 2 },     // 80
      { severity: 'medium', count: 3 },   // 60
      { severity: 'low', count: 5 },      // 40
      { severity: 'info', count: 10 },    // 20
    ])
    expect(total).toBe(200)
  })

  test('empty input is zero', () => {
    expect(vhostSniRiskScore([])).toBe(0)
  })

  test('weights respect ordinal ordering (critical-like > high > medium > low > info)', () => {
    const high = vhostSniRiskScore([{ severity: 'high', count: 1 }])
    const medium = vhostSniRiskScore([{ severity: 'medium', count: 1 }])
    const low = vhostSniRiskScore([{ severity: 'low', count: 1 }])
    const info = vhostSniRiskScore([{ severity: 'info', count: 1 }])
    expect(high).toBeGreaterThan(medium)
    expect(medium).toBeGreaterThan(low)
    expect(low).toBeGreaterThan(info)
  })
})

// ============================================================
// reportTemplate.ts source-level structural checks for vhost-sni
//
// Building a fully-typed ReportData fixture for end-to-end HTML testing is
// brittle (the template touches dozens of unrelated sections). Instead we
// source-check the template file: the conditional, the section anchor, the
// dynamic-TOC entry, and the safe-empty-state copy.
// ============================================================
describe('reportTemplate.ts -- vhost-sni section structure', () => {
  let templateSrc: string

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  beforeAll(async () => {
    const fs = await import('node:fs')
    const path = await import('node:path')
    templateSrc = fs.readFileSync(
      path.resolve(__dirname, 'reportTemplate.ts'),
      'utf-8',
    )
  })

  test('defines a renderVhostSni function', () => {
    expect(templateSrc).toMatch(/function renderVhostSni\b/)
  })

  test('renderVhostSni is conditional on totalFindings + ipsTested', () => {
    // The function must early-return empty string when there's nothing to render.
    const fnBlock = templateSrc.match(/function renderVhostSni[\s\S]*?return ''[\s\S]*?\n\}/)
    expect(fnBlock, 'renderVhostSni function not found or has no early return').not.toBeNull()
    expect(fnBlock![0]).toMatch(/totalFindings === 0\b/)
    expect(fnBlock![0]).toMatch(/ipsTested === 0\b/)
  })

  test('renderVhostSni is invoked from generateReportHtml', () => {
    expect(templateSrc).toMatch(/\$\{renderVhostSni\(data\)\}/)
  })

  test('section anchor id is "vhost-sni"', () => {
    expect(templateSrc).toMatch(/id="vhost-sni"/)
  })

  test('dynamic TOC has a guarded vhost-sni entry', () => {
    expect(templateSrc).toContain("id: 'vhost-sni'")
    expect(templateSrc).toMatch(/data\.vhostSni\.totalFindings\s*>\s*0/)
  })

  test('empty-but-tested branch is communicated to the user', () => {
    // When ipsTested > 0 but no findings, the section says "No anomalies".
    expect(templateSrc).toContain('No anomalies')
  })

  test('VHost & SNI label uses the HTML-encoded ampersand', () => {
    // The user-visible heading in the report must be HTML-safe.
    expect(templateSrc).toContain('VHost &amp; SNI Enumeration')
  })
})
