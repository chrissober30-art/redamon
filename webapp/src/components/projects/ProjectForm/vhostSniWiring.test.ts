/**
 * Wiring tests for VhostSni in the project-form / workflow-graph layer.
 *
 * Verifies:
 *   - WORKFLOW_TOOLS has VhostSni in group 6 with badge="active"
 *   - SECTION_INPUT_MAP / SECTION_NODE_MAP / SECTION_ENRICH_MAP point at
 *     existing-only node types (no new labels)
 *   - PARTIAL_RECON_SUPPORTED_TOOLS contains 'VhostSni'
 *   - PARTIAL_RECON_PHASE_MAP['VhostSni'] returns a non-empty phase list
 *   - INPUT_LOGIC_TOOLTIPS has a VhostSni entry referencing the right node names
 */
import { describe, test, expect } from 'vitest'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { INPUT_LOGIC_TOOLTIPS } from './WorkflowView/inputLogicTooltips'
import { PARTIAL_RECON_SUPPORTED_TOOLS, PARTIAL_RECON_PHASE_MAP } from '@/lib/recon-types'

const EXISTING_NODE_TYPES = new Set([
  'Domain', 'Subdomain', 'IP', 'Port', 'Service', 'DNSRecord', 'Certificate',
  'BaseURL', 'Endpoint', 'Parameter', 'Header',
  'Technology', 'Vulnerability', 'CVE', 'MitreData', 'Capec',
  'ThreatPulse', 'Malware', 'ExploitGvm', 'Traceroute',
  'ExternalDomain', 'Secret', 'UserInput',
  'GithubHunt', 'GithubRepository', 'GithubPath', 'GithubSecret', 'GithubSensitiveFile',
])

describe('WORKFLOW_TOOLS -- VhostSni entry', () => {
  const tool = WORKFLOW_TOOLS.find(t => t.id === 'VhostSni')

  test('is registered', () => {
    expect(tool).toBeDefined()
  })

  test('has user-readable label', () => {
    expect(tool!.label).toBe('VHost & SNI')
  })

  test('enabledField matches Prisma camelCase column', () => {
    expect(tool!.enabledField).toBe('vhostSniEnabled')
  })

  test('lives in group 6 alongside Nuclei + GraphqlScan + SubdomainTakeover', () => {
    expect(tool!.group).toBe(6)
    const siblings = WORKFLOW_TOOLS.filter(t => t.group === 6).map(t => t.id)
    expect(siblings).toEqual(expect.arrayContaining(['Nuclei', 'GraphqlScan', 'SubdomainTakeover', 'VhostSni']))
  })

  test('badge is "active" (sends real traffic)', () => {
    expect(tool!.badge).toBe('active')
  })
})

describe('nodeMapping -- VhostSni I/O', () => {
  test('inputs include all 7 expected sources', () => {
    const inputs = SECTION_INPUT_MAP.VhostSni
    expect(inputs).toEqual(expect.arrayContaining([
      'Subdomain', 'IP', 'Port', 'BaseURL', 'Certificate', 'DNSRecord', 'ExternalDomain',
    ]))
  })

  test('outputs include Vulnerability + BaseURL + Subdomain', () => {
    const outputs = SECTION_NODE_MAP.VhostSni
    expect(outputs).toEqual(expect.arrayContaining(['Vulnerability', 'BaseURL', 'Subdomain']))
  })

  test('enriches Subdomain + IP', () => {
    const enriched = SECTION_ENRICH_MAP.VhostSni
    expect(enriched).toEqual(expect.arrayContaining(['Subdomain', 'IP']))
  })

  test('all referenced node types are existing labels (no new labels introduced)', () => {
    const referenced = new Set([
      ...(SECTION_INPUT_MAP.VhostSni || []),
      ...(SECTION_NODE_MAP.VhostSni || []),
      ...(SECTION_ENRICH_MAP.VhostSni || []),
    ])
    for (const t of referenced) {
      expect(EXISTING_NODE_TYPES.has(t), `Unknown node label: ${t}`).toBe(true)
    }
  })
})

describe('Partial Recon registration -- VhostSni', () => {
  test('PARTIAL_RECON_SUPPORTED_TOOLS contains VhostSni', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('VhostSni')).toBe(true)
  })

  test('PARTIAL_RECON_PHASE_MAP has a non-empty phase list for VhostSni', () => {
    const phases = PARTIAL_RECON_PHASE_MAP.VhostSni
    expect(phases).toBeDefined()
    expect(phases!.length).toBeGreaterThan(0)
    expect(phases![0].toLowerCase()).toMatch(/vhost|sni/)
  })
})

describe('INPUT_LOGIC_TOOLTIPS -- VhostSni', () => {
  test('has a tooltip entry', () => {
    expect(INPUT_LOGIC_TOOLTIPS.VhostSni).toBeDefined()
  })

  test('tooltip references the Vulnerability node by name (output transformation)', () => {
    // ReactNode -> stringify by walking children. Cheap path: render to JSON.
    const json = JSON.stringify(INPUT_LOGIC_TOOLTIPS.VhostSni)
    expect(json).toMatch(/Vulnerability/)
  })

  test('tooltip mentions both layers (L7 + L4)', () => {
    const json = JSON.stringify(INPUT_LOGIC_TOOLTIPS.VhostSni)
    expect(json).toContain('L7')
    expect(json).toContain('L4')
  })

  test('tooltip avoids em dashes (style guide)', () => {
    const json = JSON.stringify(INPUT_LOGIC_TOOLTIPS.VhostSni)
    expect(json).not.toContain('—')
  })

  test('tooltip mentions the BaseURL output (downstream tools rely on it)', () => {
    const json = JSON.stringify(INPUT_LOGIC_TOOLTIPS.VhostSni)
    expect(json).toMatch(/BaseURL/)
  })
})
