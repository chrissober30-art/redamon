/**
 * Tests for VHost & SNI integration into the recon preset surface.
 *
 * Verifies:
 *   - Zod schema accepts all 11 vhostSni* fields with correct types
 *   - Zod schema rejects invalid types
 *   - All "active" presets that should enable VHost/SNI actually do
 *   - "Passive" / stealth presets do NOT enable it
 *   - PRESET_EXCLUDED_FIELDS strips vhostSniCustomWordlist
 *   - RECON_PARAMETER_CATALOG documents every vhostSni* param
 */
import { describe, test, expect } from 'vitest'
import { reconPresetSchema, RECON_PARAMETER_CATALOG } from '../recon-preset-schema'
import { PRESET_EXCLUDED_FIELDS, extractPresetSettings } from '../project-preset-utils'

// Active-recon presets that explicitly enable VHost/SNI.
// Decision per preset is grounded in the preset's stated goal — see
// readmes/VHOST_SNI_DESIGN.md preset-decision table.
const PRESETS_WITH_VHOSTSNI_ENABLED = [
  // Originally enabled (active scan family)
  'subdomain-takeover',
  'bug-bounty-deep',
  'full-active-scan',
  'full-maximum-scan',
  'web-app-pentester',
  'red-team-operator',
  'cloud-exposure',
  'infrastructure-mapper',
  // Added after the second-pass per-preset audit
  'api-security',           // API gateways often hide behind reverse proxies + SNI routing
  'bug-bounty-quick',       // BB hunters want it (graph-only candidates for speed)
  'compliance-audit',       // host_header_bypass IS a compliance finding
  'cve-hunter',             // discovers more attack surface for CVE matching
  'directory-discovery',    // hidden vhosts = hidden HTTP surfaces
  'graphql-recon',          // GraphQL endpoints often live on internal vhosts
  'parameter-injection',    // synergistic — finds more endpoints to fuzz
  'secret-hunter',          // admin panels (hidden vhosts) often leak secrets
] as const

// Presets that EXPLICITLY disable VHost/SNI (stealth or passive-only identity).
const PRESETS_EXPLICIT_DISABLE = [
  'full-passive-scan',      // "no packets to target" — preset's identity
  'osint-investigator',     // "no active scanning"
  'stealth-recon',          // 2300+ probes through Tor = catastrophic
  'large-network',          // per-IP serial × thousands of IPs = days
] as const

// Presets that leave VHost/SNI at the default (false) — out-of-scope by intent.
const PRESETS_LEAVE_DEFAULT = [
  'dns-email-security',     // DNS/email-only, no web probing
  'secret-miner',           // pure JS analysis, no host discovery
] as const

const ALL_VHOSTSNI_FIELDS = [
  'vhostSniEnabled',
  'vhostSniTimeout',
  'vhostSniConcurrency',
  'vhostSniBaselineSizeTolerance',
  'vhostSniTestL7',
  'vhostSniTestL4',
  'vhostSniInjectDiscovered',
  'vhostSniUseDefaultWordlist',
  'vhostSniUseGraphCandidates',
  'vhostSniMaxCandidatesPerIp',
  'vhostSniCustomWordlist',
] as const

// ===========================================================================
// 1. Zod schema acceptance / rejection
// ===========================================================================
describe('reconPresetSchema -- vhostSni fields', () => {
  test('accepts all 11 fields with valid values', () => {
    const result = reconPresetSchema.safeParse({
      vhostSniEnabled: true,
      vhostSniTimeout: 5,
      vhostSniConcurrency: 30,
      vhostSniBaselineSizeTolerance: 100,
      vhostSniTestL7: true,
      vhostSniTestL4: false,
      vhostSniInjectDiscovered: true,
      vhostSniUseDefaultWordlist: false,
      vhostSniUseGraphCandidates: true,
      vhostSniMaxCandidatesPerIp: 5000,
      vhostSniCustomWordlist: 'admin\nstaging',
    })
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.vhostSniEnabled).toBe(true)
      expect(result.data.vhostSniTimeout).toBe(5)
      expect(result.data.vhostSniCustomWordlist).toBe('admin\nstaging')
    }
  })

  test('rejects non-boolean for vhostSniEnabled', () => {
    const result = reconPresetSchema.safeParse({ vhostSniEnabled: 'yes' })
    expect(result.success).toBe(false)
  })

  test('rejects non-integer for vhostSniTimeout', () => {
    const result = reconPresetSchema.safeParse({ vhostSniTimeout: 'fast' })
    expect(result.success).toBe(false)
  })

  test('rejects non-string for vhostSniCustomWordlist', () => {
    const result = reconPresetSchema.safeParse({ vhostSniCustomWordlist: ['admin', 'staging'] })
    expect(result.success).toBe(false)
  })

  test('strips unknown vhost-related fields silently', () => {
    const result = reconPresetSchema.safeParse({
      vhostSniEnabled: true,
      vhostSniNonExistentField: 42,
    })
    expect(result.success).toBe(true)
    if (result.success) {
      expect((result.data as Record<string, unknown>).vhostSniNonExistentField).toBeUndefined()
    }
  })

  test('all 11 fields are optional (each works in isolation)', () => {
    for (const field of ALL_VHOSTSNI_FIELDS) {
      const result = reconPresetSchema.safeParse({ [field]: getTestValueFor(field) })
      expect(result.success, `Field "${field}" should be optional and accept its test value`).toBe(true)
    }
  })
})

function getTestValueFor(field: string): unknown {
  if (field === 'vhostSniCustomWordlist') return 'foo'
  if (field.endsWith('Enabled') || field.endsWith('L7') || field.endsWith('L4')
      || field.includes('Use') || field.includes('Inject')) return true
  return 1  // numeric default for the int fields
}

// ===========================================================================
// 2. RECON_PARAMETER_CATALOG documents every vhostSni* param
// ===========================================================================
describe('RECON_PARAMETER_CATALOG -- vhostSni coverage', () => {
  test('catalog mentions every vhostSni* param', () => {
    for (const field of ALL_VHOSTSNI_FIELDS) {
      expect(RECON_PARAMETER_CATALOG, `catalog missing entry: ${field}`).toContain(field)
    }
  })

  test('catalog has dedicated VHost & SNI section header', () => {
    expect(RECON_PARAMETER_CATALOG).toMatch(/##\s*VHost.*SNI/i)
  })
})

// ===========================================================================
// 3. PRESET_EXCLUDED_FIELDS strips the per-project custom wordlist
// ===========================================================================
describe('PRESET_EXCLUDED_FIELDS', () => {
  test('contains vhostSniCustomWordlist', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('vhostSniCustomWordlist')).toBe(true)
  })

  test('extractPresetSettings strips vhostSniCustomWordlist but keeps vhostSniEnabled', () => {
    const formData = {
      vhostSniEnabled: true,
      vhostSniCustomWordlist: 'admin\nsecret',
      vhostSniTimeout: 5,
      naabuEnabled: true,
    }
    const stripped = extractPresetSettings(formData) as Record<string, unknown>
    expect(stripped.vhostSniEnabled).toBe(true)
    expect(stripped.vhostSniTimeout).toBe(5)
    expect(stripped.naabuEnabled).toBe(true)
    expect(stripped.vhostSniCustomWordlist).toBeUndefined()
  })

  test('does NOT exclude any other vhostSni* setting', () => {
    for (const field of ALL_VHOSTSNI_FIELDS) {
      if (field === 'vhostSniCustomWordlist') continue
      expect(
        PRESET_EXCLUDED_FIELDS.has(field),
        `Field ${field} should be portable across projects, not excluded`,
      ).toBe(false)
    }
  })
})

// ===========================================================================
// 4. Active presets enable VHost/SNI; passive/stealth don't
// ===========================================================================
describe('Recon preset content -- vhost_sni enablement', () => {
  // Use eager dynamic imports so vitest discovers them
  const presetModules: Record<string, () => Promise<{ default?: unknown } & Record<string, unknown>>> = {
    // Explicitly enabled
    'subdomain-takeover': () => import('./presets/subdomain-takeover'),
    'bug-bounty-deep': () => import('./presets/bug-bounty-deep'),
    'full-active-scan': () => import('./presets/full-active-scan'),
    'full-maximum-scan': () => import('./presets/full-maximum-scan'),
    'web-app-pentester': () => import('./presets/web-app-pentester'),
    'red-team-operator': () => import('./presets/red-team-operator'),
    'cloud-exposure': () => import('./presets/cloud-exposure'),
    'infrastructure-mapper': () => import('./presets/infrastructure-mapper'),
    'api-security': () => import('./presets/api-security'),
    'bug-bounty-quick': () => import('./presets/bug-bounty-quick'),
    'compliance-audit': () => import('./presets/compliance-audit'),
    'cve-hunter': () => import('./presets/cve-hunter'),
    'directory-discovery': () => import('./presets/directory-discovery'),
    'graphql-recon': () => import('./presets/graphql-recon'),
    'parameter-injection': () => import('./presets/parameter-injection'),
    'secret-hunter': () => import('./presets/secret-hunter'),
    // Explicitly disabled
    'full-passive-scan': () => import('./presets/full-passive-scan'),
    'osint-investigator': () => import('./presets/osint-investigator'),
    'large-network': () => import('./presets/large-network'),
    'stealth-recon': () => import('./presets/stealth-recon'),
    // Leave default
    'dns-email-security': () => import('./presets/dns-email-security'),
    'secret-miner': () => import('./presets/secret-miner'),
  }

  // Helper -- return the first object value found in a module (a preset
  // file exports one named const).
  function findPresetExport(mod: Record<string, unknown>): Record<string, unknown> | null {
    for (const [, value] of Object.entries(mod)) {
      if (value && typeof value === 'object' && 'parameters' in (value as Record<string, unknown>)) {
        return value as Record<string, unknown>
      }
    }
    return null
  }

  for (const id of PRESETS_WITH_VHOSTSNI_ENABLED) {
    test(`${id} enables vhostSni`, async () => {
      const mod = await presetModules[id]()
      const preset = findPresetExport(mod)
      expect(preset, `${id}: no preset export found`).not.toBeNull()
      const params = preset!.parameters as Record<string, unknown>
      expect(params.vhostSniEnabled, `${id} should enable vhostSni`).toBe(true)
    })
  }

  for (const id of PRESETS_EXPLICIT_DISABLE) {
    test(`${id} EXPLICITLY disables vhostSni (preset identity)`, async () => {
      const mod = await presetModules[id]()
      const preset = findPresetExport(mod)
      expect(preset, `${id}: no preset export found`).not.toBeNull()
      const params = preset!.parameters as Record<string, unknown>
      // Must be explicit false — these presets define themselves by being safe
      // for hostile/passive contexts. Relying on the schema default would let
      // a future default-flip silently break the contract.
      expect(params.vhostSniEnabled, `${id} must explicitly set vhostSniEnabled: false`).toBe(false)
    })
  }

  for (const id of PRESETS_LEAVE_DEFAULT) {
    test(`${id} leaves vhostSni at default (out-of-scope by intent)`, async () => {
      const mod = await presetModules[id]()
      const preset = findPresetExport(mod)
      if (!preset) return
      const params = preset.parameters as Record<string, unknown>
      // Must NOT set vhostSniEnabled — the preset's narrow focus makes it
      // irrelevant. Any opinion on enable/disable would be noise.
      expect(params.vhostSniEnabled).toBeUndefined()
    })
  }
})

// ===========================================================================
// 5. RECON_PARAMETER_CATALOG sanity bullet for each param
// ===========================================================================
describe('Catalog descriptions are non-trivial', () => {
  test('every vhostSni* line has a description body', () => {
    const lines = RECON_PARAMETER_CATALOG.split('\n')
    const vhostLines = lines.filter(l => l.includes('vhostSni'))
    expect(vhostLines.length).toBeGreaterThanOrEqual(ALL_VHOSTSNI_FIELDS.length)
    for (const line of vhostLines) {
      // Pattern is: "- fieldName: type - description"
      expect(line, `catalog line too terse: "${line}"`).toMatch(/[A-Za-z]/)
      expect(line.length).toBeGreaterThan(40)
    }
  })
})
