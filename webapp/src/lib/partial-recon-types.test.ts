import { describe, test, expect } from 'vitest'
import {
  PARTIAL_RECON_SUPPORTED_TOOLS,
  PARTIAL_RECON_PHASES,
  PARTIAL_RECON_PHASE_MAP,
} from './recon-types'
import type {
  PartialReconStatus,
  PartialReconState,
  GraphInputs,
  PartialReconParams,
  UserTargets,
} from './recon-types'

// === PARTIAL_RECON_SUPPORTED_TOOLS ===
describe('PARTIAL_RECON_SUPPORTED_TOOLS', () => {
  test('contains SubdomainDiscovery', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SubdomainDiscovery')).toBe(true)
  })

  test('contains Naabu', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Naabu')).toBe(true)
  })

  test('contains Masscan', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Masscan')).toBe(true)
  })

  test('contains Nmap', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nmap')).toBe(true)
  })

  test('contains Httpx', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Httpx')).toBe(true)
  })

  test('contains Katana', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Katana')).toBe(true)
  })

  test('contains Hakrawler', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Hakrawler')).toBe(true)
  })

  test('does not contain unsupported tools', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nuclei')).toBe(false)
  })
})

// === PARTIAL_RECON_PHASE_MAP ===
describe('PARTIAL_RECON_PHASE_MAP', () => {
  test('has SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery'][0]).toBe('Subdomain Discovery')
  })

  test('has Naabu phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Naabu']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Naabu'][0]).toBe('Port Scanning')
  })

  test('has Masscan phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Masscan']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Masscan'][0]).toBe('Port Scanning')
  })

  test('has Nmap phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Nmap']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Nmap'][0]).toBe('Nmap Service Detection')
  })

  test('has Httpx phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Httpx']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Httpx'][0]).toBe('HTTP Probing')
  })

  test('has Katana phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Katana']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Katana'][0]).toBe('Resource Enumeration')
  })

  test('has Hakrawler phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Hakrawler']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Hakrawler'][0]).toBe('Resource Enumeration')
  })

  test('each supported tool has a phase entry', () => {
    for (const toolId of PARTIAL_RECON_SUPPORTED_TOOLS) {
      expect(PARTIAL_RECON_PHASE_MAP[toolId]).toBeDefined()
      expect(PARTIAL_RECON_PHASE_MAP[toolId].length).toBeGreaterThan(0)
    }
  })
})

// === PARTIAL_RECON_PHASES (backward compat) ===
describe('PARTIAL_RECON_PHASES', () => {
  test('defaults to SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASES).toHaveLength(1)
    expect(PARTIAL_RECON_PHASES[0]).toBe('Subdomain Discovery')
  })

  test('is an array', () => {
    expect(Array.isArray(PARTIAL_RECON_PHASES)).toBe(true)
  })
})

// === Type Shape Validation ===
describe('PartialReconState type shape', () => {
  test('default idle state has required fields', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'idle',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.project_id).toBe('proj-123')
    expect(state.status).toBe('idle')
    expect(state.stats).toBeNull()
  })

  test('completed state with stats', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'completed',
      container_id: 'abc123',
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:05:00Z',
      error: null,
      stats: { subdomains_total: 15, subdomains_new: 8, subdomains_existing: 7, ips_total: 12 },
    }
    expect(state.stats?.subdomains_new).toBe(8)
    expect(state.stats?.subdomains_existing).toBe(7)
  })

  test('error state with error message', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'error',
      container_id: null,
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:01:00Z',
      error: 'Container exited with code 1',
      stats: null,
    }
    expect(state.error).toBeTruthy()
  })
})

describe('PartialReconStatus values', () => {
  test.each<PartialReconStatus>([
    'idle', 'starting', 'running', 'completed', 'error', 'stopping',
  ])('accepts valid status: %s', (status) => {
    const state: PartialReconState = {
      project_id: 'p', tool_id: 't', status,
      container_id: null, started_at: null, completed_at: null, error: null, stats: null,
    }
    expect(state.status).toBe(status)
  })
})

describe('GraphInputs type shape', () => {
  test('from graph source', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 42,
      source: 'graph',
    }
    expect(inputs.source).toBe('graph')
    expect(inputs.existing_subdomains_count).toBe(42)
  })

  test('from settings fallback', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.source).toBe('settings')
    expect(inputs.existing_subdomains_count).toBe(0)
  })

  test('null domain when no data', () => {
    const inputs: GraphInputs = {
      domain: null,
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.domain).toBeNull()
  })

  test('with existing_ips_count for Naabu', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_ips_count).toBe(5)
  })

  test('with existing_ports_count for Nmap', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      existing_ports_count: 23,
      source: 'graph',
    }
    expect(inputs.existing_ports_count).toBe(23)
  })

  test('with existing_baseurls_count for Httpx', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      existing_ports_count: 23,
      existing_baseurls_count: 8,
      source: 'graph',
    }
    expect(inputs.existing_baseurls_count).toBe(8)
  })

  test('with existing_baseurls for Katana dropdown', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      existing_baseurls_count: 3,
      existing_baseurls: ['https://example.com', 'https://api.example.com', 'https://www.example.com'],
      source: 'graph',
    }
    expect(inputs.existing_baseurls).toHaveLength(3)
    expect(inputs.existing_baseurls).toContain('https://api.example.com')
  })
})

describe('PartialReconParams type shape', () => {
  test('minimal params', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('SubdomainDiscovery')
    expect(params.user_inputs).toHaveLength(0)
    expect(params.settings_overrides).toBeUndefined()
  })

  test('full params with user inputs and overrides', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: ['api.example.com', 'admin.example.com'],
      settings_overrides: { SUBFINDER_ENABLED: false },
    }
    expect(params.user_inputs).toHaveLength(2)
    expect(params.settings_overrides).toBeDefined()
  })

  test('Naabu params with structured user_targets', () => {
    const targets: UserTargets = {
      subdomains: ['api.example.com'],
      ips: ['10.0.0.1', '192.168.1.0/24'],
      ip_attach_to: 'api.example.com',
    }
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: targets,
    }
    expect(params.tool_id).toBe('Naabu')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(2)
    expect(params.user_targets?.ip_attach_to).toBe('api.example.com')
  })

  test('Naabu params with generic IPs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: [], ips: ['10.0.0.1'], ip_attach_to: null },
    }
    expect(params.user_targets?.ip_attach_to).toBeNull()
  })

  test('Naabu params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Nmap params with structured user_targets', () => {
    const params: PartialReconParams = {
      tool_id: 'Nmap',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: [], ips: ['10.0.0.1'], ip_attach_to: null, ports: [8443, 9090] },
    }
    expect(params.tool_id).toBe('Nmap')
    expect(params.user_targets?.ips).toHaveLength(1)
    expect(params.user_targets?.ip_attach_to).toBeNull()
    expect(params.user_targets?.ports).toHaveLength(2)
    expect(params.user_targets?.ports).toContain(8443)
  })

  test('Nmap params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Nmap',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Httpx params with structured user_targets', () => {
    const params: PartialReconParams = {
      tool_id: 'Httpx',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: ['api.example.com'], ips: [], ip_attach_to: null },
    }
    expect(params.tool_id).toBe('Httpx')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(0)
  })

  test('Httpx params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Httpx',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Masscan params with structured user_targets', () => {
    const targets: UserTargets = {
      subdomains: ['api.example.com'],
      ips: ['10.0.0.1', '192.168.1.0/24'],
      ip_attach_to: 'api.example.com',
    }
    const params: PartialReconParams = {
      tool_id: 'Masscan',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: targets,
    }
    expect(params.tool_id).toBe('Masscan')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(2)
    expect(params.user_targets?.ip_attach_to).toBe('api.example.com')
  })

  test('Katana params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com', 'https://api.example.com:8443'],
        url_attach_to: 'https://example.com',
      },
    }
    expect(params.tool_id).toBe('Katana')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBe('https://example.com')
  })

  test('Katana params with generic URLs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com'], url_attach_to: null,
      },
    }
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Katana params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Hakrawler params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Hakrawler',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com', 'https://api.example.com'],
        url_attach_to: null,
      },
    }
    expect(params.tool_id).toBe('Hakrawler')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Hakrawler params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Hakrawler',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })
})

describe('GraphInputs with existing_subdomains', () => {
  test('Naabu graph inputs include subdomain list', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 2,
      existing_subdomains: ['www.example.com', 'api.example.com'],
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_subdomains).toHaveLength(2)
    expect(inputs.existing_subdomains).toContain('api.example.com')
  })
})
