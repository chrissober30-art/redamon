'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { Play, Loader2, ArrowRight } from 'lucide-react'
import { Modal } from '@/components/ui'
import type { GraphInputs, PartialReconParams, UserTargets } from '@/lib/recon-types'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from '../nodeMapping'
import { WORKFLOW_TOOLS } from './workflowDefinition'

interface PartialReconModalProps {
  isOpen: boolean
  toolId: string | null
  onClose: () => void
  onConfirm: (params: PartialReconParams) => void
  projectId?: string
  targetDomain?: string
  subdomainPrefixes?: string[]
  isStarting?: boolean
}

const TOOL_DESCRIPTIONS: Record<string, string> = {
  SubdomainDiscovery:
    'Discovers subdomains using 5 tools in parallel (crt.sh, HackerTarget, Subfinder, Amass, Knockpy), ' +
    'filters wildcards with Puredns, then resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for each. ' +
    'Results are merged into the existing graph -- duplicates are updated, not recreated.',
  Naabu:
    'Scans discovered IPs and subdomains for open ports using Naabu (Docker-based). ' +
    'Targets are loaded from the graph (subdomains + IPs from prior discovery). ' +
    'You can also provide custom subdomains or IPs below. ' +
    'Port and Service nodes are merged into the existing graph -- duplicates are updated, not recreated.',
  Masscan:
    'High-speed SYN port scanner for large networks using raw SYN packets. ' +
    'Targets are loaded from the graph (IPs from prior discovery). ' +
    'You can also provide custom IPs below. ' +
    'Port and Service nodes are merged into the existing graph -- duplicates are updated, not recreated.',
  Nmap:
    'Runs Nmap service version detection (-sV) and NSE vulnerability scripts on ports already discovered by Naabu. ' +
    'Targets are loaded from the graph (IPs + open ports from prior port scanning). ' +
    'You can also provide custom subdomains or IPs below. ' +
    'Port, Service, Technology, Vulnerability, and CVE nodes are merged into the existing graph.',
  Httpx:
    'Probes HTTP services on discovered ports and subdomains using httpx. ' +
    'Detects live services, technologies, SSL/TLS certificates, and response metadata. ' +
    'Targets are loaded from the graph (IPs + ports from prior scanning, or subdomains on default ports). ' +
    'You can also provide custom subdomains below. ' +
    'BaseURL, Certificate, Technology, and Header nodes are merged into the existing graph.',
  Katana:
    'Crawls discovered BaseURLs using Katana to discover endpoints, parameters, and forms. ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
  Hakrawler:
    'Lightweight web crawler that discovers endpoints and links from BaseURLs using Hakrawler (Docker-based). ' +
    'Targets are loaded from the graph (BaseURLs from prior HTTP probing). ' +
    'You can also provide custom URLs below. ' +
    'Endpoint, Parameter, BaseURL, and ExternalDomain nodes are merged into the existing graph.',
}

// --- Validation helpers ---

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
const CIDR_V4_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
const CIDR_V6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/
const HOSTNAME_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

function validateIp(value: string): string | null {
  if (IPV4_RE.test(value)) {
    const octets = value.split('.').map(Number)
    if (octets.some(o => o > 255)) return `Invalid IP: ${value}`
    return null
  }
  if (IPV6_RE.test(value)) return null
  if (CIDR_V4_RE.test(value)) {
    const [ip, prefix] = value.split('/')
    const octets = ip.split('.').map(Number)
    if (octets.some(o => o > 255)) return `Invalid CIDR: ${value}`
    const pfx = parseInt(prefix, 10)
    if (pfx < 24 || pfx > 32) return `CIDR prefix must be /24 to /32, got /${pfx}`
    return null
  }
  if (CIDR_V6_RE.test(value)) {
    const prefix = parseInt(value.split('/')[1], 10)
    if (prefix < 120 || prefix > 128) return `IPv6 CIDR prefix must be /120 to /128, got /${prefix}`
    return null
  }
  return `Invalid IP or CIDR: ${value}`
}

function validatePort(value: string): string | null {
  const num = parseInt(value, 10)
  if (isNaN(num) || !Number.isInteger(num)) return `Not a valid port number: ${value}`
  if (num < 1 || num > 65535) return `Port must be 1-65535, got ${num}`
  return null
}

function validateUrl(value: string, projectDomain?: string): string | null {
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return `URL must use http or https: ${value}`
    if (!url.hostname) return `URL has no hostname: ${value}`
    // TODO: re-enable scope check after debug
    // if (projectDomain && !url.hostname.endsWith('.' + projectDomain) && url.hostname !== projectDomain) {
    //   return `${url.hostname} is out of scope (not a subdomain of ${projectDomain})`
    // }
    return null
  } catch {
    return `Invalid URL: ${value}`
  }
}

function validateSubdomain(value: string, projectDomain: string): string | null {
  if (!HOSTNAME_RE.test(value)) return `Invalid hostname: ${value}`
  if (projectDomain && !value.endsWith('.' + projectDomain) && value !== projectDomain) {
    return `${value} is not a subdomain of ${projectDomain}`
  }
  return null
}

function validateLines(text: string, validator: (v: string) => string | null) {
  if (!text.trim()) return { errors: [] as { line: number; error: string }[], validCount: 0 }
  const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
  const errors: { line: number; error: string }[] = []
  let validCount = 0
  lines.forEach((line, i) => {
    const err = validator(line)
    if (err) errors.push({ line: i + 1, error: err })
    else validCount++
  })
  return { errors, validCount }
}

// --- Shared inline styles ---

const textareaStyle = (hasError: boolean) => ({
  width: '100%',
  padding: '8px 10px',
  borderRadius: '6px',
  border: `1px solid ${hasError ? '#ef4444' : 'var(--border-color, #334155)'}`,
  backgroundColor: 'var(--bg-secondary, #1e293b)',
  color: 'var(--text-primary, #e2e8f0)',
  fontSize: '12px',
  fontFamily: 'monospace',
  resize: 'vertical' as const,
})

const labelStyle = { fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '4px' }
const hintStyle = { fontSize: '10px', color: 'var(--text-muted, #64748b)', marginTop: '2px' }
const errorListStyle = { marginTop: '4px', display: 'flex', flexDirection: 'column' as const, gap: '2px' }
const errorLineStyle = { fontSize: '10px', color: '#f87171' }

// --- Component ---

export function PartialReconModal({
  isOpen,
  toolId,
  onClose,
  onConfirm,
  projectId,
  targetDomain = '',
  subdomainPrefixes = [],
  isStarting = false,
}: PartialReconModalProps) {
  const [graphInputs, setGraphInputs] = useState<GraphInputs | null>(null)
  const [loadingInputs, setLoadingInputs] = useState(false)
  const [customSubdomains, setCustomSubdomains] = useState('')
  const [customIps, setCustomIps] = useState('')
  const [ipAttachTo, setIpAttachTo] = useState<string | null>(null)
  const [customPorts, setCustomPorts] = useState('')
  const [customUrls, setCustomUrls] = useState('')
  const [urlAttachTo, setUrlAttachTo] = useState<string | null>(null)
  const [includeGraphTargets, setIncludeGraphTargets] = useState(true)

  useEffect(() => {
    if (!isOpen || !toolId || !projectId) return
    setLoadingInputs(true)
    setCustomSubdomains('')
    setCustomIps('')
    setIpAttachTo(null)
    setCustomPorts('')
    setCustomUrls('')
    setUrlAttachTo(null)
    setIncludeGraphTargets(true)
    fetch(`/api/recon/${projectId}/graph-inputs/${toolId}`)
      .then(res => res.ok ? res.json() : null)
      .then((data: GraphInputs | null) => {
        setGraphInputs(data || { domain: targetDomain || null, existing_subdomains_count: 0, existing_ips_count: 0, existing_ports_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
      .catch(() => {
        setGraphInputs({ domain: targetDomain || null, existing_subdomains_count: 0, existing_ips_count: 0, existing_ports_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
  }, [isOpen, toolId, projectId, targetDomain])

  const domain = graphInputs?.domain || targetDomain || ''
  const isPortScanner = toolId === 'Naabu' || toolId === 'Masscan'
  const isNmap = toolId === 'Nmap'
  const isHttpx = toolId === 'Httpx'
  const isResourceEnum = toolId === 'Katana' || toolId === 'Hakrawler'
  const hasUserInputs = isPortScanner || isNmap || isHttpx || isResourceEnum
  const hasIpInput = isPortScanner || isNmap || isHttpx
  const hasSubdomainInput = toolId === 'Naabu' || isHttpx
  const hasPortInput = isNmap || isHttpx
  const hasUrlInput = isResourceEnum

  // Subdomain validation
  const subdomainValidation = useMemo(
    () => validateLines(customSubdomains, v => validateSubdomain(v, domain)),
    [customSubdomains, domain],
  )

  // IP validation
  const ipValidation = useMemo(
    () => validateLines(customIps, validateIp),
    [customIps],
  )

  // Port validation (Nmap only)
  const portValidation = useMemo(
    () => validateLines(customPorts, validatePort),
    [customPorts],
  )

  // URL validation (resource enum tools: Katana, Hakrawler) -- must be in project scope
  const urlValidation = useMemo(
    () => validateLines(customUrls, v => validateUrl(v, domain)),
    [customUrls, domain],
  )

  const hasValidationErrors = (hasSubdomainInput && subdomainValidation.errors.length > 0)
    || (hasIpInput && ipValidation.errors.length > 0)
    || (hasPortInput && portValidation.errors.length > 0)
    || (hasUrlInput && urlValidation.errors.length > 0)

  // Build dropdown options: graph subdomains + custom subdomains (live)
  const attachToOptions = useMemo(() => {
    const graphSubs = graphInputs?.existing_subdomains || []
    const customSubs = customSubdomains
      .split('\n')
      .map(s => s.trim().toLowerCase())
      .filter(s => s && HOSTNAME_RE.test(s) && (s.endsWith('.' + domain) || s === domain))
    // Deduplicate, graph first
    const seen = new Set<string>()
    const options: { value: string; label: string; source: string }[] = []
    for (const s of graphSubs) {
      if (!seen.has(s)) { seen.add(s); options.push({ value: s, label: s, source: 'graph' }) }
    }
    for (const s of customSubs) {
      if (!seen.has(s)) { seen.add(s); options.push({ value: s, label: s, source: 'custom' }) }
    }
    return options
  }, [graphInputs?.existing_subdomains, customSubdomains, domain])

  // Build dropdown options for URL attachment: existing BaseURLs from graph
  const urlAttachToOptions = useMemo(() => {
    const graphBaseUrls = graphInputs?.existing_baseurls || []
    return graphBaseUrls.map(u => ({ value: u, label: u }))
  }, [graphInputs?.existing_baseurls])

  // If selected attach_to was removed from options, reset to null
  useEffect(() => {
    if (ipAttachTo && !attachToOptions.some(o => o.value === ipAttachTo)) {
      setIpAttachTo(null)
    }
  }, [attachToOptions, ipAttachTo])

  useEffect(() => {
    if (urlAttachTo && !urlAttachToOptions.some(o => o.value === urlAttachTo)) {
      setUrlAttachTo(null)
    }
  }, [urlAttachToOptions, urlAttachTo])

  const handleRun = useCallback(() => {
    if (!domain || hasValidationErrors) return

    if (hasUserInputs) {
      const subdomains = hasSubdomainInput ? customSubdomains.split('\n').map(s => s.trim()).filter(Boolean) : []
      const ips = hasIpInput ? customIps.split('\n').map(s => s.trim()).filter(Boolean) : []
      const ports = hasPortInput ? customPorts.split('\n').map(s => s.trim()).filter(Boolean).map(Number).filter(n => n >= 1 && n <= 65535) : []
      const urls = hasUrlInput ? customUrls.split('\n').map(s => s.trim()).filter(Boolean) : []
      const hasCustomInput = subdomains.length || ips.length || ports.length || urls.length
      const userTargets: UserTargets | undefined = hasCustomInput
        ? {
            subdomains, ips, ip_attach_to: ipAttachTo,
            ...(ports.length ? { ports } : {}),
            ...(urls.length ? { urls, url_attach_to: urlAttachTo } : {}),
          }
        : undefined

      const params = {
        tool_id: toolId || '',
        graph_inputs: { domain },
        user_inputs: [],
        user_targets: userTargets,
        ...(includeGraphTargets ? {} : { include_graph_targets: false }),
      }
      console.log('[PartialReconModal] handleRun params:', JSON.stringify(params))
      onConfirm(params)
    } else {
      onConfirm({
        tool_id: toolId || '',
        graph_inputs: { domain },
        user_inputs: [],
        ...(includeGraphTargets ? {} : { include_graph_targets: false }),
      })
    }
  }, [domain, hasValidationErrors, hasUserInputs, hasSubdomainInput, hasIpInput, hasPortInput, hasUrlInput, isNmap, toolId, onConfirm, customSubdomains, customIps, ipAttachTo, customPorts, customUrls, urlAttachTo, includeGraphTargets])

  if (!isOpen || !toolId) return null

  const inputNodeTypes = SECTION_INPUT_MAP[toolId] || []
  const outputNodeTypes = SECTION_NODE_MAP[toolId] || []
  const enrichNodeTypes = SECTION_ENRICH_MAP[toolId] || []
  const hasNoGraphTargets = (isPortScanner && !loadingInputs && (graphInputs?.existing_ips_count ?? 0) === 0)
    || (isNmap && !loadingInputs && (graphInputs?.existing_ports_count ?? 0) === 0)
    || (isHttpx && !loadingInputs && (graphInputs?.existing_ports_count ?? 0) === 0 && (graphInputs?.existing_subdomains_count ?? 0) === 0)
    || (isResourceEnum && !loadingInputs && (graphInputs?.existing_baseurls_count ?? 0) === 0)
  const hasNoCustomTargets = (!hasSubdomainInput || !customSubdomains.trim()) && (!hasIpInput || !customIps.trim()) && !customPorts.trim() && (!hasUrlInput || !customUrls.trim())
  const noTargetsToScan = hasUserInputs && !includeGraphTargets && hasNoCustomTargets
  const nmapNoPorts = isNmap && !includeGraphTargets && !customPorts.trim()
  const httpxNoPorts = isHttpx && !includeGraphTargets && !customPorts.trim() && !customSubdomains.trim()
  const resourceEnumNoUrls = isResourceEnum && !includeGraphTargets && !customUrls.trim()

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Partial Recon: ${WORKFLOW_TOOLS.find(t => t.id === toolId)?.label || toolId}`}
      size="default"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Input / Output flow */}
        <div style={{ display: 'flex', alignItems: 'stretch', gap: '12px' }}>
          {/* Input */}
          <div style={{
            flex: 1, padding: '12px 14px', borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#3b82f6', marginBottom: '8px' }}>
              Input
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', marginBottom: '6px' }}>
              {inputNodeTypes.map(nt => (
                <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', fontWeight: 600 }}>{nt}</span>
              ))}
            </div>
            <div style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--text-primary, #e2e8f0)' }}>
              {loadingInputs ? 'Loading...' : isNmap
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_ports_count ?? 0} ports, ${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : isHttpx
                ? `${domain || 'No domain'} (${graphInputs?.existing_subdomains_count ?? 0} subdomains, ${graphInputs?.existing_ports_count ?? 0} ports, ${graphInputs?.existing_baseurls_count ?? 0} existing URLs)`
                : isResourceEnum
                ? `${domain || 'No domain'} (${graphInputs?.existing_baseurls_count ?? 0} BaseURLs)`
                : toolId === 'Naabu'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs, ${graphInputs?.existing_subdomains_count ?? 0} subdomains)`
                : toolId === 'Masscan'
                ? `${domain || 'No domain'} (${graphInputs?.existing_ips_count ?? 0} IPs)`
                : domain || 'No domain configured'}
            </div>
          </div>

          {/* Arrow */}
          <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
            <ArrowRight size={18} style={{ color: 'var(--text-muted, #64748b)' }} />
          </div>

          {/* Output */}
          <div style={{
            flex: 1, padding: '12px 14px', borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#22c55e', marginBottom: '8px' }}>
              Output
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {outputNodeTypes.map(nt => (
                <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', fontWeight: 600 }}>{nt}</span>
              ))}
            </div>
            {enrichNodeTypes.length > 0 && (
              <>
                <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#4ade80', marginTop: '8px', marginBottom: '4px', opacity: 0.7 }}>
                  Enriches
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {enrichNodeTypes.map(nt => (
                    <span key={nt} style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(34, 197, 94, 0.08)', color: '#4ade80', fontWeight: 600, borderStyle: 'dashed', border: '1px dashed rgba(34, 197, 94, 0.3)' }}>{nt}</span>
                  ))}
                </div>
              </>
            )}
            <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', marginTop: '6px' }}>
              New nodes merged into graph
            </div>
          </div>
        </div>

        {/* Tools info */}
        <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', lineHeight: '1.6' }}>
          {TOOL_DESCRIPTIONS[toolId] || 'Runs this pipeline phase independently and merges results into the existing graph.'}
        </div>

        {/* Include graph targets checkbox */}
        {hasUserInputs && (
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={includeGraphTargets}
              onChange={e => setIncludeGraphTargets(e.target.checked)}
              style={{ accentColor: '#3b82f6' }}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-primary, #e2e8f0)' }}>
              Include existing graph targets in scan
            </span>
          </label>
        )}

        {/* No targets warning */}
        {hasNoGraphTargets && includeGraphTargets && hasNoCustomTargets && (
          <div style={{
            fontSize: '11px', color: '#facc15', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.2)',
          }}>
            {isNmap
              ? 'No ports found in graph. Run Naabu first to discover open ports, or provide custom targets below.'
              : isHttpx
              ? 'No subdomains or ports found in graph. Run Subdomain Discovery + Port Scanning first, or provide custom subdomains below.'
              : isResourceEnum
              ? 'No BaseURLs found in graph. Run HTTP Probing (Httpx) first to discover live URLs, or provide custom URLs below.'
              : 'No IPs found in graph. Run Subdomain Discovery first to populate the graph, or provide custom targets below.'}
          </div>
        )}
        {noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Provide custom targets below or enable graph targets to run the scan.
          </div>
        )}
        {nmapNoPorts && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Nmap requires ports to scan. Provide custom ports below or enable graph targets (which include existing ports from Naabu/Masscan).
          </div>
        )}
        {httpxNoPorts && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            Httpx requires ports or subdomains to probe. Provide custom ports/IPs, custom subdomains (probed on default ports), or enable graph targets.
          </div>
        )}
        {resourceEnumNoUrls && !noTargetsToScan && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            {toolId} requires URLs to crawl. Provide custom URLs below or enable graph targets (which include existing BaseURLs from Httpx).
          </div>
        )}

        {/* === Section A - Custom Subdomains (only for tools that consume Subdomain) === */}
        {hasSubdomainInput && (
          <div>
            <div style={labelStyle}>Custom subdomains (optional, one per line)</div>
            <textarea
              value={customSubdomains}
              onChange={e => setCustomSubdomains(e.target.value)}
              placeholder={`api.${domain || 'example.com'}\nstaging.${domain || 'example.com'}`}
              rows={2}
              style={textareaStyle(subdomainValidation.errors.length > 0)}
            />
            {subdomainValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {subdomainValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>Will be DNS-resolved and added to the graph as Subdomain nodes</div>
            )}
          </div>
        )}

        {/* === Section B - Custom IPs === */}
        {hasIpInput && (
          <div>
            <div style={labelStyle}>Custom IPs (optional, one per line)</div>
            <textarea
              value={customIps}
              onChange={e => setCustomIps(e.target.value)}
              placeholder={'192.168.1.1\n10.0.0.0/24'}
              rows={2}
              style={textareaStyle(ipValidation.errors.length > 0)}
            />
            {ipValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {ipValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>{isNmap || isHttpx
                ? 'IPv4, IPv6, or CIDR ranges (/24-/32). Will be probed on all ports (graph + custom).'
                : 'IPv4, IPv6, or CIDR ranges (/24-/32)'}</div>
            )}

            {/* Dropdown: associate IPs to subdomain */}
            {customIps.trim() && ipValidation.errors.length === 0 && (
              <div style={{ marginTop: '8px' }}>
                <div style={labelStyle}>Associate IPs to</div>
                <select
                  value={ipAttachTo || ''}
                  onChange={e => setIpAttachTo(e.target.value || null)}
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #334155)',
                    backgroundColor: 'var(--bg-secondary, #1e293b)',
                    color: 'var(--text-primary, #e2e8f0)',
                    fontSize: '12px',
                  }}
                >
                  <option value="">-- Generic (UserInput) --</option>
                  {attachToOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}{opt.source === 'custom' ? ' (new)' : ''}
                    </option>
                  ))}
                </select>
                <div style={hintStyle}>
                  {ipAttachTo
                    ? `IPs will be linked to ${ipAttachTo} via RESOLVES_TO`
                    : 'IPs will be tracked via a UserInput node (no subdomain link)'}
                </div>
              </div>
            )}
          </div>
        )}

        {/* === Section C - Custom Ports (Nmap / Httpx) === */}
        {hasPortInput && (
          <div>
            <div style={labelStyle}>Custom ports (optional, one per line)</div>
            <textarea
              value={customPorts}
              onChange={e => setCustomPorts(e.target.value)}
              placeholder={'8443\n9090\n3000'}
              rows={2}
              style={textareaStyle(portValidation.errors.length > 0)}
            />
            {portValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {portValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>Port numbers 1-65535. Scanned on all target IPs (graph + custom).</div>
            )}
          </div>
        )}

        {/* Httpx default ports info */}
        {isHttpx && (customSubdomains.trim() || customIps.trim()) && !customPorts.trim() && (
          <div style={{
            fontSize: '11px', color: '#60a5fa', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.2)',
          }}>
            No custom ports specified. Custom subdomains and IPs will be probed on default ports (80, 443) only.
            Add custom ports above to probe additional ports.
          </div>
        )}

        {/* === Section D - Custom URLs (resource enum: Katana, Hakrawler) === */}
        {hasUrlInput && (
          <div>
            <div style={labelStyle}>Custom URLs (optional, one per line)</div>
            <textarea
              value={customUrls}
              onChange={e => setCustomUrls(e.target.value)}
              placeholder={'https://example.com\nhttps://api.example.com:8443'}
              rows={2}
              style={textareaStyle(urlValidation.errors.length > 0)}
            />
            {urlValidation.errors.length > 0 ? (
              <div style={errorListStyle}>
                {urlValidation.errors.map((err, i) => (
                  <div key={i} style={errorLineStyle}>Line {err.line}: {err.error}</div>
                ))}
              </div>
            ) : (
              <div style={hintStyle}>Full URLs (http/https). Will be crawled to discover endpoints and parameters.</div>
            )}

            {/* Dropdown: associate URLs to BaseURL */}
            {customUrls.trim() && urlValidation.errors.length === 0 && (
              <div style={{ marginTop: '8px' }}>
                <div style={labelStyle}>Associate URLs to</div>
                <select
                  value={urlAttachTo || ''}
                  onChange={e => setUrlAttachTo(e.target.value || null)}
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color, #334155)',
                    backgroundColor: 'var(--bg-secondary, #1e293b)',
                    color: 'var(--text-primary, #e2e8f0)',
                    fontSize: '12px',
                  }}
                >
                  <option value="">-- Generic (UserInput) --</option>
                  {urlAttachToOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
                <div style={hintStyle}>
                  {urlAttachTo
                    ? `Discovered endpoints will be linked to ${urlAttachTo}`
                    : 'URLs will be tracked via a UserInput node (no BaseURL link)'}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Subdomain prefix warning (SubdomainDiscovery only) */}
        {toolId === 'SubdomainDiscovery' && subdomainPrefixes.length > 0 && (
          <div style={{
            fontSize: '11px', color: '#f87171', lineHeight: '1.5', padding: '8px 12px', borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            This project has subdomain prefixes locked to <strong>{subdomainPrefixes.join(', ')}</strong>.
            Partial recon ignores this filter and runs full discovery to find all subdomains.
            New subdomains found outside the prefix list will still be added to the graph.
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-color, #334155)' }}>
          <button
            type="button"
            onClick={onClose}
            disabled={isStarting}
            style={{
              padding: '8px 16px', borderRadius: '6px',
              border: '1px solid var(--border-color, #334155)',
              backgroundColor: 'transparent',
              color: 'var(--text-primary, #e2e8f0)',
              cursor: isStarting ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              opacity: isStarting ? 0.5 : 1,
            }}
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleRun}
            disabled={!domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls}
            style={{
              padding: '8px 16px', borderRadius: '6px', border: 'none',
              backgroundColor: '#3b82f6', color: '#fff',
              cursor: !domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: !domain || isStarting || hasValidationErrors || noTargetsToScan || nmapNoPorts || httpxNoPorts || resourceEnumNoUrls ? 0.5 : 1,
            }}
          >
            {isStarting ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={14} />}
            {isStarting ? 'Starting...' : 'Run Partial Recon'}
          </button>
        </div>
      </div>
    </Modal>
  )
}
