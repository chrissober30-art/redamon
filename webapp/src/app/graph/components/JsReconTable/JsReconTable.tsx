'use client'

import { useState, useEffect, useCallback, useMemo, memo } from 'react'
import { Loader2, AlertTriangle, Copy, Check } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import styles from './JsReconTable.module.css'
import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from '../../utils/exportHelpers'

export type { JsReconData }

interface JsReconTableProps {
  projectId: string | null
  search: string
  onDataLoaded?: (data: JsReconData | null) => void
}

interface JsReconData {
  scan_metadata?: { scan_timestamp?: string; js_files_analyzed?: number; duration_seconds?: number }
  secrets?: any[]
  endpoints?: any[]
  dependencies?: any[]
  source_maps?: any[]
  dom_sinks?: any[]
  frameworks?: any[]
  dev_comments?: any[]
  cloud_assets?: any[]
  emails?: any[]
  ip_addresses?: any[]
  object_references?: any[]
  discovered_subdomains?: string[]
  external_domains?: any[]
  summary?: Record<string, any>
}

const SUB_TABS = [
  { id: 'secrets', label: 'Secrets' },
  { id: 'endpoints', label: 'Endpoints' },
  { id: 'dependencies', label: 'Dependencies' },
  { id: 'sourcemaps', label: 'Source Maps' },
  { id: 'security', label: 'Security' },
  { id: 'surface', label: 'Attack Surface' },
] as const

const PAGE_SIZE = 50

interface JsReconSheet {
  name: string
  rows: any[]
  columns: string[]
}

function getCol(row: any, col: string): unknown {
  return col.includes('.') ? col.split('.').reduce((o: any, k) => o?.[k], row) : row[col]
}

function buildJsReconSheets(data: JsReconData): JsReconSheet[] {
  return [
    { name: 'Secrets', rows: data.secrets || [], columns: ['severity', 'name', 'redacted_value', 'matched_text', 'category', 'source_url', 'line_number', 'context', 'detection_method', 'validation.status', 'confidence', 'validator_ref'] },
    { name: 'Endpoints', rows: data.endpoints || [], columns: ['severity', 'method', 'path', 'full_url', 'type', 'category', 'base_url', 'source_js', 'parameters', 'line_number'] },
    { name: 'Dependencies', rows: data.dependencies || [], columns: ['severity', 'finding_type', 'package_name', 'scope', 'npm_exists', 'confidence', 'title', 'detail', 'recommendation', 'source_urls'] },
    { name: 'Source Maps', rows: data.source_maps || [], columns: ['severity', 'finding_type', 'js_url', 'map_url', 'accessible', 'discovery_method', 'files_count', 'source_files', 'secrets_in_source', 'secrets'] },
    { name: 'DOM Sinks', rows: data.dom_sinks || [], columns: ['severity', 'finding_type', 'type', 'pattern', 'description', 'source_url', 'line', 'confidence'] },
    { name: 'Frameworks', rows: data.frameworks || [], columns: ['name', 'version', 'severity', 'finding_type', 'source_url', 'confidence'] },
    { name: 'Dev Comments', rows: data.dev_comments || [], columns: ['severity', 'type', 'content', 'source_url', 'line', 'confidence'] },
    { name: 'Cloud Assets', rows: data.cloud_assets || [], columns: ['provider', 'type', 'url', 'source_url'] },
    { name: 'Emails', rows: data.emails || [], columns: ['email', 'category', 'source_url', 'context'] },
    { name: 'IPs', rows: data.ip_addresses || [], columns: ['ip', 'type', 'source_url', 'context'] },
    { name: 'Object Refs', rows: data.object_references || [], columns: ['type', 'value', 'source_url', 'context', 'potential_idor'] },
    { name: 'Subdomains', rows: (data.discovered_subdomains || []).map(s => ({ subdomain: s })), columns: ['subdomain'] },
    { name: 'External Domains', rows: data.external_domains || [], columns: ['domain', 'times_seen'] },
  ]
}

/**
 * Multi-section CSV: each non-empty section gets a "# Section: <name>" marker
 * row followed by its own header + data rows, separated by a blank line.
 * Streamed end-to-end (showSaveFilePicker if available) so the largest
 * findings dumps don't pin the file in browser memory.
 */
export async function exportJsReconCsv(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  function* dictRows(sheet: { rows: any[]; columns: string[] }): Iterable<Record<string, unknown>> {
    for (const r of sheet.rows) {
      const row: Record<string, unknown> = {}
      for (const col of sheet.columns) row[col] = getCol(r, col)
      yield row
    }
  }

  async function* combined(): AsyncGenerator<string> {
    yield '\uFEFF'
    let first = true
    for (const sheet of sheets) {
      if (!first) yield '\r\n'
      first = false
      yield `# Section: ${sheet.name}\r\n`
      // streamCsvChunks emits its own BOM + trailing CRLF; drop the BOM
      // (we already wrote one) but keep the trailing CRLF so the next
      // section's marker starts on a fresh line.
      let bomDropped = false
      for await (const chunk of streamCsvChunks(sheet.columns, dictRows(sheet))) {
        if (!bomDropped && chunk === '\uFEFF') { bomDropped = true; continue }
        yield chunk
      }
    }
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.csv`,
    CSV_MIME,
    () => combined(),
  )
}

export async function exportJsReconJson(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  function* dictRows(sheet: { rows: any[]; columns: string[] }): Iterable<Record<string, unknown>> {
    for (const r of sheet.rows) {
      const row: Record<string, unknown> = {}
      for (const col of sheet.columns) row[col] = getCol(r, col) ?? null
      yield row
    }
  }

  async function* combined(): AsyncGenerator<string> {
    if (sheets.length === 0) { yield '{}\n'; return }
    yield '{\n'
    for (let s = 0; s < sheets.length; s++) {
      const sheet = sheets[s]
      yield `  ${JSON.stringify(sheet.name)}: `
      yield* streamJsonArrayChunks(dictRows(sheet), { outerIndent: 2 })
      yield s === sheets.length - 1 ? '\n' : ',\n'
    }
    yield '}\n'
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => combined(),
  )
}

export async function exportJsReconMarkdown(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  async function* combined(): AsyncGenerator<string> {
    yield `# JS Recon Findings\n\nGenerated: ${new Date().toISOString()}\n\n`
    for (const sheet of sheets) {
      yield `## ${sheet.name} (${sheet.rows.length})\n\n`
      yield* streamMarkdownTableChunks(
        sheet.columns,
        sheet.rows,
        (row, col) => getCol(row, col),
      )
      yield '\n\n'
    }
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}

function sevBadge(severity: string) {
  const cls = { critical: styles.badgeCritical, high: styles.badgeHigh, medium: styles.badgeMedium, low: styles.badgeLow, info: styles.badgeInfo }[severity] || styles.badgeInfo
  return <span className={`${styles.badge} ${cls}`}>{severity}</span>
}

function valBadge(status: string) {
  if (status === 'validated') return <span className={`${styles.badge} ${styles.badgeLive}`}>LIVE</span>
  if (status === 'format_validated') return <span className={`${styles.badge} ${styles.badgeFormatValid}`}>format ok</span>
  if (status === 'invalid') return <span className={`${styles.badge} ${styles.badgeInvalid}`}>invalid</span>
  return <span className={`${styles.badge} ${styles.badgeUnvalidated}`}>{status || 'n/a'}</span>
}

const VALIDATION_PRIORITY: Record<string, number> = {
  validated: 0, format_validated: 1, incomplete: 2, unvalidated: 3, skipped: 4, invalid: 5,
}
const SEVERITY_PRIORITY: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

function sortSecrets(rows: any[]): any[] {
  return [...rows].sort((a, b) => {
    const va = VALIDATION_PRIORITY[a.validation?.status ?? 'unvalidated'] ?? 3
    const vb = VALIDATION_PRIORITY[b.validation?.status ?? 'unvalidated'] ?? 3
    if (va !== vb) return va - vb
    const sa = SEVERITY_PRIORITY[a.severity ?? 'info'] ?? 4
    const sb = SEVERITY_PRIORITY[b.severity ?? 'info'] ?? 4
    return sa - sb
  })
}

export const JsReconTable = memo(function JsReconTable({
  projectId, search, onDataLoaded,
}: JsReconTableProps) {
  const [data, setData] = useState<JsReconData | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<string>('secrets')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const fetchData = useCallback(async () => {
    if (!projectId) return
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/js-recon/${projectId}/download`)
      if (res.status === 404) { setError('No JS Recon data. Run a recon scan with JS Recon enabled.'); return }
      if (!res.ok) throw new Error('Failed to fetch')
      const json = await res.json()
      setData(json)
      onDataLoaded?.(json)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  useEffect(() => { fetchData() }, [fetchData])
  useEffect(() => { setLimit(PAGE_SIZE) }, [activeTab, search])

  const tabCounts = useMemo(() => {
    if (!data) return {}
    return {
      secrets: data.secrets?.length || 0,
      endpoints: data.endpoints?.length || 0,
      dependencies: data.dependencies?.length || 0,
      sourcemaps: data.source_maps?.length || 0,
      security: (data.dom_sinks?.length || 0) + (data.frameworks?.length || 0) + (data.dev_comments?.length || 0),
      surface: (data.discovered_subdomains?.length || 0) + (data.cloud_assets?.length || 0) + (data.emails?.length || 0) + (data.ip_addresses?.length || 0) + (data.external_domains?.length || 0),
    }
  }, [data])

  if (!projectId) return <div className={styles.stateContainer}>Select a project.</div>
  if (isLoading) return <div className={styles.stateContainer}><Loader2 size={24} className={styles.spinner} /> Loading JS Recon data...</div>
  if (error) return <div className={styles.stateContainer}><AlertTriangle size={20} />{error}</div>
  if (!data) return <div className={styles.stateContainer}>No data loaded.</div>

  return (
    <div className={styles.container}>
      {/* Sub-tabs */}
      <div className={styles.subTabs}>
        {SUB_TABS.map(tab => (
          <button
            key={tab.id}
            className={activeTab === tab.id ? styles.subTabActive : styles.subTab}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {(tabCounts as any)[tab.id] > 0 && <span className={styles.subTabBadge}>{(tabCounts as any)[tab.id]}</span>}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className={styles.tableWrapper}>
        {activeTab === 'secrets' && <SecretsTable rows={data.secrets || []} search={search} limit={limit} />}
        {activeTab === 'endpoints' && <EndpointsTable rows={data.endpoints || []} search={search} limit={limit} />}
        {activeTab === 'dependencies' && <DepsTable rows={data.dependencies || []} search={search} limit={limit} />}
        {activeTab === 'sourcemaps' && <SourceMapsTable rows={data.source_maps || []} search={search} limit={limit} />}
        {activeTab === 'security' && <SecurityTable data={data} search={search} limit={limit} />}
        {activeTab === 'surface' && <SurfaceTable data={data} search={search} limit={limit} />}
      </div>

      {/* Pagination */}
      {(() => {
        const totalForTab = (tabCounts as any)[activeTab] || 0
        if (limit < totalForTab) return (
          <div className={styles.pagination}>
            <button className={styles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
              Showing {Math.min(limit, totalForTab)} of {totalForTab} -- Load more
            </button>
          </div>
        )
        return null
      })()}
    </div>
  )
})

// ============================================================
// Sub-table components
// ============================================================

function filterRows(rows: any[], search: string): any[] {
  if (!search) return rows
  const s = search.toLowerCase()
  return rows.filter(r => {
    // Search ALL string/number values in the object (universal search)
    for (const v of Object.values(r)) {
      if (v == null) continue
      if (typeof v === 'object' && !Array.isArray(v)) {
        // Check one level deep (e.g., validation.status)
        for (const sv of Object.values(v as Record<string, unknown>)) {
          if (typeof sv === 'string' && sv.toLowerCase().includes(s)) return true
        }
      } else if (String(v).toLowerCase().includes(s)) {
        return true
      }
    }
    return false
  })
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [text])
  if (!text) return null
  return (
    <button
      type="button"
      className={styles.copyButton}
      onClick={handleCopy}
      title="Copy full value"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  )
}

function SecretsTable({ rows, search, limit }: { rows: any[]; search: string; limit: number }) {
  const filtered = sortSecrets(filterRows(rows, search)).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No secrets found.</div>
  return (
    <table className={styles.table}>
      <thead><tr><th>Severity</th><th>Type</th><th>Redacted Value</th><th>Source</th><th>Validation</th><th>Confidence</th></tr></thead>
      <tbody>
        {filtered.map((s, i) => (
          <tr key={s.id || i}>
            <td>{sevBadge(s.severity)}</td>
            <td>{s.name}</td>
            <td>
              <code className={styles.mono}>{s.redacted_value}</code>
              <CopyButton text={s.matched_text || ''} />
            </td>
            <td className={styles.truncate} title={s.source_url}><ExternalLink href={s.source_url}>{s.source_url}</ExternalLink></td>
            <td>{valBadge(s.validation?.status)}</td>
            <td>{s.confidence}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function EndpointsTable({ rows, search, limit }: { rows: any[]; search: string; limit: number }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No endpoints extracted.</div>
  return (
    <table className={styles.table}>
      <thead><tr><th>Severity</th><th>Method</th><th>Path</th><th>Type</th><th>Category</th><th>Source</th></tr></thead>
      <tbody>
        {filtered.map((ep, i) => (
          <tr key={ep.id || i}>
            <td>{sevBadge(ep.severity || 'info')}</td>
            <td><code className={styles.mono}>{ep.method}</code></td>
            <td className={styles.truncate} title={ep.full_url || ep.path}><code className={styles.mono}>{ep.path}</code></td>
            <td>{ep.type}</td>
            <td>{ep.category}</td>
            <td className={styles.truncate} title={ep.source_js}><ExternalLink href={ep.source_js}>{ep.source_js}</ExternalLink></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function DepsTable({ rows, search, limit }: { rows: any[]; search: string; limit: number }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No dependency confusion findings.</div>
  return (
    <table className={styles.table}>
      <thead><tr><th>Severity</th><th>Package</th><th>Scope</th><th>On npm?</th><th>Detail</th></tr></thead>
      <tbody>
        {filtered.map((d, i) => (
          <tr key={d.id || i}>
            <td>{sevBadge(d.severity)}</td>
            <td><code className={styles.mono}>{d.package_name}</code></td>
            <td>{d.scope}</td>
            <td>{d.npm_exists ? 'Yes' : 'No'}</td>
            <td className={styles.truncate} title={d.detail}>{d.title}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function SourceMapsTable({ rows, search, limit }: { rows: any[]; search: string; limit: number }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No source maps discovered.</div>
  return (
    <table className={styles.table}>
      <thead><tr><th>JS File</th><th>Map URL</th><th>Accessible</th><th>Files</th><th>Secrets</th><th>Discovery</th></tr></thead>
      <tbody>
        {filtered.map((sm, i) => (
          <tr key={sm.id || i}>
            <td className={styles.truncate} title={sm.js_url}><code className={styles.mono}><ExternalLink href={sm.js_url}>{sm.js_url}</ExternalLink></code></td>
            <td className={styles.truncate} title={sm.map_url}><code className={styles.mono}><ExternalLink href={sm.map_url}>{sm.map_url}</ExternalLink></code></td>
            <td>{sm.accessible ? 'Yes' : 'No'}</td>
            <td>{sm.files_count || 0}</td>
            <td>{sm.secrets_in_source || 0}</td>
            <td>{sm.discovery_method}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function SecurityTable({ data, search, limit }: { data: JsReconData; search: string; limit: number }) {
  const frameworks = filterRows(data.frameworks || [], search)
  const sinks = filterRows(data.dom_sinks || [], search)
  const comments = filterRows(data.dev_comments || [], search)
  const refs = filterRows(data.object_references || [], search)

  if (!frameworks.length && !sinks.length && !comments.length && !refs.length)
    return <div className={styles.stateContainer}>No security pattern findings.</div>

  // Calculate per-section limits upfront (not during render)
  let budget = limit
  const fwLimit = Math.min(frameworks.length, budget); budget -= fwLimit
  const sinkLimit = Math.min(sinks.length, budget); budget -= sinkLimit
  const cmtLimit = Math.min(comments.length, budget); budget -= cmtLimit
  const refLimit = Math.min(refs.length, budget)

  return (
    <>
      {frameworks.length > 0 && (
        <>
          <div className={styles.sectionTitle}>Frameworks ({frameworks.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Framework</th><th>Version</th><th>Source</th></tr></thead>
            <tbody>{frameworks.slice(0, fwLimit).map((f, i) => (
              <tr key={f.id || i}><td>{f.name}</td><td>{f.version || '-'}</td><td className={styles.truncate} title={f.source_url}><ExternalLink href={f.source_url}>{f.source_url}</ExternalLink></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {sinks.length > 0 && sinkLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>DOM Sinks ({sinks.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Severity</th><th>Type</th><th>Pattern</th><th>Source</th><th>Line</th></tr></thead>
            <tbody>{sinks.slice(0, sinkLimit).map((s, i) => (
              <tr key={s.id || i}>
                <td>{sevBadge(s.severity)}</td>
                <td><code className={styles.mono}>{s.type}</code></td>
                <td className={styles.truncate} title={s.pattern}><code className={styles.mono}>{s.pattern}</code></td>
                <td className={styles.truncate} title={s.source_url}><ExternalLink href={s.source_url}>{s.source_url}</ExternalLink></td>
                <td>{s.line}</td>
              </tr>
            ))}</tbody>
          </table>
        </>
      )}
      {comments.length > 0 && cmtLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Developer Comments ({comments.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Severity</th><th>Type</th><th>Content</th><th>Source</th><th>Line</th></tr></thead>
            <tbody>{comments.slice(0, cmtLimit).map((c, i) => (
              <tr key={c.id || i}>
                <td>{sevBadge(c.severity)}</td>
                <td>{c.type}</td>
                <td className={styles.truncate} title={c.content}>{c.content}</td>
                <td className={styles.truncate} title={c.source_url}><ExternalLink href={c.source_url}>{c.source_url}</ExternalLink></td>
                <td>{c.line}</td>
              </tr>
            ))}</tbody>
          </table>
        </>
      )}
      {refs.length > 0 && refLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Object References / IDOR ({refs.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>
            <tbody>{refs.slice(0, refLimit).map((r, i) => (
              <tr key={i}><td>{r.type}</td><td><code className={styles.mono}>{r.value}</code></td><td className={styles.truncate} title={r.source_url}><ExternalLink href={r.source_url}>{r.source_url}</ExternalLink></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
    </>
  )
}

function SurfaceTable({ data, search, limit }: { data: JsReconData; search: string; limit: number }) {
  const subs = (data.discovered_subdomains || []).filter(s => !search || s.toLowerCase().includes(search.toLowerCase()))
  const cloud = filterRows(data.cloud_assets || [], search)
  const emails = filterRows(data.emails || [], search)
  const ips = filterRows(data.ip_addresses || [], search)
  const extDomains = filterRows(data.external_domains || [], search)

  if (!subs.length && !cloud.length && !emails.length && !ips.length && !extDomains.length)
    return <div className={styles.stateContainer}>No attack surface data found.</div>

  // Calculate per-section limits upfront
  let budget = limit
  const subsLimit = Math.min(subs.length, budget); budget -= subsLimit
  const cloudLimit = Math.min(cloud.length, budget); budget -= cloudLimit
  const emailsLimit = Math.min(emails.length, budget); budget -= emailsLimit
  const ipsLimit = Math.min(ips.length, budget); budget -= ipsLimit
  const extLimit = Math.min(extDomains.length, budget)

  return (
    <>
      {subs.length > 0 && (
        <>
          <div className={styles.sectionTitle}>New Subdomains ({subs.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Subdomain</th></tr></thead>
            <tbody>{subs.slice(0, subsLimit).map(s => (
              <tr key={s}><td><code className={styles.mono}>{s}</code></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {cloud.length > 0 && cloudLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Cloud Assets ({cloud.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Provider</th><th>Type</th><th>URL</th><th>Source</th></tr></thead>
            <tbody>{cloud.slice(0, cloudLimit).map((a, i) => (
              <tr key={i}><td>{a.provider}</td><td>{a.type}</td><td className={styles.truncate} title={a.url}><code className={styles.mono}><ExternalLink href={a.url}>{a.url}</ExternalLink></code></td><td className={styles.truncate} title={a.source_url}><ExternalLink href={a.source_url}>{a.source_url}</ExternalLink></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {emails.length > 0 && emailsLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Email Addresses ({emails.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Email</th><th>Source</th></tr></thead>
            <tbody>{emails.slice(0, emailsLimit).map((e, i) => (
              <tr key={i}><td>{e.email}</td><td className={styles.truncate} title={e.source_url}><ExternalLink href={e.source_url}>{e.source_url}</ExternalLink></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {ips.length > 0 && ipsLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Internal IPs ({ips.length})</div>
          <table className={styles.table}>
            <thead><tr><th>IP</th><th>Type</th><th>Source</th></tr></thead>
            <tbody>{ips.slice(0, ipsLimit).map((ip, i) => (
              <tr key={i}><td><code className={styles.mono}>{ip.ip}</code></td><td>{ip.type}</td><td className={styles.truncate} title={ip.source_url}><ExternalLink href={ip.source_url}>{ip.source_url}</ExternalLink></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {extDomains.length > 0 && extLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>External Domains ({extDomains.length})</div>
          <table className={styles.table}>
            <thead><tr><th>Domain</th><th>Times Seen</th></tr></thead>
            <tbody>{extDomains.slice(0, extLimit).map((d, i) => (
              <tr key={i}><td><code className={styles.mono}>{d.domain}</code></td><td>{d.times_seen}</td></tr>
            ))}</tbody>
          </table>
        </>
      )}
    </>
  )
}
