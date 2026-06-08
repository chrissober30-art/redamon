'use client'

import { memo, useEffect, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import type { RedZoneExportConfig } from './exportCsv'
import {
  Mono, Truncated, UrlCell, NumCell, BoolChip, ListCell, SeverityBadge, filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

type CellKind = 'url' | 'mono' | 'text' | 'bool' | 'num' | 'list' | 'sev'

interface ColumnDef { key: string; header: string; kind: CellKind; max?: number }
interface SheetDef { key: string; label: string; columns: ColumnDef[]; empty: string }

interface MultiSheetProps {
  projectId: string | null
  slug: 'aiSurface' | 'aiRisk'
  title: string
  sheets: SheetDef[]
}

function renderCell(kind: CellKind, value: unknown, max?: number) {
  switch (kind) {
    case 'url': return <UrlCell url={value as string | null} max={max ?? 260} />
    case 'mono': return value ? <Mono>{String(value)}</Mono> : <span>-</span>
    case 'bool': return <BoolChip value={value as boolean | null} />
    case 'num': return <NumCell value={value as number | null} />
    case 'list': return <ListCell items={(value as string[]) || []} max={max ?? 4} />
    case 'sev': return <SeverityBadge severity={normalizeSeverity(value as string)} />
    default: return <Truncated text={value == null ? '' : String(value)} max={max ?? 200} />
  }
}

const MultiSheetTable = memo(function MultiSheetTable({ projectId, slug, title, sheets }: MultiSheetProps) {
  const [data, setData] = useState<{ sheets: Record<string, unknown[]> } | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState(sheets[0].key)
  const [search, setSearch] = useState('')

  const fetchData = useMemo(() => async () => {
    if (!projectId) { setData(null); return }
    setIsLoading(true); setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/${slug}?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) {
        const b = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        throw new Error(b.error || `HTTP ${res.status}`)
      }
      setData(await res.json())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally { setIsLoading(false) }
  }, [projectId, slug])

  useEffect(() => { fetchData() }, [fetchData])

  const sheet = sheets.find(s => s.key === active) ?? sheets[0]
  const allRows = useMemo(() => (data?.sheets?.[sheet.key] as Record<string, unknown>[]) ?? [], [data, sheet.key])
  const filtered = useMemo(() => filterRowsByText(allRows, search), [allRows, search])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    filtered.length > 0
      ? { rows: filtered, sheetName: sheet.label, fileSlug: `${slug}-${sheet.key}`,
          columns: sheet.columns.map(c => ({ key: c.key, header: c.header })) }
      : undefined,
    [filtered, sheet, slug])

  const counts = (data?.sheets ?? {}) as Record<string, unknown[]>
  const meta = sheets.map(s => `${s.label}: ${counts[s.key]?.length ?? 0}`).join(' · ')

  return (
    <RedZoneTableShell
      title={title}
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder={`Search ${sheet.label.toLowerCase()}...`}
      exportConfig={exportConfig}
      onRefresh={fetchData}
      isLoading={isLoading}
      error={error}
      rowCount={allRows.length}
      filteredRowCount={filtered.length}
      emptyLabel={sheet.empty}
    >
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '8px 4px' }}>
        {sheets.map(s => {
          const n = counts[s.key]?.length ?? 0
          const isActive = s.key === active
          return (
            <button
              key={s.key}
              onClick={() => { setActive(s.key); setSearch('') }}
              style={{
                fontSize: 12, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                border: '1px solid ' + (isActive ? '#f59e0b' : 'rgba(255,255,255,0.15)'),
                background: isActive ? 'rgba(245,158,11,0.15)' : 'transparent',
                color: isActive ? '#f59e0b' : 'inherit', fontWeight: isActive ? 600 : 400,
              }}
            >
              {s.label} <span style={{ opacity: 0.6 }}>({n})</span>
            </button>
          )
        })}
      </div>
      <table className={rowStyles.table}>
        <thead>
          <tr>{sheet.columns.map(c => <th key={c.key}>{c.header}</th>)}</tr>
        </thead>
        <tbody>
          {filtered.map((r, i) => (
            <tr key={i}>
              {sheet.columns.map(c => <td key={c.key}>{renderCell(c.kind, r[c.key], c.max)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </RedZoneTableShell>
  )
})

// --------------------------------------------------------------------------- //
const AI_SURFACE_SHEETS: SheetDef[] = [
  { key: 'llmEndpoints', label: 'LLM Endpoints',
    empty: 'No AI/LLM endpoints detected. Run a scan with AI Surface Recon enabled.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'interfaceType', header: 'Interface', kind: 'text' },
      { key: 'streaming', header: 'Stream', kind: 'bool' },
      { key: 'tools', header: 'Tools', kind: 'bool' },
      { key: 'vision', header: 'Vision', kind: 'bool' },
      { key: 'modelFamily', header: 'Model Family', kind: 'text' },
      { key: 'latencyMs', header: 'Latency (ms)', kind: 'num' },
      { key: 'ragIngest', header: 'RAG', kind: 'bool' },
      { key: 'framework', header: 'Framework', kind: 'text' },
      { key: 'source', header: 'Source', kind: 'text' },
    ] },
  { key: 'mcpServers', label: 'MCP Servers',
    empty: 'No MCP servers detected.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'serverName', header: 'Server', kind: 'text' },
      { key: 'serverVersion', header: 'Version', kind: 'text' },
      { key: 'protocolVersion', header: 'Protocol', kind: 'text' },
      { key: 'toolCount', header: 'Tools', kind: 'num' },
      { key: 'resourceCount', header: 'Res', kind: 'num' },
      { key: 'promptCount', header: 'Prompts', kind: 'num' },
      { key: 'capabilities', header: 'Capabilities', kind: 'list' },
      { key: 'authRequired', header: 'Auth', kind: 'bool' },
      { key: 'toolsHash', header: 'Tools Hash', kind: 'mono', max: 16 },
    ] },
  { key: 'technologies', label: 'AI Technologies',
    empty: 'No AI technologies fingerprinted.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'category', header: 'Category', kind: 'text' },
      { key: 'version', header: 'Version', kind: 'text' },
      { key: 'detectedBy', header: 'Detected By', kind: 'list' },
      { key: 'attachedTo', header: 'Attached', kind: 'num' },
    ] },
  { key: 'vectorDbs', label: 'Vector DBs',
    empty: 'No vector databases confirmed.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'host', header: 'Host', kind: 'text' },
      { key: 'port', header: 'Port', kind: 'num' },
      { key: 'detectedBy', header: 'Detected By', kind: 'text' },
    ] },
  { key: 'models', label: 'Model Inventory',
    empty: 'No model IDs discovered.',
    columns: [
      { key: 'modelId', header: 'Model ID', kind: 'mono' },
      { key: 'family', header: 'Family', kind: 'text' },
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'sourceEndpoint', header: 'Source Endpoint', kind: 'mono' },
    ] },
]

const AI_RISK_SHEETS: SheetDef[] = [
  { key: 'findings', label: 'MCP Tool Poisoning',
    empty: 'No MCP tool-poisoning findings. Good — or MCP analysis was disabled.',
    columns: [
      { key: 'severity', header: 'Severity', kind: 'sev' },
      { key: 'type', header: 'Type', kind: 'text' },
      { key: 'name', header: 'Finding', kind: 'text', max: 300 },
      { key: 'owasp', header: 'OWASP-LLM', kind: 'text' },
      { key: 'atlas', header: 'ATLAS', kind: 'text' },
      { key: 'payloadClass', header: 'Class', kind: 'text' },
      { key: 'baseUrl', header: 'MCP Server', kind: 'url' },
      { key: 'endpointPath', header: 'Path', kind: 'mono' },
    ] },
  { key: 'injectableParams', label: 'Injectable Params',
    empty: 'No prompt-injectable parameters flagged.',
    columns: [
      { key: 'name', header: 'Parameter', kind: 'text' },
      { key: 'endpointPath', header: 'Endpoint', kind: 'mono' },
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'toolArgPath', header: 'Tool Arg Path', kind: 'mono' },
      { key: 'position', header: 'Position', kind: 'text' },
    ] },
  { key: 'ragPoints', label: 'RAG Ingestion',
    empty: 'No RAG ingestion endpoints flagged.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'method', header: 'Method', kind: 'text' },
      { key: 'interfaceType', header: 'Interface', kind: 'text' },
    ] },
  { key: 'exposedRuntimes', label: 'Exposed Runtimes',
    empty: 'No exposed AI runtimes or gateways.',
    columns: [
      { key: 'name', header: 'Name', kind: 'text' },
      { key: 'category', header: 'Category', kind: 'text' },
      { key: 'version', header: 'Version', kind: 'text' },
      { key: 'exposedOn', header: 'Exposed On', kind: 'list' },
    ] },
  { key: 'unauthenticatedMcp', label: 'Unauthenticated MCP',
    empty: 'No unauthenticated MCP servers.',
    columns: [
      { key: 'baseUrl', header: 'Base URL', kind: 'url' },
      { key: 'path', header: 'Path', kind: 'mono' },
      { key: 'serverName', header: 'Server', kind: 'text' },
      { key: 'toolCount', header: 'Tools', kind: 'num' },
    ] },
]

interface Props { projectId: string | null }

export const AiSurfaceTable = memo(function AiSurfaceTable({ projectId }: Props) {
  return <MultiSheetTable projectId={projectId} slug="aiSurface" title="AI / LLM Attack Surface" sheets={AI_SURFACE_SHEETS} />
})

export const AiRiskTable = memo(function AiRiskTable({ projectId }: Props) {
  return <MultiSheetTable projectId={projectId} slug="aiRisk" title="AI Risk (OWASP-LLM / ATLAS)" sheets={AI_RISK_SHEETS} />
})
