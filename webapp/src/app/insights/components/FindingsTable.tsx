'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import { hostPortToUrl, ipToUrl, resolveLinkable } from '@/lib/url-utils'
import { severityColor } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './DataTable.module.css'
import type { SecurityFinding } from '../types'

interface FindingsTableProps {
  data: SecurityFinding[] | undefined
  isLoading: boolean
}

type SortKey = 'severity' | 'name' | 'target' | 'source'
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

export function FindingsTable({ data, isLoading }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [sortAsc, setSortAsc] = useState(false)

  const sorted = useMemo(() => {
    if (!data) return []
    return [...data].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'severity') cmp = (SEV_ORDER[a.severity?.toLowerCase()] ?? 5) - (SEV_ORDER[b.severity?.toLowerCase()] ?? 5)
      else if (sortKey === 'name') cmp = a.name.localeCompare(b.name)
      else if (sortKey === 'target') cmp = (a.target || '').localeCompare(b.target || '')
      else cmp = a.findingSource.localeCompare(b.findingSource)
      return sortAsc ? cmp : -cmp
    })
  }, [data, sortKey, sortAsc])

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(false) }
  }

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) return null
    return sortAsc ? <ChevronUp size={12} /> : <ChevronDown size={12} />
  }

  const getTargetDisplay = (f: SecurityFinding) => {
    if (f.endpointPath) return f.endpointPath + (f.paramName ? `?${f.paramName}` : '')
    if (f.target) return f.target
    if (f.host) return f.host
    if (f.targetIp) return f.targetIp + (f.targetPort ? `:${f.targetPort}` : '')
    return '-'
  }

  const getTargetHref = (f: SecurityFinding): string | null => {
    if (f.target) return resolveLinkable(f.target)
    if (f.host) {
      if (f.targetPort) return hostPortToUrl(f.host, f.targetPort)
      return resolveLinkable(f.host)
    }
    if (f.targetIp) return ipToUrl(f.targetIp, f.targetPort ?? undefined)
    return null
  }

  return (
    <ChartCard title="Security Findings" subtitle={`${data?.length || 0} findings`} isLoading={isLoading} isEmpty={!sorted.length}>
      <div className={styles.tableWrap}>
        <table className="table">
          <thead className="tableHeader">
            <tr>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('severity')}>
                Sev <SortIcon col="severity" />
              </th>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('name')}>
                Finding <SortIcon col="name" />
              </th>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('target')}>
                Target <SortIcon col="target" />
              </th>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('source')}>
                Source <SortIcon col="source" />
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, i) => (
              <tr key={i} className="tableRow">
                <td className="tableCell">
                  <span className={styles.sevBadge} style={{ color: severityColor(row.severity) }}>
                    {row.severity}
                  </span>
                </td>
                <td className="tableCell tableCellTruncate" title={row.name}>{row.name}</td>
                <td className="tableCell tableCellMono tableCellTruncate" title={getTargetDisplay(row)}>
                  {(() => {
                    const display = getTargetDisplay(row)
                    const href = getTargetHref(row)
                    return href ? <ExternalLink href={href}>{display}</ExternalLink> : display
                  })()}
                </td>
                <td className="tableCell">
                  <span className={styles.sourceBadge}>{row.findingSource}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartCard>
  )
}
