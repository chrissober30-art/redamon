'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import { capecToUrl, cveToUrl, cweToUrl } from '@/lib/url-utils'
import { severityColor } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './DataTable.module.css'
import type { CveChain } from '../types'

interface CveChainTableProps {
  data: CveChain[] | undefined
  isLoading: boolean
}

type SortKey = 'cvss' | 'tech' | 'cveId'

export function CveChainTable({ data, isLoading }: CveChainTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('cvss')
  const [sortAsc, setSortAsc] = useState(false)

  const sorted = useMemo(() => {
    if (!data) return []
    // Deduplicate by cveId (same CVE may appear multiple times with different CWE/CAPEC)
    const seen = new Map<string, CveChain>()
    for (const row of data) {
      if (!seen.has(row.cveId) || (row.capecId && !seen.get(row.cveId)!.capecId)) {
        seen.set(row.cveId, row)
      }
    }
    return [...seen.values()].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'cvss') cmp = (a.cvss || 0) - (b.cvss || 0)
      else if (sortKey === 'tech') cmp = a.tech.localeCompare(b.tech)
      else cmp = a.cveId.localeCompare(b.cveId)
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

  return (
    <ChartCard title="CVE Danger Chains" subtitle={`${sorted.length} CVEs · Tech → CVE → CWE → CAPEC`} isLoading={isLoading} isEmpty={!sorted.length}>
      <div className={styles.tableWrap}>
        <table className="table">
          <thead className="tableHeader">
            <tr>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('tech')}>
                Technology <SortIcon col="tech" />
              </th>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('cveId')}>
                CVE <SortIcon col="cveId" />
              </th>
              <th className="tableHeaderCell tableHeaderSortable" onClick={() => toggleSort('cvss')}>
                CVSS <SortIcon col="cvss" />
              </th>
              <th className="tableHeaderCell">
                CWE
              </th>
              <th className="tableHeaderCell">
                Attack Pattern
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, i) => (
              <tr key={i} className="tableRow">
                <td className="tableCell tableCellTruncate" title={row.tech}>
                  {row.tech}{row.techVersion ? ` ${row.techVersion}` : ''}
                </td>
                <td className="tableCell tableCellMono" style={{ fontSize: '10px' }}>
                  <span style={{ color: severityColor(row.cveSeverity || 'unknown') }}>
                    <ExternalLink href={cveToUrl(row.cveId)}>{row.cveId}</ExternalLink>
                  </span>
                </td>
                <td className="tableCell tableCellMono">
                  {row.cvss != null ? (
                    <span style={{ color: severityColor(row.cveSeverity || 'unknown') }}>
                      {row.cvss.toFixed(1)}
                    </span>
                  ) : '-'}
                </td>
                <td className="tableCell tableCellTruncate" title={row.cweName || ''} style={{ fontSize: '10px' }}>
                  {row.cweId ? <ExternalLink href={cweToUrl(row.cweId)}>{row.cweId}</ExternalLink> : '-'}
                </td>
                <td className="tableCell tableCellTruncate" title={row.capecName || ''} style={{ fontSize: '10px' }}>
                  {row.capecId ? (
                    <>
                      <ExternalLink href={capecToUrl(row.capecId)}>{row.capecId}</ExternalLink>
                      {row.capecName ? `: ${row.capecName}` : ''}
                    </>
                  ) : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartCard>
  )
}
