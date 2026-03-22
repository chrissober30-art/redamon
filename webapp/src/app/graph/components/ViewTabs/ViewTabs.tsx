'use client'

import { memo } from 'react'
import { Waypoints, Table2, Terminal, Shield, Search, Download, SquareTerminal } from 'lucide-react'
import styles from './ViewTabs.module.css'

export type ViewMode = 'graph' | 'table' | 'sessions' | 'terminal' | 'roe'

export interface TunnelInfo {
  active: boolean
  host?: string
  port?: number
  srvPort?: number
}

export interface TunnelStatus {
  ngrok: TunnelInfo
  chisel: TunnelInfo
}

interface ViewTabsProps {
  activeView: ViewMode
  onViewChange: (view: ViewMode) => void
  // Table-only controls
  globalFilter?: string
  onGlobalFilterChange?: (value: string) => void
  onExport?: () => void
  totalRows?: number
  filteredRows?: number
  // Sessions badge
  sessionCount?: number
  // Tunnel status
  tunnelStatus?: TunnelStatus
}

export const ViewTabs = memo(function ViewTabs({
  activeView,
  onViewChange,
  globalFilter,
  onGlobalFilterChange,
  onExport,
  totalRows,
  filteredRows,
  sessionCount,
  tunnelStatus,
}: ViewTabsProps) {
  return (
    <div className={styles.tabBar}>
      <div className={styles.tabs} role="tablist" aria-label="View mode">
        <button
          role="tab"
          aria-selected={activeView === 'graph'}
          className={`${styles.tab} ${activeView === 'graph' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('graph')}
        >
          <Waypoints size={14} />
          <span>Graph Map</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'table'}
          className={`${styles.tab} ${activeView === 'table' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('table')}
        >
          <Table2 size={14} />
          <span>Data Table</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'sessions'}
          className={`${styles.tab} ${activeView === 'sessions' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('sessions')}
        >
          <Terminal size={14} />
          <span>Reverse Shell</span>
          {sessionCount != null && sessionCount > 0 && (
            <span className={styles.badge}>{sessionCount}</span>
          )}
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'terminal'}
          className={`${styles.tab} ${activeView === 'terminal' ? styles.tabActive : ''} ${activeView === 'terminal' ? styles.tabTerminal : ''}`}
          onClick={() => onViewChange('terminal')}
        >
          <SquareTerminal size={14} />
          <span>RedAmon Terminal</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'roe'}
          className={`${styles.tab} ${activeView === 'roe' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('roe')}
        >
          <Shield size={14} />
          <span>RoE</span>
        </button>
      </div>

      <div className={styles.rightSection}>
        {(tunnelStatus?.ngrok?.active || tunnelStatus?.chisel?.active) && (
          <div className={styles.tunnelBadges}>
            {tunnelStatus.ngrok?.active && (
              <span className={styles.tunnelBadge} title={`Tunnel active — used for reverse shells. Target connects to ${tunnelStatus.ngrok.host}:${tunnelStatus.ngrok.port} which forwards to kali-sandbox:4444`}>
                <span className={styles.tunnelDot} />
                <span className={styles.tunnelName}>ngrok</span>
                <span className={styles.tunnelSep}>|</span>
                <span className={styles.tunnelHost}>{tunnelStatus.ngrok.host}:{tunnelStatus.ngrok.port}</span>
              </span>
            )}
            {tunnelStatus.chisel?.active && (
              <span className={styles.tunnelBadge} title={`Tunnel active — used for reverse shells. Target connects to ${tunnelStatus.chisel.host}:${tunnelStatus.chisel.port} which forwards to kali-sandbox:4444. Web delivery at ${tunnelStatus.chisel.host}:${tunnelStatus.chisel.srvPort} → kali-sandbox:8080`}>
                <span className={styles.tunnelDot} />
                <span className={styles.tunnelName}>chisel</span>
                <span className={styles.tunnelSep}>|</span>
                <span className={styles.tunnelHost}>{tunnelStatus.chisel.host}:{tunnelStatus.chisel.port}</span>
              </span>
            )}
          </div>
        )}

      {activeView === 'table' && onGlobalFilterChange && (
        <div className={styles.tableControls}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search..."
              value={globalFilter || ''}
              onChange={e => onGlobalFilterChange(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <span className={styles.rowCount}>
            {filteredRows === totalRows
              ? `${totalRows}`
              : `${filteredRows}/${totalRows}`}
          </span>
          <button className={styles.exportBtn} onClick={onExport} aria-label="Export to Excel">
            <Download size={12} />
            <span>XLSX</span>
          </button>
        </div>
      )}
      </div>
    </div>
  )
})
