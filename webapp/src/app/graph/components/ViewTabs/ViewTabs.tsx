'use client'

import { memo, useState, useRef, useEffect, useCallback } from 'react'
import { Waypoints, Table2, Terminal, Shield, Search, Download, SquareTerminal, Filter, Plus, Trash2, X } from 'lucide-react'
import styles from './ViewTabs.module.css'

export type ViewMode = 'graph' | 'graphViews' | 'table' | 'sessions' | 'terminal' | 'roe'

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

interface DataFilterView {
  id: string
  name: string
  description?: string
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
  // Data filter selector
  dataFilters?: DataFilterView[]
  selectedFilterId?: string | null
  onSelectFilter?: (id: string | null) => void
  onDeleteFilter?: (id: string) => void
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
  dataFilters,
  selectedFilterId,
  onSelectFilter,
  onDeleteFilter,
}: ViewTabsProps) {
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const selectedFilter = dataFilters?.find(f => f.id === selectedFilterId)
  const hasFilters = dataFilters && dataFilters.length > 0

  // Close dropdown on outside click
  useEffect(() => {
    if (!dropdownOpen) return
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [dropdownOpen])

  const handleSelectFilter = useCallback((id: string) => {
    if (id === selectedFilterId) {
      onSelectFilter?.(null)
    } else {
      onSelectFilter?.(id)
    }
    setDropdownOpen(false)
  }, [selectedFilterId, onSelectFilter])

  const handleDeleteFilter = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    onDeleteFilter?.(id)
  }, [onDeleteFilter])

  const handleClearFilter = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onSelectFilter?.(null)
    setDropdownOpen(false)
  }, [onSelectFilter])

  return (
    <div className={styles.tabBar}>
      <div className={styles.tabs} role="tablist" aria-label="View mode">
        {/* Filter group -- create + select as a unified element */}
        <div className={styles.filterGroup}>
          <button
            role="tab"
            aria-selected={activeView === 'graphViews'}
            className={`${styles.filterGroupCreate} ${activeView === 'graphViews' ? styles.filterGroupCreateActive : ''}`}
            onClick={() => onViewChange('graphViews')}
            title="Surface Shaper"
          >
            <Filter size={13} />
            <Plus size={10} className={styles.createFilterPlus} />
          </button>

          {hasFilters && (
            <div className={styles.filterGroupSelect} ref={dropdownRef}>
              <button
                className={`${styles.filterGroupPill} ${selectedFilter ? styles.filterGroupPillActive : ''}`}
                onClick={() => setDropdownOpen(prev => !prev)}
                title={selectedFilter ? `Active surface: ${selectedFilter.name}` : 'Select a surface'}
              >
                {selectedFilter ? (
                  <>
                    <span className={styles.filterPillName}>{selectedFilter.name}</span>
                    <span
                      className={styles.filterPillClear}
                      onClick={handleClearFilter}
                      title="Clear surface"
                    >
                      <X size={10} />
                    </span>
                  </>
                ) : (
                  <span className={styles.filterPillLabel}>Surfaces</span>
                )}
              </button>

              {dropdownOpen && (
                <div className={styles.filterDropdown}>
                  <div className={styles.filterDropdownHeader}>Surface Shapers</div>
                  <div className={styles.filterDropdownList}>
                    {dataFilters!.map(f => (
                      <div
                        key={f.id}
                        className={`${styles.filterDropdownItem} ${f.id === selectedFilterId ? styles.filterDropdownItemActive : ''}`}
                        onClick={() => handleSelectFilter(f.id)}
                      >
                        <div className={styles.filterDropdownInfo}>
                          <span className={styles.filterDropdownName}>{f.name}</span>
                          {f.description && (
                            <span className={styles.filterDropdownDesc}>{f.description}</span>
                          )}
                        </div>
                        <button
                          className={styles.filterDropdownDelete}
                          onClick={(e) => handleDeleteFilter(f.id, e)}
                          title="Delete surface"
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

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
          className={`${styles.tab} ${activeView === 'terminal' ? styles.tabActive : ''}`}
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
              <span className={styles.tunnelBadge} title={`Tunnel active -- used for reverse shells. Target connects to ${tunnelStatus.ngrok.host}:${tunnelStatus.ngrok.port} which forwards to kali-sandbox:4444`}>
                <span className={styles.tunnelDot} />
                <span className={styles.tunnelName}>ngrok</span>
                <span className={styles.tunnelSep}>|</span>
                <span className={styles.tunnelHost}>{tunnelStatus.ngrok.host}:{tunnelStatus.ngrok.port}</span>
              </span>
            )}
            {tunnelStatus.chisel?.active && (
              <span className={styles.tunnelBadge} title={`Tunnel active -- used for reverse shells. Target connects to ${tunnelStatus.chisel.host}:${tunnelStatus.chisel.port} which forwards to kali-sandbox:4444. Web delivery at ${tunnelStatus.chisel.host}:${tunnelStatus.chisel.srvPort} -> kali-sandbox:8080`}>
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
