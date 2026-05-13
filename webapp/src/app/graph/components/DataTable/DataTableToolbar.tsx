'use client'

import { memo, useMemo } from 'react'
import { Search, Download } from 'lucide-react'
import { NODE_COLORS } from '../../config'
import styles from './DataTableToolbar.module.css'

interface DataTableToolbarProps {
  globalFilter: string
  onGlobalFilterChange: (value: string) => void
  nodeTypeCounts: Record<string, number>
  activeNodeTypes: Set<string>
  onToggleNodeType: (type: string) => void
  onSelectAllTypes: () => void
  onClearAllTypes: () => void
  onExport: () => void
  totalRows: number
  filteredRows: number
}

export const DataTableToolbar = memo(function DataTableToolbar({
  globalFilter,
  onGlobalFilterChange,
  nodeTypeCounts,
  activeNodeTypes,
  onToggleNodeType,
  onSelectAllTypes,
  onClearAllTypes,
  onExport,
  totalRows,
  filteredRows,
}: DataTableToolbarProps) {
  const sortedTypes = useMemo(
    () => Object.keys(nodeTypeCounts).sort(),
    [nodeTypeCounts]
  )

  return (
    <div className={styles.toolbar}>
      <div className={styles.searchWrapper}>
        <Search size={14} className={styles.searchIcon} />
        <input
          type="text"
          className={styles.searchInput}
          placeholder="Search by name or type..."
          value={globalFilter}
          onChange={e => onGlobalFilterChange(e.target.value)}
          aria-label="Search nodes"
        />
      </div>

      <button className={styles.exportBtn} onClick={onExport} aria-label="Export to CSV">
        <Download size={14} />
        <span>CSV</span>
      </button>

      <div className={styles.chipActions}>
        <button className={styles.chipAction} onClick={onSelectAllTypes}>All</button>
        <button className={styles.chipAction} onClick={onClearAllTypes}>None</button>
      </div>

      <div className={styles.chips}>
        {sortedTypes.map(type => {
          const isActive = activeNodeTypes.has(type)
          const color = NODE_COLORS[type] || NODE_COLORS.Default
          return (
            <button
              key={type}
              className={`${styles.typeChip} ${isActive ? styles.typeChipActive : ''}`}
              onClick={() => onToggleNodeType(type)}
              style={{ '--chip-color': color } as React.CSSProperties}
              aria-pressed={isActive}
            >
              <span className={styles.chipDot} />
              <span className={styles.chipLabel}>{type}</span>
              <span className={styles.chipCount}>{nodeTypeCounts[type]}</span>
            </button>
          )
        })}
      </div>

      <span className={styles.rowCount}>
        {filteredRows === totalRows
          ? `${totalRows} nodes`
          : `${filteredRows} of ${totalRows} nodes`}
      </span>
    </div>
  )
})
