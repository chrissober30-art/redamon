'use client'

import { useState, useMemo, useEffect, useRef, Fragment } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getExpandedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
  type ExpandedState,
  type VisibilityState,
} from '@tanstack/react-table'
import {
  ChevronDown,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  Loader2,
  AlertCircle,
  Database,
  Columns3,
  Search,
  Download,
} from 'lucide-react'
import type { GraphData } from '../../types'
import { NODE_COLORS } from '../../config'
import { HIDDEN_KEYS, getNodeUrl } from '../../utils'
import { renderPropertyValue } from '../../utils/renderPropertyValue'
import { ExpandedRowDetail } from '../DataTable/ExpandedRowDetail'
import { ExternalLink } from '@/components/ui'
import { useTableData, type TableRow } from '../../hooks/useTableData'
import { useNodeDetailsPrefs } from '@/hooks/useUserPreferences'
import {
  groupRowsByType,
  deriveDynamicColumnKeys,
  toggleHiddenColumn,
} from './nodeDetailsHelpers'
import {
  exportNodeDetailsCsv,
  exportNodeDetailsJson,
  exportNodeDetailsMarkdown,
} from './exportNodeDetails'
import styles from './NodeDetailsTable.module.css'

interface NodeDetailsTableProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
}

const columnHelper = createColumnHelper<TableRow>()

export function NodeDetailsTable({ data, isLoading, error }: NodeDetailsTableProps) {
  // Build full TableRow set (rows + connection maps) using the existing hook.
  const allRows = useTableData(data)

  const { sortedTypes, typeCounts, rowsByType } = useMemo(
    () => groupRowsByType(allRows),
    [allRows]
  )

  // -- Selected type --------------------------------------------------------
  const [selectedNodeType, setSelectedNodeType] = useState<string | null>(null)
  useEffect(() => {
    if (selectedNodeType && typeCounts.has(selectedNodeType)) return
    setSelectedNodeType(sortedTypes[0] ?? null)
  }, [sortedTypes, typeCounts, selectedNodeType])

  const rows = useMemo(
    () => (selectedNodeType ? rowsByType.get(selectedNodeType) ?? [] : []),
    [rowsByType, selectedNodeType]
  )

  const dynamicColumnKeys = useMemo(() => deriveDynamicColumnKeys(rows), [rows])

  // -- Hideable column registry --------------------------------------------
  // Storage keys MUST be stable across data shapes since they're persisted
  // per-user. Property storage keys are the bare property name; the connection
  // count columns get fixed keys that can't collide with `prop:*` IDs.
  const FIXED_HIDEABLE = useMemo(
    () => [
      { storageKey: 'connectionsIn', columnId: 'connectionsIn', label: 'In' },
      { storageKey: 'connectionsOut', columnId: 'connectionsOut', label: 'Out' },
    ],
    []
  )
  const hideableColumns = useMemo(
    () => [
      ...dynamicColumnKeys.map(k => ({ storageKey: k, columnId: `prop:${k}`, label: k })),
      ...FIXED_HIDEABLE,
    ],
    [dynamicColumnKeys, FIXED_HIDEABLE]
  )

  // -- Persistent column visibility per node type --------------------------
  const { hiddenColumns, setHiddenColumns } = useNodeDetailsPrefs(selectedNodeType)
  const hiddenSet = useMemo(() => new Set(hiddenColumns), [hiddenColumns])
  const columnVisibility: VisibilityState = useMemo(() => {
    const v: VisibilityState = {}
    for (const c of hideableColumns) v[c.columnId] = !hiddenSet.has(c.storageKey)
    return v
  }, [hideableColumns, hiddenSet])

  // -- Build columns -------------------------------------------------------
  // Order: [expand, name, ...dynamic, In, Out]
  // In/Out live at the rightmost position and are user-hideable.
  const columns = useMemo(() => {
    const leading = [
      columnHelper.display({
        id: 'expand',
        header: '',
        size: 40,
        enableHiding: false,
        cell: ({ row }) => (
          <button
            className={styles.expandBtn}
            onClick={row.getToggleExpandedHandler()}
            aria-expanded={row.getIsExpanded()}
            aria-label={row.getIsExpanded() ? 'Collapse row' : 'Expand row'}
          >
            {row.getIsExpanded() ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        ),
      }),
      columnHelper.accessor(row => row.node.name, {
        id: 'name',
        header: 'Name',
        size: 320,
        enableHiding: false,
        cell: info => {
          const name = info.getValue()
          const url = getNodeUrl(info.row.original.node)
          if (url) {
            return (
              <span className={styles.nameCell} title={name}>
                <ExternalLink href={url}>{name}</ExternalLink>
              </span>
            )
          }
          return (
            <span className={styles.nameCell} title={name}>
              {name}
            </span>
          )
        },
      }),
    ]

    const dynamic = dynamicColumnKeys.map(key =>
      columnHelper.accessor(row => row.node.properties[key], {
        id: `prop:${key}`,
        header: key,
        size: 200,
        cell: info => (
          <span className={styles.propCell} title={String(info.getValue() ?? '')}>
            {renderPropertyValue(info.getValue())}
          </span>
        ),
      })
    )

    const trailing = [
      columnHelper.accessor(row => row.connectionsIn.length, {
        id: 'connectionsIn',
        header: 'In',
        size: 70,
        cell: info => {
          const n = info.getValue()
          return n > 0 ? (
            <span className={styles.connBadge}>{n}</span>
          ) : (
            <span className={styles.connEmpty}>0</span>
          )
        },
      }),
      columnHelper.accessor(row => row.connectionsOut.length, {
        id: 'connectionsOut',
        header: 'Out',
        size: 70,
        cell: info => {
          const n = info.getValue()
          return n > 0 ? (
            <span className={styles.connBadge}>{n}</span>
          ) : (
            <span className={styles.connEmpty}>0</span>
          )
        },
      }),
    ]

    return [...leading, ...dynamic, ...trailing]
  }, [dynamicColumnKeys])

  // -- Search + sorting + expansion ---------------------------------------
  const [globalFilter, setGlobalFilter] = useState('')
  const [sorting, setSorting] = useState<SortingState>([])
  const [expanded, setExpanded] = useState<ExpandedState>({})

  // Reset transient state when type changes
  useEffect(() => {
    setExpanded({})
    setSorting([])
    setGlobalFilter('')
  }, [selectedNodeType])

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter, expanded, columnVisibility },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    globalFilterFn: (row, _columnId, filterValue) => {
      const search = String(filterValue).toLowerCase()
      if (!search) return true
      const name = row.original.node.name?.toLowerCase() || ''
      if (name.includes(search)) return true
      const props = row.original.node.properties as Record<string, unknown>
      for (const k of Object.keys(props)) {
        if (HIDDEN_KEYS.has(k)) continue
        const v = props[k]
        if (v == null) continue
        if (String(v).toLowerCase().includes(search)) return true
      }
      return false
    },
    initialState: { pagination: { pageSize: 50 } },
    getRowCanExpand: () => true,
  })

  const filteredRowCount = table.getFilteredRowModel().rows.length
  const visibleColCount = table.getVisibleLeafColumns().length

  // -- Type / column dropdown UI state ------------------------------------
  const [typeMenuOpen, setTypeMenuOpen] = useState(false)
  const [colsMenuOpen, setColsMenuOpen] = useState(false)
  const typeMenuRef = useRef<HTMLDivElement>(null)
  const colsMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!typeMenuOpen) return
    const onClick = (e: MouseEvent) => {
      if (!typeMenuRef.current?.contains(e.target as Node)) setTypeMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [typeMenuOpen])

  useEffect(() => {
    if (!colsMenuOpen) return
    const onClick = (e: MouseEvent) => {
      if (!colsMenuRef.current?.contains(e.target as Node)) setColsMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [colsMenuOpen])

  function toggleColumn(storageKey: string) {
    setHiddenColumns(toggleHiddenColumn(hiddenColumns, storageKey))
  }
  function showAllColumns() {
    setHiddenColumns([])
  }
  function hideAllColumns() {
    setHiddenColumns(hideableColumns.map(c => c.storageKey))
  }

  const visibleHideableCount = hideableColumns.filter(c => !hiddenSet.has(c.storageKey)).length
  const totalHideableCount = hideableColumns.length

  // -- Export handlers -----------------------------------------------------
  // Exports honor: (1) the selected node type, (2) the active search filter,
  // (3) the user's per-type column visibility prefs.
  const buildExportInput = () => ({
    nodeType: selectedNodeType ?? 'Nodes',
    rows: table.getFilteredRowModel().rows.map(r => r.original),
    visibleDynamicKeys: dynamicColumnKeys.filter(k => !hiddenSet.has(k)),
    showIn: !hiddenSet.has('connectionsIn'),
    showOut: !hiddenSet.has('connectionsOut'),
  })
  const [exporting, setExporting] = useState<'csv' | 'json' | 'md' | null>(null)
  const runExport = async (format: 'csv' | 'json' | 'md', fn: () => Promise<void>) => {
    if (exporting) return
    setExporting(format)
    try { await fn() } finally { setExporting(null) }
  }
  const handleExportCsv = () => runExport('csv', () => exportNodeDetailsCsv(buildExportInput()))
  const handleExportJson = () => runExport('json', () => exportNodeDetailsJson(buildExportInput()))
  const handleExportMarkdown = () => runExport('md', () => exportNodeDetailsMarkdown(buildExportInput()))

  // -- States --------------------------------------------------------------
  if (isLoading) {
    return (
      <div className={styles.stateContainer}>
        <Loader2 size={32} className={styles.spinner} />
        <p className={styles.stateText}>Loading graph data...</p>
      </div>
    )
  }
  if (error) {
    return (
      <div className={styles.stateContainer}>
        <AlertCircle size={32} className={styles.errorIcon} />
        <p className={styles.stateText}>Failed to load graph data</p>
        <p className={styles.stateSubtext}>{error.message}</p>
      </div>
    )
  }
  if (!data || data.nodes.length === 0 || sortedTypes.length === 0) {
    return (
      <div className={styles.stateContainer}>
        <Database size={32} className={styles.emptyIcon} />
        <p className={styles.stateText}>No data yet</p>
        <p className={styles.stateSubtext}>Run a reconnaissance scan to populate the graph.</p>
      </div>
    )
  }

  const selectedColor =
    (selectedNodeType && NODE_COLORS[selectedNodeType]) || NODE_COLORS.Default

  return (
    <div className={styles.container}>
      {/* Toolbar */}
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search…"
              value={globalFilter}
              onChange={e => setGlobalFilter(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <span className={styles.rowCount}>
            {filteredRowCount === rows.length ? `${rows.length}` : `${filteredRowCount}/${rows.length}`}
          </span>
        </div>
        <div className={styles.toolbarRight}>
          {/* Export buttons */}
          <button
            className={styles.exportBtn}
            onClick={handleExportCsv}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to CSV"
            title="Export to CSV"
          >
            {exporting === 'csv'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>CSV</span>
          </button>
          <button
            className={styles.exportBtn}
            onClick={handleExportJson}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to JSON"
            title="Export to JSON"
          >
            {exporting === 'json'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>JSON</span>
          </button>
          <button
            className={styles.exportBtn}
            onClick={handleExportMarkdown}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to Markdown"
            title="Export to Markdown"
          >
            {exporting === 'md'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>MD</span>
          </button>

          {/* Type selector */}
          <div ref={typeMenuRef} className={styles.menuContainer}>
            <button
              className={styles.menuButton}
              onClick={() => setTypeMenuOpen(o => !o)}
              aria-haspopup="listbox"
              aria-expanded={typeMenuOpen}
            >
              <span className={styles.typeDot} style={{ background: selectedColor }} />
              <span className={styles.menuButtonLabel}>{selectedNodeType ?? 'Select type'}</span>
              {selectedNodeType && (
                <span className={styles.menuButtonCount}>
                  {typeCounts.get(selectedNodeType)}
                </span>
              )}
              <ChevronDown size={14} />
            </button>
            {typeMenuOpen && (
              <div className={styles.dropdownMenu} role="listbox">
                {sortedTypes.map(type => (
                  <button
                    key={type}
                    role="option"
                    aria-selected={type === selectedNodeType}
                    className={`${styles.dropdownItem} ${type === selectedNodeType ? styles.dropdownItemActive : ''}`}
                    onClick={() => {
                      setSelectedNodeType(type)
                      setTypeMenuOpen(false)
                    }}
                  >
                    <span
                      className={styles.typeDot}
                      style={{ background: NODE_COLORS[type] || NODE_COLORS.Default }}
                    />
                    <span className={styles.dropdownItemLabel}>{type}</span>
                    <span className={styles.dropdownItemCount}>{typeCounts.get(type)}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Columns menu */}
          <div ref={colsMenuRef} className={styles.menuContainer}>
            <button
              className={styles.menuButton}
              onClick={() => setColsMenuOpen(o => !o)}
              disabled={totalHideableCount === 0}
              aria-haspopup="menu"
              aria-expanded={colsMenuOpen}
            >
              <Columns3 size={14} />
              <span className={styles.menuButtonLabel}>Columns</span>
              <span className={styles.menuButtonCount}>
                {visibleHideableCount}/{totalHideableCount}
              </span>
              <ChevronDown size={14} />
            </button>
            {colsMenuOpen && (
              <div className={styles.dropdownMenu} role="menu">
                <div className={styles.dropdownActions}>
                  <button className={styles.dropdownActionBtn} onClick={showAllColumns}>
                    Show all
                  </button>
                  <button className={styles.dropdownActionBtn} onClick={hideAllColumns}>
                    Hide all
                  </button>
                </div>
                <div className={styles.dropdownList}>
                  {hideableColumns.map(col => {
                    const visible = !hiddenSet.has(col.storageKey)
                    return (
                      <label key={col.storageKey} className={styles.dropdownCheckRow}>
                        <input
                          type="checkbox"
                          checked={visible}
                          onChange={() => toggleColumn(col.storageKey)}
                        />
                        <span>{col.label}</span>
                      </label>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    className={styles.th}
                    style={{ width: header.getSize() }}
                    onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                    aria-sort={
                      header.column.getIsSorted() === 'asc'
                        ? 'ascending'
                        : header.column.getIsSorted() === 'desc'
                          ? 'descending'
                          : 'none'
                    }
                  >
                    <div className={styles.thContent}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (
                        <span className={styles.sortIcon}>
                          {header.column.getIsSorted() === 'asc' ? (
                            <ArrowUp size={12} />
                          ) : header.column.getIsSorted() === 'desc' ? (
                            <ArrowDown size={12} />
                          ) : (
                            <ArrowUpDown size={12} />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <Fragment key={row.id}>
                <tr className={`${styles.tr} ${row.getIsExpanded() ? styles.trExpanded : ''}`}>
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className={styles.td}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {row.getIsExpanded() && (
                  <tr className={styles.trExpandedDetail}>
                    <td colSpan={visibleColCount} className={styles.tdExpanded}>
                      <ExpandedRowDetail row={row.original} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className={styles.pagination}>
        <div className={styles.paginationInfo}>
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount() || 1}
          <span className={styles.paginationRows}>({filteredRowCount} rows)</span>
        </div>
        <div className={styles.paginationControls}>
          <button
            className={styles.pageBtn}
            onClick={() => table.setPageIndex(0)}
            disabled={!table.getCanPreviousPage()}
            aria-label="First page"
          >
            <ChevronsLeft size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="Previous page"
          >
            <ChevronLeft size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Next page"
          >
            <ChevronRight size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.setPageIndex(table.getPageCount() - 1)}
            disabled={!table.getCanNextPage()}
            aria-label="Last page"
          >
            <ChevronsRight size={14} />
          </button>
        </div>
        <div className={styles.pageSizeSelect}>
          <select
            value={table.getState().pagination.pageSize}
            onChange={e => table.setPageSize(Number(e.target.value))}
            className={styles.select}
            aria-label="Rows per page"
          >
            {[10, 25, 50, 100].map(size => (
              <option key={size} value={size}>
                {size} rows
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
}
