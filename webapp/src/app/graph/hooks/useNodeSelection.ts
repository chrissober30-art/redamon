import { useState, useCallback } from 'react'
import { GraphNode } from '../types'

interface UseNodeSelectionReturn {
  selectedNode: GraphNode | null
  drawerOpen: boolean
  expandedPath: GraphNode[]
  expandedChild: GraphNode | null
  selectNode: (node: GraphNode) => void
  clearSelection: () => void
  expandChild: (node: GraphNode) => void
  collapseChild: () => void
}

/**
 * Custom hook for managing node selection state.
 *
 * `expandedPath` is a stack of children the user drilled into from the root cluster.
 * Nested clusters push another entry; the Back button pops one. `expandedChild`
 * (top of stack) is kept for back-compat with the existing drawer signature.
 */
export function useNodeSelection(): UseNodeSelectionReturn {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [expandedPath, setExpandedPath] = useState<GraphNode[]>([])

  const selectNode = useCallback((node: GraphNode) => {
    setSelectedNode(node)
    setExpandedPath([])
    setDrawerOpen(true)
  }, [])

  const clearSelection = useCallback(() => {
    setDrawerOpen(false)
    setSelectedNode(null)
    setExpandedPath([])
  }, [])

  const expandChild = useCallback((node: GraphNode) => {
    setExpandedPath(prev => [...prev, node])
  }, [])

  const collapseChild = useCallback(() => {
    setExpandedPath(prev => prev.slice(0, -1))
  }, [])

  return {
    selectedNode,
    drawerOpen,
    expandedPath,
    expandedChild: expandedPath[expandedPath.length - 1] ?? null,
    selectNode,
    clearSelection,
    expandChild,
    collapseChild,
  }
}
