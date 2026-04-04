'use client'

import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import { GraphToolbar } from './components/GraphToolbar'
import { GraphCanvas } from './components/GraphCanvas'
import { NodeDrawer } from './components/NodeDrawer'
import { AIAssistantDrawer } from './components/AIAssistantDrawer'
import { PageBottomBar } from './components/PageBottomBar'
import { ReconConfirmModal } from './components/ReconConfirmModal'
import { GvmConfirmModal } from './components/GvmConfirmModal'
import { ReconLogsDrawer } from './components/ReconLogsDrawer'
import { ViewTabs, type ViewMode, type TunnelStatus } from './components/ViewTabs'
import { DataTable } from './components/DataTable'
import { JsReconTable, exportJsReconXlsx } from './components/JsReconTable'
import type { JsReconData } from './components/JsReconTable'
import { ActiveSessions } from './components/ActiveSessions'
import { RoeViewer } from './components/RoeViewer'
import { KaliTerminal } from './components/KaliTerminal'
import { GraphViews } from './components/GraphViews'
import { GitHubStarBanner } from './components/GitHubStarBanner'
import { useGraphData, useDimensions, useNodeSelection, useTableData, useGraphViews } from './hooks'
import { exportToExcel } from './utils/exportExcel'
import { useTheme, useSession, useReconStatus, useReconSSE, useGvmStatus, useGvmSSE, useGithubHuntStatus, useGithubHuntSSE, useTrufflehogStatus, useTrufflehogSSE, useActiveSessions } from '@/hooks'
import { useProjectById } from '@/hooks/useProjects'
import { useProject } from '@/providers/ProjectProvider'
import { GVM_PHASES, GITHUB_HUNT_PHASES, TRUFFLEHOG_PHASES } from '@/lib/recon-types'
import { OtherScansModal } from './components/OtherScansModal/OtherScansModal'
import styles from './page.module.css'

export default function GraphPage() {
  const router = useRouter()
  const { projectId, userId, currentProject, setCurrentProject, isLoading: projectLoading } = useProject()

  const [activeView, setActiveView] = useState<ViewMode>('graph')

  // Full project data for RoE viewer (only fetched when RoE tab is active)
  const { data: fullProject } = useProjectById(activeView === 'roe' ? projectId : null)
  const [is3D, setIs3D] = useState(true)
  const [showLabels, setShowLabels] = useState(true)
  const [isAIOpen, setIsAIOpen] = useState(false)
  const [isReconModalOpen, setIsReconModalOpen] = useState(false)
  const [activeLogsDrawer, setActiveLogsDrawer] = useState<'recon' | 'gvm' | 'githubHunt' | 'trufflehog' | null>(null)
  const [hasReconData, setHasReconData] = useState(false)
  const [hasGvmData, setHasGvmData] = useState(false)
  const [hasGithubHuntData, setHasGithubHuntData] = useState(false)
  const [hasTrufflehogData, setHasTrufflehogData] = useState(false)
  const [gvmAvailable, setGvmAvailable] = useState(true)
  const [isOtherScansModalOpen, setIsOtherScansModalOpen] = useState(false)
  const [hasGithubToken, setHasGithubToken] = useState(false)
  const [graphStats, setGraphStats] = useState<{ totalNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [gvmStats, setGvmStats] = useState<{ totalGvmNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [isGvmModalOpen, setIsGvmModalOpen] = useState(false)
  const contentRef = useRef<HTMLDivElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)

  const { selectedNode, drawerOpen, selectNode, clearSelection } = useNodeSelection()
  const dimensions = useDimensions(contentRef)

  // Close all drawers when project changes
  useEffect(() => {
    setIsAIOpen(false)
    setActiveLogsDrawer(null)
    clearSelection()
  }, [projectId, clearSelection])

  // Track .body position for fixed-position log drawers
  useEffect(() => {
    const body = bodyRef.current
    if (!body) return
    const update = () => {
      const rect = body.getBoundingClientRect()
      document.documentElement.style.setProperty('--drawer-top', `${rect.top}px`)
      document.documentElement.style.setProperty('--drawer-bottom', `${window.innerHeight - rect.bottom}px`)
    }
    update()
    const ro = new ResizeObserver(update)
    ro.observe(body)
    window.addEventListener('resize', update)
    return () => { ro.disconnect(); window.removeEventListener('resize', update) }
  }, [])
  // Check if GVM stack is installed
  useEffect(() => {
    fetch('/api/gvm/available')
      .then(res => res.json())
      .then(data => setGvmAvailable(data.available ?? false))
      .catch(() => setGvmAvailable(false))
  }, [])

  const { isDark } = useTheme()
  const { sessionId, resetSession, switchSession } = useSession()

  // Data filters (formerly graph views) -- used in tab selector, Graph Map, Data Table, AI drawer
  const { views: graphViews, deleteView, executeCypher, fetchViews } = useGraphViews(projectId)
  const [selectedFilterId, setSelectedFilterId] = useState<string | null>(null)
  const [filterGraphData, setFilterGraphData] = useState<{ nodes: any[]; links: any[]; projectId: string } | null>(null)
  const [filterLoading, setFilterLoading] = useState(false)

  // Resolve the Cypher query for the selected filter (stable across graphViews refetches)
  const selectedFilterCypherQuery = useMemo(() => {
    if (!selectedFilterId) return null
    return graphViews.find(v => v.id === selectedFilterId)?.cypherQuery ?? null
  }, [selectedFilterId, graphViews])

  // Active filter Cypher for the agent
  const selectedFilterCypher = selectedFilterCypherQuery ?? undefined

  // Clear filter if the selected filter gets deleted
  const handleDeleteFilter = useCallback(async (id: string) => {
    const ok = await deleteView(id)
    if (ok && selectedFilterId === id) {
      setSelectedFilterId(null)
    }
  }, [deleteView, selectedFilterId])

  // Callback for when a new filter is created in the GraphViews tab
  const handleFilterCreated = useCallback(() => {
    fetchViews()
  }, [fetchViews])

  const handleFilterCreatedAndSelect = useCallback((filterId: string) => {
    fetchViews()
    setSelectedFilterId(filterId)
    setActiveView('graph')
  }, [fetchViews])

  // Agent status polling — lightweight fetch every 5s for toolbar indicators
  const [agentSummary, setAgentSummary] = useState<{
    activeCount: number
    conversations: Array<{
      id: string
      title: string
      currentPhase: string
      iterationCount: number
      agentRunning: boolean
      sessionId: string
    }>
  }>({ activeCount: 0, conversations: [] })

  useEffect(() => {
    if (!projectId || !userId) return
    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/conversations?projectId=${projectId}&userId=${userId}`)
        if (!res.ok) return
        const convs = await res.json()
        const active = convs.filter((c: any) => c.agentRunning)
        setAgentSummary({ activeCount: active.length, conversations: convs })
      } catch { /* ignore fetch errors */ }
    }
    fetchStatus()
    const interval = setInterval(fetchStatus, 5000)
    return () => clearInterval(interval)
  }, [projectId, userId])

  // Tunnel status polling — check every 10s which tunnels are active
  const [tunnelStatus, setTunnelStatus] = useState<TunnelStatus>()

  useEffect(() => {
    const fetchTunnels = async () => {
      try {
        const res = await fetch('/api/agent/tunnel-status')
        if (res.ok) setTunnelStatus(await res.json())
      } catch { /* ignore */ }
    }
    fetchTunnels()
    const interval = setInterval(fetchTunnels, 10000)
    return () => clearInterval(interval)
  }, [])

  // Check if user has a GitHub access token configured in global settings
  useEffect(() => {
    if (!userId) return
    const checkToken = async () => {
      try {
        const res = await fetch(`/api/users/${userId}/settings`)
        if (res.ok) {
          const data = await res.json()
          setHasGithubToken((data.githubAccessToken || '').length > 0)
        }
      } catch { /* ignore */ }
    }
    checkToken()
  }, [userId])

  // Recon status hook - must be before useGraphData to provide isReconRunning
  const {
    state: reconState,
    isLoading: isReconLoading,
    startRecon,
    stopRecon,
    pauseRecon,
    resumeRecon,
  } = useReconStatus({
    projectId,
    enabled: !!projectId,
  })

  // Check if recon is running to enable auto-refresh of graph data
  const isReconRunning = reconState?.status === 'running' || reconState?.status === 'starting'

  // Check if any agent conversation is active (writes attack chain nodes to graph)
  const isAgentRunning = agentSummary.activeCount > 0

  // Graph data with auto-refresh every 5 seconds while recon or agent is running
  const { data, isLoading, error, refetch: refetchGraph } = useGraphData(projectId, {
    isReconRunning,
    isAgentRunning,
  })

  // Execute filter Cypher when selected filter changes or when graph data refreshes
  // (so the filtered view stays in sync with live recon/agent data)
  const filterRefreshKey = data?.nodes.length ?? 0
  useEffect(() => {
    if (!selectedFilterCypherQuery || !projectId) {
      setFilterGraphData(null)
      return
    }
    let cancelled = false
    setFilterLoading(true)
    executeCypher(selectedFilterCypherQuery).then(result => {
      if (cancelled) return
      setFilterLoading(false)
      if ('error' in result) {
        setFilterGraphData(null)
      } else {
        setFilterGraphData({ nodes: result.nodes, links: result.links, projectId })
      }
    })
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFilterCypherQuery, projectId, executeCypher, filterRefreshKey])

  // Recon logs SSE hook
  const {
    logs: reconLogs,
    currentPhase,
    currentPhaseNumber,
    clearLogs,
  } = useReconSSE({
    projectId,
    enabled: reconState?.status === 'running' || reconState?.status === 'starting' || reconState?.status === 'paused' || reconState?.status === 'stopping',
  })

  // GVM status hook
  const {
    state: gvmState,
    isLoading: isGvmLoading,
    error: gvmError,
    startGvm,
    stopGvm,
    pauseGvm,
    resumeGvm,
  } = useGvmStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGvmRunning = gvmState?.status === 'running' || gvmState?.status === 'starting'

  // GVM logs SSE hook
  const {
    logs: gvmLogs,
    currentPhase: gvmCurrentPhase,
    currentPhaseNumber: gvmCurrentPhaseNumber,
    clearLogs: clearGvmLogs,
  } = useGvmSSE({
    projectId,
    enabled: gvmState?.status === 'running' || gvmState?.status === 'starting' || gvmState?.status === 'paused' || gvmState?.status === 'stopping',
  })

  // GitHub Hunt status hook
  const {
    state: githubHuntState,
    isLoading: isGithubHuntLoading,
    startGithubHunt,
    stopGithubHunt,
    pauseGithubHunt,
    resumeGithubHunt,
  } = useGithubHuntStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGithubHuntRunning = githubHuntState?.status === 'running' || githubHuntState?.status === 'starting'

  // GitHub Hunt logs SSE hook
  const {
    logs: githubHuntLogs,
    currentPhase: githubHuntCurrentPhase,
    currentPhaseNumber: githubHuntCurrentPhaseNumber,
    clearLogs: clearGithubHuntLogs,
  } = useGithubHuntSSE({
    projectId,
    enabled: githubHuntState?.status === 'running' || githubHuntState?.status === 'starting' || githubHuntState?.status === 'paused' || githubHuntState?.status === 'stopping',
  })

  // TruffleHog status hook
  const {
    state: trufflehogState,
    startTrufflehog,
    stopTrufflehog,
    pauseTrufflehog,
    resumeTrufflehog,
  } = useTrufflehogStatus({
    projectId,
    enabled: !!projectId,
  })

  const isTrufflehogRunning = trufflehogState?.status === 'running' || trufflehogState?.status === 'starting'

  // TruffleHog logs SSE hook
  const {
    logs: trufflehogLogs,
    currentPhase: trufflehogCurrentPhase,
    currentPhaseNumber: trufflehogCurrentPhaseNumber,
    clearLogs: clearTrufflehogLogs,
  } = useTrufflehogSSE({
    projectId,
    enabled: trufflehogState?.status === 'running' || trufflehogState?.status === 'starting' || trufflehogState?.status === 'paused' || trufflehogState?.status === 'stopping',
  })

  // Active sessions hook — polls kali-sandbox session list
  const activeSessions = useActiveSessions({
    enabled: true,
    fastPoll: activeView === 'sessions',
  })

  // ── Table view state (lifted from DataTable) ──────────────────────────
  const tableRows = useTableData(data)
  const filterTableRows = useTableData(filterGraphData ?? undefined)
  const [globalFilter, setGlobalFilter] = useState('')
  const [tableViewMode, setTableViewMode] = useState<'all' | 'jsRecon'>('all')
  const [jsReconSearch, setJsReconSearch] = useState('')
  const [jsReconData, setJsReconData] = useState<JsReconData | null>(null)
  const [activeNodeTypes, setActiveNodeTypes] = useState<Set<string>>(new Set())
  const [tableInitialized, setTableInitialized] = useState(false)

  const nodeTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    tableRows.forEach(r => {
      counts[r.node.type] = (counts[r.node.type] || 0) + 1
    })
    return counts
  }, [tableRows])

  const filterNodeTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    filterTableRows.forEach(r => {
      counts[r.node.type] = (counts[r.node.type] || 0) + 1
    })
    return counts
  }, [filterTableRows])

  const effectiveNodeTypeCounts = selectedFilterId ? filterNodeTypeCounts : nodeTypeCounts
  const nodeTypes = useMemo(() => Object.keys(effectiveNodeTypeCounts).sort(), [effectiveNodeTypeCounts])

  // Reset active node types when filter selection changes
  useEffect(() => {
    setActiveNodeTypes(new Set(nodeTypes))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFilterId])

  useEffect(() => {
    if (nodeTypes.length > 0 && !tableInitialized) {
      setActiveNodeTypes(new Set(nodeTypes))
      setTableInitialized(true)
    } else if (tableInitialized) {
      // Auto-enable newly discovered node types (e.g. attack chain nodes created mid-session)
      setActiveNodeTypes((prev: Set<string>) => {
        const newTypes = nodeTypes.filter((t: string) => !prev.has(t))
        if (newTypes.length === 0) return prev
        const next = new Set(prev)
        newTypes.forEach((t: string) => next.add(t))
        return next
      })
    }
  }, [nodeTypes, tableInitialized])

  const filteredByTypeOnly = useMemo(() => {
    if (activeNodeTypes.size === 0) return []
    return tableRows.filter(r => activeNodeTypes.has(r.node.type))
  }, [tableRows, activeNodeTypes])

  // ── Session (chain) visibility ──────────────────────────────────────
  const CHAIN_NODE_TYPES = useMemo(() => new Set([
    'AttackChain', 'ChainStep', 'ChainDecision', 'ChainFailure', 'ChainFinding',
  ]), [])

  const effectiveBarData = selectedFilterId ? filterGraphData : data

  const sessionChainIds = useMemo(() => {
    if (!effectiveBarData) return []
    const ids = new Set<string>()
    for (const node of effectiveBarData.nodes) {
      const chainId = node.properties?.chain_id as string | undefined
      if (chainId && CHAIN_NODE_TYPES.has(node.type)) {
        ids.add(chainId)
      }
    }
    return Array.from(ids).sort()
  }, [effectiveBarData, CHAIN_NODE_TYPES])

  const sessionTitles = useMemo(() => {
    if (!effectiveBarData) return {} as Record<string, string>
    const titles: Record<string, string> = {}
    for (const node of effectiveBarData.nodes) {
      if (node.type === 'AttackChain') {
        const chainId = node.properties?.chain_id as string | undefined
        const title = node.properties?.title as string | undefined
        if (chainId && title) {
          titles[chainId] = title
        }
      }
    }
    return titles
  }, [effectiveBarData])

  const [hiddenSessions, setHiddenSessions] = useState<Set<string>>(new Set())

  // Auto-show newly discovered sessions
  useEffect(() => {
    setHiddenSessions((prev: Set<string>) => {
      const updated = new Set<string>()
      for (const id of prev) {
        if (sessionChainIds.includes(id)) updated.add(id)
      }
      return updated.size !== prev.size ? updated : prev
    })
  }, [sessionChainIds])

  const handleToggleSession = useCallback((chainId: string) => {
    setHiddenSessions((prev: Set<string>) => {
      const next = new Set(prev)
      if (next.has(chainId)) next.delete(chainId)
      else next.add(chainId)
      return next
    })
  }, [])

  const handleShowAllSessions = useCallback(() => {
    setHiddenSessions(new Set())
  }, [])

  const handleHideAllSessions = useCallback(() => {
    setHiddenSessions(new Set(sessionChainIds))
  }, [sessionChainIds])

  // "Hide other chains" / "Show all" toggle for the AI drawer
  const isOtherChainsHidden = useMemo(() => {
    if (hiddenSessions.size === 0) return false
    const otherChains = sessionChainIds.filter((id: string) => id !== sessionId)
    if (otherChains.length === 0) return false
    return otherChains.every((id: string) => hiddenSessions.has(id))
  }, [hiddenSessions, sessionChainIds, sessionId])

  const handleToggleOtherChains = useCallback(() => {
    const otherChains = sessionChainIds.filter((id: string) => id !== sessionId)
    setHiddenSessions((prev: Set<string>) => {
      const allOthersHidden = otherChains.every((id: string) => prev.has(id))
      if (allOthersHidden) {
        return new Set()
      } else {
        return new Set(otherChains)
      }
    })
  }, [sessionChainIds, sessionId])
  // ── End session visibility ────────────────────────────────────────

  // Table rows filtered by type + hidden sessions
  const filteredByType = useMemo(() => {
    if (hiddenSessions.size === 0) return filteredByTypeOnly
    return filteredByTypeOnly.filter((r: { node: { type: string; properties: Record<string, unknown> } }) => {
      if (CHAIN_NODE_TYPES.has(r.node.type)) {
        const chainId = r.node.properties?.chain_id as string | undefined
        if (chainId && hiddenSessions.has(chainId)) return false
      }
      return true
    })
  }, [filteredByTypeOnly, hiddenSessions, CHAIN_NODE_TYPES])

  // Filtered graph data for GraphCanvas (filter nodes by type + hidden sessions, then prune links)
  const filteredGraphData = useMemo(() => {
    if (!data) return undefined
    const allTypesActive = activeNodeTypes.size === nodeTypes.length
    const noSessionsHidden = hiddenSessions.size === 0
    if (allTypesActive && noSessionsHidden) return data // nothing filtered
    const filteredNodes = data.nodes.filter(n => {
      if (!activeNodeTypes.has(n.type)) return false
      // Hide chain nodes belonging to hidden sessions
      if (hiddenSessions.size > 0 && CHAIN_NODE_TYPES.has(n.type)) {
        const chainId = n.properties?.chain_id as string | undefined
        if (chainId && hiddenSessions.has(chainId)) return false
      }
      return true
    })
    const visibleIds = new Set(filteredNodes.map(n => n.id))
    const filteredLinks = data.links.filter(l => {
      const srcId = typeof l.source === 'string' ? l.source : l.source.id
      const tgtId = typeof l.target === 'string' ? l.target : l.target.id
      return visibleIds.has(srcId) && visibleIds.has(tgtId)
    })
    return { ...data, nodes: filteredNodes, links: filteredLinks }
  }, [data, activeNodeTypes, nodeTypes.length, hiddenSessions, CHAIN_NODE_TYPES])

  // Effective table rows: use filter data when a data filter is active
  const effectiveTableRows = selectedFilterId ? filterTableRows : filteredByType

  const textFilteredCount = useMemo(() => {
    if (!globalFilter) return effectiveTableRows.length
    const search = globalFilter.toLowerCase()
    return effectiveTableRows.filter(r =>
      r.node.name?.toLowerCase().includes(search) ||
      r.node.type?.toLowerCase().includes(search)
    ).length
  }, [effectiveTableRows, globalFilter])

  const handleToggleNodeType = useCallback((type: string) => {
    setActiveNodeTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      return next
    })
  }, [])

  const handleSelectAllTypes = useCallback(() => {
    setActiveNodeTypes(new Set(nodeTypes))
  }, [nodeTypes])

  const handleClearAllTypes = useCallback(() => {
    setActiveNodeTypes(new Set())
  }, [])

  const handleExportExcel = useCallback(() => {
    let rows = effectiveTableRows
    if (globalFilter) {
      const search = globalFilter.toLowerCase()
      rows = rows.filter(r =>
        r.node.name?.toLowerCase().includes(search) ||
        r.node.type?.toLowerCase().includes(search)
      )
    }
    exportToExcel(rows)
  }, [effectiveTableRows, globalFilter])

  // ── End table view state ──────────────────────────────────────────────

  // Check if recon data exists
  const checkReconData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/recon/${projectId}/download`, { method: 'HEAD' })
      setHasReconData(response.ok)
    } catch {
      setHasReconData(false)
    }
  }, [projectId])

  // Calculate graph stats when data changes
  useEffect(() => {
    if (data?.nodes) {
      const nodesByType: Record<string, number> = {}
      data.nodes.forEach(node => {
        const type = node.type || 'Unknown'
        nodesByType[type] = (nodesByType[type] || 0) + 1
      })
      setGraphStats({
        totalNodes: data.nodes.length,
        nodesByType,
      })
    } else {
      setGraphStats(null)
    }
  }, [data])

  // Calculate GVM-specific stats from graph data
  useEffect(() => {
    if (data?.nodes) {
      const gvmTypes: Record<string, number> = {}
      let total = 0
      data.nodes.forEach(node => {
        const isGvmVuln = node.type === 'Vulnerability' && node.properties?.source === 'gvm'
        const isGvmTech = node.type === 'Technology' && (node.properties?.detected_by as string[] | undefined)?.includes('gvm')
        if (isGvmVuln || isGvmTech) {
          const type = node.type || 'Unknown'
          gvmTypes[type] = (gvmTypes[type] || 0) + 1
          total++
        }
      })
      setGvmStats(total > 0 ? { totalGvmNodes: total, nodesByType: gvmTypes } : null)
    } else {
      setGvmStats(null)
    }
  }, [data])

  // Check if GVM data exists
  const checkGvmData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/gvm/${projectId}/download`, { method: 'HEAD' })
      setHasGvmData(response.ok)
    } catch {
      setHasGvmData(false)
    }
  }, [projectId])

  // Check if GitHub Hunt data exists
  const checkGithubHuntData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/github-hunt/${projectId}/download`, { method: 'HEAD' })
      setHasGithubHuntData(response.ok)
    } catch {
      setHasGithubHuntData(false)
    }
  }, [projectId])

  // Check if TruffleHog data exists
  const checkTrufflehogData = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/download`, { method: 'HEAD' })
      setHasTrufflehogData(response.ok)
    } catch {
      setHasTrufflehogData(false)
    }
  }, [projectId])

  // Check for recon/GVM/GitHub Hunt/TruffleHog data on mount and when project changes
  useEffect(() => {
    checkReconData()
    checkGvmData()
    checkGithubHuntData()
    checkTrufflehogData()
  }, [checkReconData, checkGvmData, checkGithubHuntData, checkTrufflehogData])

  // Refresh graph data when recon completes
  useEffect(() => {
    if (reconState?.status === 'completed' || reconState?.status === 'error') {
      refetchGraph()
      checkReconData()
    }
  }, [reconState?.status, refetchGraph, checkReconData])

  // Refresh graph when GVM scan completes
  useEffect(() => {
    if (gvmState?.status === 'completed' || gvmState?.status === 'error') {
      refetchGraph()
      checkGvmData()
    }
  }, [gvmState?.status, refetchGraph, checkGvmData])

  // Refresh when GitHub Hunt completes
  useEffect(() => {
    if (githubHuntState?.status === 'completed' || githubHuntState?.status === 'error') {
      refetchGraph()
      checkGithubHuntData()
    }
  }, [githubHuntState?.status, refetchGraph, checkGithubHuntData])

  // Refresh when TruffleHog completes
  useEffect(() => {
    if (trufflehogState?.status === 'completed' || trufflehogState?.status === 'error') {
      refetchGraph()
      checkTrufflehogData()
    }
  }, [trufflehogState?.status, refetchGraph, checkTrufflehogData])

  const handleToggleAI = useCallback(() => {
    setIsAIOpen((prev) => !prev)
  }, [])

  const handleCloseAI = useCallback(() => {
    setIsAIOpen(false)
  }, [])

  const handleToggleStealth = useCallback(async (newValue: boolean) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stealthMode: newValue }),
      })
      if (res.ok && currentProject) {
        setCurrentProject({ ...currentProject, stealthMode: newValue })
      }
    } catch (error) {
      console.error('Failed to toggle stealth mode:', error)
    }
  }, [projectId, currentProject, setCurrentProject])

  const handleToggleDeepThink = useCallback(async (newValue: boolean) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentDeepThinkEnabled: newValue }),
      })
      if (res.ok && currentProject) {
        setCurrentProject({ ...currentProject, agentDeepThinkEnabled: newValue })
      }
    } catch (error) {
      console.error('Failed to toggle deep think:', error)
    }
  }, [projectId, currentProject, setCurrentProject])

  const handleModelChange = useCallback(async (modelId: string) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentOpenaiModel: modelId }),
      })
      if (res.ok && currentProject) {
        setCurrentProject({ ...currentProject, agentOpenaiModel: modelId })
      }
    } catch (error) {
      console.error('Failed to change model:', error)
    }
  }, [projectId, currentProject, setCurrentProject])

  const handleStartRecon = useCallback(() => {
    setIsReconModalOpen(true)
  }, [])

  const handleConfirmRecon = useCallback(async () => {
    clearLogs()
    const result = await startRecon()
    if (result) {
      setIsReconModalOpen(false)
      setActiveLogsDrawer('recon')
    }
  }, [startRecon, clearLogs])

  const handleDownloadJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/recon/${projectId}/download`, '_blank')
  }, [projectId])

  const handleDeleteNode = useCallback(async (nodeId: string) => {
    if (!projectId) return
    const res = await fetch(`/api/graph?nodeId=${nodeId}&projectId=${projectId}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const data = await res.json()
      alert(data.error || 'Failed to delete node')
      return
    }
    refetchGraph()
  }, [projectId, refetchGraph])

  const handleToggleLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'recon' ? null : 'recon')
  }, [])

  const handleStartGvm = useCallback(() => {
    setIsGvmModalOpen(true)
  }, [])

  const handleConfirmGvm = useCallback(async () => {
    clearGvmLogs()
    const result = await startGvm()
    if (result) {
      setIsGvmModalOpen(false)
      setActiveLogsDrawer('gvm')
    }
  }, [startGvm, clearGvmLogs])

  const handleDownloadGvmJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/gvm/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGvmLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'gvm' ? null : 'gvm')
  }, [])

  const handleStartGithubHunt = useCallback(async () => {
    clearGithubHuntLogs()
    const result = await startGithubHunt()
    if (result) {
      setActiveLogsDrawer('githubHunt')
    }
  }, [startGithubHunt, clearGithubHuntLogs])

  const handleDownloadGithubHuntJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/github-hunt/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGithubHuntLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'githubHunt' ? null : 'githubHunt')
  }, [])

  const handleStartTrufflehog = useCallback(async () => {
    clearTrufflehogLogs()
    const result = await startTrufflehog()
    if (result) {
      setActiveLogsDrawer('trufflehog')
    }
  }, [startTrufflehog, clearTrufflehogLogs])

  const handleDownloadTrufflehogJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/trufflehog/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleTrufflehogLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'trufflehog' ? null : 'trufflehog')
  }, [])

  // Pause/Resume/Stop handlers
  const handlePauseRecon = useCallback(async () => { await pauseRecon() }, [pauseRecon])
  const handleResumeRecon = useCallback(async () => { await resumeRecon() }, [resumeRecon])
  const handleStopRecon = useCallback(async () => { await stopRecon() }, [stopRecon])
  const handlePauseGvm = useCallback(async () => { await pauseGvm() }, [pauseGvm])
  const handleResumeGvm = useCallback(async () => { await resumeGvm() }, [resumeGvm])
  const handleStopGvm = useCallback(async () => { await stopGvm() }, [stopGvm])
  const handlePauseGithubHunt = useCallback(async () => { await pauseGithubHunt() }, [pauseGithubHunt])
  const handleResumeGithubHunt = useCallback(async () => { await resumeGithubHunt() }, [resumeGithubHunt])
  const handleStopGithubHunt = useCallback(async () => { await stopGithubHunt() }, [stopGithubHunt])
  const handlePauseTrufflehog = useCallback(async () => { await pauseTrufflehog() }, [pauseTrufflehog])
  const handleResumeTrufflehog = useCallback(async () => { await resumeTrufflehog() }, [resumeTrufflehog])
  const handleStopTrufflehog = useCallback(async () => { await stopTrufflehog() }, [stopTrufflehog])

  // Emergency Pause All — freezes every running pipeline and agent at once
  const isAnyPipelineRunning = isReconRunning || isGvmRunning || isGithubHuntRunning || isTrufflehogRunning || isAgentRunning
  const [isEmergencyPausing, setIsEmergencyPausing] = useState(false)

  // Auto-clear the pausing state once all pipelines have actually stopped
  useEffect(() => {
    if (isEmergencyPausing && !isAnyPipelineRunning) {
      setIsEmergencyPausing(false)
    }
  }, [isEmergencyPausing, isAnyPipelineRunning])

  const handleEmergencyPauseAll = useCallback(async () => {
    setIsEmergencyPausing(true)
    const tasks: Promise<unknown>[] = []
    if (reconState?.status === 'running' || reconState?.status === 'starting') {
      tasks.push(pauseRecon())
    }
    if (gvmState?.status === 'running' || gvmState?.status === 'starting') {
      tasks.push(pauseGvm())
    }
    if (githubHuntState?.status === 'running' || githubHuntState?.status === 'starting') {
      tasks.push(pauseGithubHunt())
    }
    if (trufflehogState?.status === 'running' || trufflehogState?.status === 'starting') {
      tasks.push(pauseTrufflehog())
    }
    // Stop all running AI agent conversations
    tasks.push(fetch('/api/agent/emergency-stop-all', { method: 'POST' }))
    await Promise.allSettled(tasks)
  }, [reconState?.status, gvmState?.status, githubHuntState?.status, trufflehogState?.status, pauseRecon, pauseGvm, pauseGithubHunt, pauseTrufflehog])

  // Show message if no project is selected
  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div className={styles.noProject}>
          <h2>No Project Selected</h2>
          <p>Select a project from the dropdown in the header or create a new one.</p>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <GraphToolbar
        projectId={projectId || ''}
        is3D={is3D}
        showLabels={showLabels}
        onToggle3D={setIs3D}
        onToggleLabels={setShowLabels}
        onToggleAI={handleToggleAI}
        isAIOpen={isAIOpen}
        // Target info
        targetDomain={currentProject?.targetDomain}
        subdomainList={currentProject?.subdomainList}
        // Recon props
        onStartRecon={handleStartRecon}
        onPauseRecon={handlePauseRecon}
        onResumeRecon={handleResumeRecon}
        onStopRecon={handleStopRecon}
        onDownloadJSON={handleDownloadJSON}
        onToggleLogs={handleToggleLogs}
        reconStatus={reconState?.status || 'idle'}
        hasReconData={hasReconData}
        isLogsOpen={activeLogsDrawer === 'recon'}
        // GVM props
        gvmAvailable={gvmAvailable}
        onStartGvm={handleStartGvm}
        onPauseGvm={handlePauseGvm}
        onResumeGvm={handleResumeGvm}
        onStopGvm={handleStopGvm}
        onDownloadGvmJSON={handleDownloadGvmJSON}
        onToggleGvmLogs={handleToggleGvmLogs}
        gvmStatus={gvmState?.status || 'idle'}
        hasGvmData={hasGvmData}
        isGvmLogsOpen={activeLogsDrawer === 'gvm'}
        // GitHub Hunt props
        onStartGithubHunt={handleStartGithubHunt}
        onPauseGithubHunt={handlePauseGithubHunt}
        onResumeGithubHunt={handleResumeGithubHunt}
        onStopGithubHunt={handleStopGithubHunt}
        onDownloadGithubHuntJSON={handleDownloadGithubHuntJSON}
        onToggleGithubHuntLogs={handleToggleGithubHuntLogs}
        githubHuntStatus={githubHuntState?.status || 'idle'}
        hasGithubHuntData={hasGithubHuntData}
        isGithubHuntLogsOpen={activeLogsDrawer === 'githubHunt'}
        // TruffleHog props
        onStartTrufflehog={handleStartTrufflehog}
        onPauseTrufflehog={handlePauseTrufflehog}
        onResumeTrufflehog={handleResumeTrufflehog}
        onStopTrufflehog={handleStopTrufflehog}
        onDownloadTrufflehogJSON={handleDownloadTrufflehogJSON}
        onToggleTrufflehogLogs={handleToggleTrufflehogLogs}
        trufflehogStatus={trufflehogState?.status || 'idle'}
        hasTrufflehogData={hasTrufflehogData}
        isTrufflehogLogsOpen={activeLogsDrawer === 'trufflehog'}
        // Other Scans modal
        onToggleOtherScansModal={() => setIsOtherScansModalOpen(prev => !prev)}
        // Stealth mode
        stealthMode={currentProject?.stealthMode}
        // RoE
        roeEnabled={currentProject?.roeEnabled}
        // Emergency Pause All
        onEmergencyPauseAll={handleEmergencyPauseAll}
        isAnyPipelineRunning={isAnyPipelineRunning}
        isEmergencyPausing={isEmergencyPausing}
        tunnelStatus={tunnelStatus}
        // Agent status
        agentActiveCount={agentSummary.activeCount}
        agentConversations={agentSummary.conversations}
      />

      <OtherScansModal
        isOpen={isOtherScansModalOpen}
        onClose={() => setIsOtherScansModalOpen(false)}
        hasReconData={hasReconData}
        hasGithubToken={hasGithubToken}
        // GitHub Hunt
        onStartGithubHunt={handleStartGithubHunt}
        onPauseGithubHunt={handlePauseGithubHunt}
        onResumeGithubHunt={handleResumeGithubHunt}
        onStopGithubHunt={handleStopGithubHunt}
        onDownloadGithubHuntJSON={handleDownloadGithubHuntJSON}
        onToggleGithubHuntLogs={handleToggleGithubHuntLogs}
        githubHuntStatus={githubHuntState?.status || 'idle'}
        hasGithubHuntData={hasGithubHuntData}
        isGithubHuntLogsOpen={activeLogsDrawer === 'githubHunt'}
        // TruffleHog
        onStartTrufflehog={handleStartTrufflehog}
        onPauseTrufflehog={handlePauseTrufflehog}
        onResumeTrufflehog={handleResumeTrufflehog}
        onStopTrufflehog={handleStopTrufflehog}
        onDownloadTrufflehogJSON={handleDownloadTrufflehogJSON}
        onToggleTrufflehogLogs={handleToggleTrufflehogLogs}
        trufflehogStatus={trufflehogState?.status || 'idle'}
        hasTrufflehogData={hasTrufflehogData}
        isTrufflehogLogsOpen={activeLogsDrawer === 'trufflehog'}
      />

      <ViewTabs
        activeView={activeView}
        onViewChange={setActiveView}
        globalFilter={globalFilter}
        onGlobalFilterChange={setGlobalFilter}
        onExport={handleExportExcel}
        totalRows={effectiveTableRows.length}
        filteredRows={textFilteredCount}
        sessionCount={activeSessions.totalCount}
        tunnelStatus={tunnelStatus}
        dataFilters={graphViews}
        selectedFilterId={selectedFilterId}
        onSelectFilter={setSelectedFilterId}
        onDeleteFilter={handleDeleteFilter}
        tableViewMode={tableViewMode}
        onTableViewModeChange={setTableViewMode}
        jsReconSearch={jsReconSearch}
        onJsReconSearchChange={setJsReconSearch}
        onJsReconExportXlsx={jsReconData ? () => exportJsReconXlsx(jsReconData) : undefined}
        jsReconMeta={jsReconData ? `${jsReconData.scan_metadata?.js_files_analyzed || 0} files${jsReconData.summary?.validated_keys?.live ? ` | ${jsReconData.summary.validated_keys.live} LIVE` : ''}` : undefined}
        is3D={is3D}
        showLabels={showLabels}
        onToggle3D={setIs3D}
        onToggleLabels={setShowLabels}
      />

      <div ref={bodyRef} className={styles.body}>
        {activeView === 'graph' && (
          <NodeDrawer
            node={selectedNode}
            isOpen={drawerOpen}
            onClose={clearSelection}
            onDeleteNode={handleDeleteNode}
          />
        )}

        <div ref={contentRef} className={styles.content}>
          {activeView === 'graph' ? (
            <GraphCanvas
              data={filterGraphData ?? filteredGraphData}
              isLoading={filterLoading || isLoading}
              error={error}
              projectId={projectId || ''}
              is3D={is3D}
              width={dimensions.width}
              height={dimensions.height}
              showLabels={showLabels}
              selectedNode={selectedNode}
              onNodeClick={selectNode}
              isDark={isDark}
              activeChainId={sessionId}
            />
          ) : activeView === 'graphViews' ? (
            <GraphViews
              projectId={projectId || ''}
              userId={userId || ''}
              modelConfigured={!!currentProject?.agentOpenaiModel}
              is3D={is3D}
              showLabels={showLabels}
              isDark={isDark}
              onFilterCreated={handleFilterCreated}
              onFilterCreatedAndSelect={handleFilterCreatedAndSelect}
            />
          ) : activeView === 'table' ? (
            tableViewMode === 'jsRecon' ? (
              <JsReconTable projectId={projectId} search={jsReconSearch} onDataLoaded={setJsReconData} />
            ) : (
              <DataTable
                data={filterGraphData ?? data}
                isLoading={filterLoading || isLoading}
                error={error}
                rows={effectiveTableRows}
                globalFilter={globalFilter}
                onGlobalFilterChange={setGlobalFilter}
              />
            )
          ) : activeView === 'sessions' ? (
            <ActiveSessions
              sessions={activeSessions.sessions}
              jobs={activeSessions.jobs}
              nonMsfSessions={activeSessions.nonMsfSessions}
              agentBusy={activeSessions.agentBusy}
              isLoading={activeSessions.isLoading}
              projectId={projectId || ''}
              onInteract={activeSessions.interactWithSession}
              onKillSession={activeSessions.killSession}
              onKillJob={activeSessions.killJob}
            />
          ) : activeView === 'terminal' ? (
            <KaliTerminal />
          ) : activeView === 'roe' ? (
            <RoeViewer
              projectId={projectId || ''}
              project={fullProject || {}}
            />
          ) : null}
        </div>

      </div>

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'recon'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={reconLogs}
        currentPhase={currentPhase}
        currentPhaseNumber={currentPhaseNumber}
        status={reconState?.status || 'idle'}
        errorMessage={reconState?.error}
        onClearLogs={clearLogs}
        onPause={handlePauseRecon}
        onResume={handleResumeRecon}
        onStop={handleStopRecon}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'gvm'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={gvmLogs}
        currentPhase={gvmCurrentPhase}
        currentPhaseNumber={gvmCurrentPhaseNumber}
        status={gvmState?.status || 'idle'}
        errorMessage={gvmState?.error}
        onClearLogs={clearGvmLogs}
        onPause={handlePauseGvm}
        onResume={handleResumeGvm}
        onStop={handleStopGvm}
        title="GVM Vulnerability Scan Logs"
        phases={GVM_PHASES}
        totalPhases={4}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'githubHunt'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={githubHuntLogs}
        currentPhase={githubHuntCurrentPhase}
        currentPhaseNumber={githubHuntCurrentPhaseNumber}
        status={githubHuntState?.status || 'idle'}
        errorMessage={githubHuntState?.error}
        onClearLogs={clearGithubHuntLogs}
        onPause={handlePauseGithubHunt}
        onResume={handleResumeGithubHunt}
        onStop={handleStopGithubHunt}
        title="GitHub Secret Hunt Logs"
        phases={GITHUB_HUNT_PHASES}
        totalPhases={3}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'trufflehog'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={trufflehogLogs}
        currentPhase={trufflehogCurrentPhase}
        currentPhaseNumber={trufflehogCurrentPhaseNumber}
        status={trufflehogState?.status || 'idle'}
        errorMessage={trufflehogState?.error}
        onClearLogs={clearTrufflehogLogs}
        onPause={handlePauseTrufflehog}
        onResume={handleResumeTrufflehog}
        onStop={handleStopTrufflehog}
        title="TruffleHog Secret Scanner Logs"
        phases={TRUFFLEHOG_PHASES}
        totalPhases={3}
      />

      <AIAssistantDrawer
        isOpen={isAIOpen}
        onClose={handleCloseAI}
        userId={userId || ''}
        projectId={projectId || ''}
        sessionId={sessionId || ''}
        onResetSession={resetSession}
        onSwitchSession={switchSession}
        modelName={currentProject?.agentOpenaiModel}
        onModelChange={handleModelChange}
        toolPhaseMap={currentProject?.agentToolPhaseMap}
        stealthMode={currentProject?.stealthMode}
        onToggleStealth={handleToggleStealth}
        deepThinkEnabled={currentProject?.agentDeepThinkEnabled}
        onToggleDeepThink={handleToggleDeepThink}
        onRefetchGraph={refetchGraph}
        isOtherChainsHidden={isOtherChainsHidden}
        onToggleOtherChains={handleToggleOtherChains}
        hasOtherChains={sessionChainIds.length > 1 || (sessionChainIds.length === 1 && sessionChainIds[0] !== sessionId)}
        requireToolConfirmation={currentProject?.agentRequireToolConfirmation ?? true}
        graphViewCypher={selectedFilterCypher}
      />

      <ReconConfirmModal
        isOpen={isReconModalOpen}
        onClose={() => setIsReconModalOpen(false)}
        onConfirm={handleConfirmRecon}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetDomain || 'Unknown'}
        ipMode={currentProject?.ipMode}
        targetIps={currentProject?.targetIps}
        stats={graphStats}
        isLoading={isReconLoading}
      />

      <GvmConfirmModal
        isOpen={isGvmModalOpen}
        onClose={() => setIsGvmModalOpen(false)}
        onConfirm={handleConfirmGvm}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetDomain || currentProject?.targetIps?.join(', ') || 'Unknown'}
        stats={gvmStats}
        isLoading={isGvmLoading}
        error={gvmError}
      />

      <GitHubStarBanner hasAttackChain={(graphStats?.nodesByType?.['AttackChain'] ?? 0) > 0} />

      <PageBottomBar
        data={effectiveBarData ?? undefined}
        is3D={is3D}
        showLabels={showLabels}
        activeView={activeView}
        tableViewMode={tableViewMode}
        activeNodeTypes={activeNodeTypes}
        nodeTypeCounts={effectiveNodeTypeCounts}
        onToggleNodeType={handleToggleNodeType}
        onSelectAllTypes={handleSelectAllTypes}
        onClearAllTypes={handleClearAllTypes}
        sessionChainIds={sessionChainIds}
        sessionTitles={sessionTitles}
        hiddenSessions={hiddenSessions}
        onToggleSession={handleToggleSession}
        onShowAllSessions={handleShowAllSessions}
        onHideAllSessions={handleHideAllSessions}
      />
    </div>
  )
}
