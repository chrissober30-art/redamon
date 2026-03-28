import { useState, useCallback, useEffect } from 'react'
import type { Conversation } from '@/hooks/useConversations'
import type { TodoItem } from '@/lib/websocket-types'
import type { ChatItem, Message, FileDownloadItem, Phase } from '../types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from '../AgentTimeline'

interface ConversationRestorationDeps {
  // From useConversations
  loadConversation: (id: string) => Promise<any>
  deleteConversation: (id: string) => Promise<void>
  fetchConversations: () => Promise<void>
  // Props
  onSwitchSession?: (sessionId: string) => void
  onRefetchGraph?: () => void
  projectId: string
  userId: string
  // From useChatState
  setChatItems: React.Dispatch<React.SetStateAction<ChatItem[]>>
  setCurrentPhase: (v: Phase) => void
  setAttackPathType: (v: string) => void
  setIterationCount: (v: number) => void
  setIsLoading: (v: boolean) => void
  setIsStopped: (v: boolean) => void
  setTodoList: (v: TodoItem[]) => void
  isRestoringConversation: React.MutableRefObject<boolean>
  shouldAutoScroll: React.MutableRefObject<boolean>
  // From useInteractionState
  setAwaitingApproval: (v: boolean) => void
  setApprovalRequest: (v: any) => void
  setAwaitingQuestion: (v: boolean) => void
  setQuestionRequest: (v: any) => void
  setAwaitingToolConfirmation: (v: boolean) => void
  setToolConfirmationRequest: (v: any) => void
  awaitingApprovalRef: React.MutableRefObject<boolean>
  awaitingQuestionRef: React.MutableRefObject<boolean>
  awaitingToolConfirmationRef: React.MutableRefObject<boolean>
  pendingApprovalToolId: React.MutableRefObject<string | null>
  pendingApprovalWaveId: React.MutableRefObject<string | null>
  // Main component
  handleNewChat: () => void
}

export function useConversationRestoration(deps: ConversationRestorationDeps) {
  const {
    loadConversation, deleteConversation, fetchConversations,
    onSwitchSession, onRefetchGraph,
    projectId, userId,
    setChatItems, setCurrentPhase, setAttackPathType, setIterationCount,
    setIsLoading, setIsStopped, setTodoList,
    isRestoringConversation, shouldAutoScroll,
    setAwaitingApproval, setApprovalRequest,
    setAwaitingQuestion, setQuestionRequest,
    setAwaitingToolConfirmation, setToolConfirmationRequest,
    awaitingApprovalRef, awaitingQuestionRef, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    handleNewChat,
  } = deps

  const [conversationId, setConversationId] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)

  // Fetch + auto-refresh conversations when history panel opens
  useEffect(() => {
    if (showHistory && projectId && userId) {
      fetchConversations()
      const interval = setInterval(fetchConversations, 5000)
      return () => clearInterval(interval)
    }
  }, [showHistory, projectId, userId, fetchConversations])

  const handleSelectConversation = useCallback(async (conv: Conversation) => {
    const full = await loadConversation(conv.id)
    if (!full) return

    let lastTodoList: TodoItem[] = []
    let lastApprovalRequest: any = null
    let lastQuestionRequest: any = null
    let lastToolConfirmationRequest: any = null
    let lastRenderedPhase: string = ''
    let lastAttackPathType: string = ''
    let hasWorkAfterApproval = false
    let hasWorkAfterQuestion = false
    let hasWorkAfterToolConfirmation = false

    // --- Proper tool_start ↔ tool_complete pairing ---
    const duplicateStartIds = new Set<string>()
    const duplicateCompleteIds = new Set<string>()
    {
      const recentStarts = new Map<string, number>()
      const recentCompletes = new Map<string, number>()
      for (const msg of full.messages) {
        const d = msg.data as any
        const t = new Date(msg.createdAt).getTime()
        if (msg.type === 'tool_start' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${JSON.stringify(d?.tool_args || {})}`
          const prev = recentStarts.get(fp)
          if (prev && t - prev < 60000) {
            duplicateStartIds.add(msg.id)
          } else {
            recentStarts.set(fp, t)
          }
        }
        if (msg.type === 'tool_complete' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${(d?.raw_output || '').slice(0, 500)}`
          const prev = recentCompletes.get(fp)
          if (prev && t - prev < 60000) {
            duplicateCompleteIds.add(msg.id)
          } else {
            recentCompletes.set(fp, t)
          }
        }
      }
    }

    const standaloneStartsByName = new Map<string, { id: string; createdAt: string }[]>()
    const standaloneCompletesByName = new Map<string, { id: string; createdAt: string }[]>()
    for (const msg of full.messages) {
      const d = msg.data as any
      if (msg.type === 'tool_start' && !d?.wave_id && !duplicateStartIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneStartsByName.has(name)) standaloneStartsByName.set(name, [])
        standaloneStartsByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
      if (msg.type === 'tool_complete' && !d?.wave_id && !duplicateCompleteIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneCompletesByName.has(name)) standaloneCompletesByName.set(name, [])
        standaloneCompletesByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
    }

    const consumedStartIds = new Set<string>()
    const completeToStartTime = new Map<string, Date>()
    for (const [name, completes] of standaloneCompletesByName) {
      const starts = standaloneStartsByName.get(name) || []
      for (let i = 0; i < completes.length && i < starts.length; i++) {
        consumedStartIds.add(starts[i].id)
        completeToStartTime.set(completes[i].id, new Date(starts[i].createdAt))
      }
    }

    const seenThinkingKeys = new Set<string>()
    const seenRunningToolKeys = new Set<string>()

    const restored: ChatItem[] = full.messages.map((msg: { id: string; type: string; data: unknown; createdAt: string }) => {
      const data = msg.data as any

      if (msg.type === 'thinking' || msg.type === 'tool_start' || msg.type === 'tool_complete') {
        if (lastApprovalRequest) hasWorkAfterApproval = true
        if (lastQuestionRequest) hasWorkAfterQuestion = true
        if (lastToolConfirmationRequest) hasWorkAfterToolConfirmation = true
      }

      if (msg.type === 'thinking') {
        const key = (data.thought || '').slice(0, 200)
        if (seenThinkingKeys.has(key)) return null
        seenThinkingKeys.add(key)
      }

      if (msg.type === 'user_message' || msg.type === 'assistant_message') {
        const restoredTier = data.response_tier || (data.task_complete ? 'full_report' : undefined)
        return {
          type: 'message',
          id: msg.id,
          role: msg.type === 'user_message' ? 'user' : 'assistant',
          content: data.content || '',
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
          isGuidance: data.isGuidance || false,
          isReport: restoredTier === 'full_report' || (!data.response_tier && (data.isReport || data.task_complete || false)),
          responseTier: restoredTier,
          error: data.error || null,
        } as Message
      } else if (msg.type === 'thinking') {
        return {
          type: 'thinking',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          thought: data.thought || '',
          reasoning: data.reasoning || '',
          action: 'thinking',
          updated_todo_list: [],
        } as ThinkingItem
      } else if (msg.type === 'tool_start') {
        if (data.wave_id) return null
        if (duplicateStartIds.has(msg.id)) return null
        if (consumedStartIds.has(msg.id)) return null
        const runKey = `${data.tool_name || ''}::${JSON.stringify(data.tool_args || {})}`
        if (seenRunningToolKeys.has(runKey)) return null
        seenRunningToolKeys.add(runKey)
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: 'running',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_complete') {
        if (data.wave_id) return null
        if (duplicateCompleteIds.has(msg.id)) return null
        const rawOutput = data.raw_output || ''
        const startTime = completeToStartTime.get(msg.id)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: data.success ? 'success' : 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
        } as ToolExecutionItem
      } else if (msg.type === 'error') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: data.message,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'task_complete') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: data.message || '',
          phase: data.final_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'guidance') {
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: data.content || '',
          isGuidance: true,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'file_ready') {
        return {
          type: 'file_download',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          filepath: data.filepath || '',
          filename: data.filename || '',
          description: data.description || '',
          source: data.source || '',
        } as FileDownloadItem
      } else if (msg.type === 'todo_update') {
        lastTodoList = data.todo_list || []
        return null
      } else if (msg.type === 'phase_update') {
        if (data.attack_path_type) lastAttackPathType = data.attack_path_type
        const phase = data.current_phase || 'unknown'
        if (phase !== lastRenderedPhase) {
          lastRenderedPhase = phase
          return {
            type: 'message',
            id: msg.id,
            role: 'assistant',
            content: `**Phase:** ${phase}` + (data.iteration_count ? ` — Step ${data.iteration_count}` : ''),
            phase,
            timestamp: new Date(msg.createdAt),
          } as Message
        }
        return null
      } else if (msg.type === 'approval_request') {
        lastApprovalRequest = data
        hasWorkAfterApproval = false
        const parts = [`**Phase Transition Request:** ${data.from_phase || '?'} → ${data.to_phase || '?'}`]
        if (data.reason) parts.push(`\n**Reason:** ${data.reason}`)
        if (data.planned_actions?.length) parts.push(`\n**Planned Actions:**\n${data.planned_actions.map((a: string) => `- ${a}`).join('\n')}`)
        if (data.risks?.length) parts.push(`\n**Risks:**\n${data.risks.map((r: string) => `- ${r}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: parts.join('\n'),
          phase: data.from_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'approval_response') {
        lastApprovalRequest = null
        hasWorkAfterApproval = true
        const label = data.decision === 'approve'
          ? 'Approved phase transition'
          : data.decision === 'modify'
          ? `Modified: ${data.modification || ''}`
          : 'Aborted phase transition'
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: label,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'question_request') {
        lastQuestionRequest = data
        hasWorkAfterQuestion = false
        const qParts = [`**Agent Question:** ${data.question || ''}`]
        if (data.context) qParts.push(`\n> ${data.context}`)
        if (data.options?.length) qParts.push(`\n**Options:**\n${data.options.map((o: string) => `- ${o}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: qParts.join('\n'),
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'answer_response') {
        lastQuestionRequest = null
        hasWorkAfterQuestion = true
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: `Answer: ${data.answer || ''}`,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'tool_confirmation_request') {
        lastToolConfirmationRequest = data
        hasWorkAfterToolConfirmation = false
        const confMode = data.mode || 'single'
        const confTools = data.tools || []
        if (confMode === 'plan') {
          return {
            type: 'plan_wave',
            id: msg.id,
            timestamp: new Date(msg.createdAt),
            wave_id: '',
            plan_rationale: data.reasoning || '',
            tool_count: confTools.length,
            tools: confTools.map((t: any, idx: number) => ({
              type: 'tool_execution' as const,
              id: `${msg.id}-tool-${idx}`,
              timestamp: new Date(msg.createdAt),
              tool_name: t.tool_name || '',
              tool_args: t.tool_args || {},
              status: 'pending_approval' as const,
              output_chunks: [],
            })),
            status: 'pending_approval',
          } as PlanWaveItem
        }
        const tool = confTools[0] || {}
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: tool.tool_name || '',
          tool_args: tool.tool_args || {},
          status: 'pending_approval',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_confirmation_response') {
        lastToolConfirmationRequest = null
        hasWorkAfterToolConfirmation = true
        return { _toolConfResponse: true, decision: data.decision } as any
      } else if (msg.type === 'plan_start') {
        return { _planStartLink: true, wave_id: data.wave_id || '', msg_id: msg.id, timestamp: new Date(msg.createdAt), plan_rationale: data.plan_rationale || '', tool_count: data.tool_count || 0 } as any
      } else if (msg.type === 'deep_think') {
        return {
          type: 'deep_think',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          trigger_reason: data.trigger_reason || '',
          analysis: data.analysis || '',
          iteration: data.iteration || 0,
          phase: data.phase || '',
        } as DeepThinkItem
      } else if (msg.type === 'plan_complete') {
        return null
      }
      return null
    }).filter((item: ChatItem | null): item is ChatItem => item !== null)

    // Post-pass: apply tool_confirmation_response decisions
    {
      const markers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._toolConfResponse) {
          markers.push(i)
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.status === 'pending_approval' && (prev.type === 'tool_execution' || prev.type === 'plan_wave')) {
              if (item.decision === 'approve') {
                if (prev.type === 'plan_wave') {
                  restored[j] = { ...prev, status: 'running', tools: [] }
                } else {
                  restored.splice(j, 1)
                  for (let m = 0; m < markers.length; m++) {
                    if (markers[m] > j) markers[m]--
                  }
                  i--
                }
              } else {
                restored[j] = { ...prev, status: 'error', final_output: 'Rejected by user' }
              }
              break
            }
          }
        }
      }
      for (let k = markers.length - 1; k >= 0; k--) {
        restored.splice(markers[k], 1)
      }
    }

    // Post-pass: link plan_start markers to existing PlanWaveItems
    {
      const planStartMarkers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._planStartLink) {
          planStartMarkers.push(i)
          let linked = false
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.type === 'plan_wave' && prev.wave_id === '') {
              restored[j] = {
                ...prev,
                wave_id: item.wave_id,
                plan_rationale: item.plan_rationale || prev.plan_rationale,
                tool_count: item.tool_count || prev.tool_count,
                status: prev.status === 'pending_approval' ? 'pending_approval' : 'running',
              }
              linked = true
              break
            }
          }
          if (!linked) {
            restored[i] = {
              type: 'plan_wave',
              id: item.msg_id,
              timestamp: item.timestamp,
              wave_id: item.wave_id,
              plan_rationale: item.plan_rationale,
              tool_count: item.tool_count,
              tools: [],
              status: 'running',
            } as PlanWaveItem
            continue
          }
        }
      }
      for (let k = planStartMarkers.length - 1; k >= 0; k--) {
        if ((restored[planStartMarkers[k]] as any)._planStartLink) {
          restored.splice(planStartMarkers[k], 1)
        }
      }
    }

    // Post-pass: nest wave tool_complete items
    const waveToolStartTimes = new Map<string, Date>()
    for (const msg of full.messages) {
      if (msg.type === 'tool_start' && (msg.data as any)?.wave_id) {
        const d = msg.data as any
        const si = d.step_index ?? ''
        waveToolStartTimes.set(`${d.wave_id}:${d.tool_name}:${si}`, new Date(msg.createdAt))
      }
    }

    const waveToolCompletes = full.messages.filter(
      (m: any) => m.type === 'tool_complete' && (m.data as any)?.wave_id
    )
    for (const msg of waveToolCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        const rawOutput = data.raw_output || ''
        const si = data.step_index ?? ''
        const startTime = waveToolStartTimes.get(`${data.wave_id}:${data.tool_name}:${si}`)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        const newTools = [...wave.tools, {
          type: 'tool_execution' as const,
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: (data.success ? 'success' : 'error') as 'success' | 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
          step_index: data.step_index,
        }]
        restored[waveIdx] = { ...wave, tools: newTools, tool_count: Math.max(wave.tool_count, newTools.length) }
      }
    }

    // Apply plan_complete statuses
    const planCompletes = full.messages.filter((m: any) => m.type === 'plan_complete')
    for (const msg of planCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        let status: PlanWaveItem['status'] = 'success'
        if (data.failed === data.total_steps) status = 'error'
        else if (data.failed > 0) status = 'partial'
        restored[waveIdx] = { ...wave, status }
      }
    }

    // Apply plan_analysis data
    const planAnalyses = full.messages.filter((m: any) => m.type === 'plan_analysis')
    for (const msg of planAnalyses) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        restored[waveIdx] = {
          ...wave,
          interpretation: data.interpretation || '',
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
        }
      }
    }

    // Sort by timestamp
    restored.sort((a: any, b: any) => {
      const ta = a.timestamp instanceof Date ? a.timestamp.getTime() : new Date(a.timestamp).getTime()
      const tb = b.timestamp instanceof Date ? b.timestamp.getTime() : new Date(b.timestamp).getTime()
      return ta - tb
    })

    // Apply state
    setChatItems(restored)
    setConversationId(conv.id)
    setCurrentPhase((conv.currentPhase || 'informational') as Phase)
    setAttackPathType(lastAttackPathType)
    setIterationCount(conv.iterationCount || 0)
    setIsLoading(conv.agentRunning)
    setIsStopped(false)
    setTodoList(lastTodoList)
    shouldAutoScroll.current = true
    setShowHistory(false)

    if (lastApprovalRequest && !hasWorkAfterApproval) {
      setAwaitingApproval(true)
      setApprovalRequest(lastApprovalRequest)
      awaitingApprovalRef.current = true
    } else {
      setAwaitingApproval(false)
      setApprovalRequest(null)
    }
    if (lastQuestionRequest && !hasWorkAfterQuestion) {
      setAwaitingQuestion(true)
      setQuestionRequest(lastQuestionRequest)
      awaitingQuestionRef.current = true
    } else {
      setAwaitingQuestion(false)
      setQuestionRequest(null)
    }
    if (lastToolConfirmationRequest && !hasWorkAfterToolConfirmation) {
      setAwaitingToolConfirmation(true)
      setToolConfirmationRequest(lastToolConfirmationRequest)
      awaitingToolConfirmationRef.current = true
      const pendingTool = restored.findLast?.((item: any) => item.type === 'tool_execution' && item.status === 'pending_approval')
      const pendingWave = restored.findLast?.((item: any) => item.type === 'plan_wave' && item.status === 'pending_approval')
      if (pendingWave) {
        pendingApprovalWaveId.current = (pendingWave as any).id
      } else if (pendingTool) {
        pendingApprovalToolId.current = (pendingTool as any).id
      }
    } else {
      setAwaitingToolConfirmation(false)
      setToolConfirmationRequest(null)
    }

    isRestoringConversation.current = true
    onSwitchSession?.(conv.sessionId)
  }, [loadConversation, onSwitchSession])

  const handleHistoryNewChat = useCallback(() => {
    setShowHistory(false)
    handleNewChat()
  }, [handleNewChat])

  const handleDeleteConversation = useCallback(async (id: string) => {
    await deleteConversation(id)
    onRefetchGraph?.()
    if (id === conversationId) {
      handleNewChat()
    }
  }, [deleteConversation, onRefetchGraph, conversationId, handleNewChat])

  return {
    conversationId,
    setConversationId,
    showHistory,
    setShowHistory,
    handleSelectConversation,
    handleHistoryNewChat,
    handleDeleteConversation,
  }
}
