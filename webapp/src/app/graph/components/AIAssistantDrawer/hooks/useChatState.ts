import { useState, useRef, useMemo } from 'react'
import type { ChatItem, Message, FileDownloadItem } from '../types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from '../AgentTimeline'
import type { TodoItem } from '@/lib/websocket-types'
import type { Phase } from '../types'

export function useChatState() {
  const [chatItems, setChatItems] = useState<ChatItem[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isStopped, setIsStopped] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<Phase>('informational')
  const [attackPathType, setAttackPathType] = useState<string>('')
  const [iterationCount, setIterationCount] = useState(0)
  const [todoList, setTodoList] = useState<TodoItem[]>([])

  const isRestoringConversation = useRef(false)
  const itemIdCounter = useRef(0)

  const groupedChatItems = useMemo(() => {
    const result: Array<{
      type: 'message' | 'timeline' | 'file_download'
      content: Message | Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> | FileDownloadItem
    }> = []

    let currentTimelineGroup: Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> = []

    chatItems.forEach((item) => {
      if ('role' in item) {
        if (currentTimelineGroup.length > 0) {
          result.push({ type: 'timeline', content: currentTimelineGroup })
          currentTimelineGroup = []
        }
        result.push({ type: 'message', content: item as Message })
      } else if ('type' in item && item.type === 'file_download') {
        if (currentTimelineGroup.length > 0) {
          result.push({ type: 'timeline', content: currentTimelineGroup })
          currentTimelineGroup = []
        }
        result.push({ type: 'file_download', content: item as FileDownloadItem })
      } else if ('type' in item && (item.type === 'thinking' || item.type === 'tool_execution' || item.type === 'plan_wave' || item.type === 'deep_think')) {
        currentTimelineGroup.push(item as ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem)
      }
    })

    if (currentTimelineGroup.length > 0) {
      result.push({ type: 'timeline', content: currentTimelineGroup })
    }

    return result
  }, [chatItems])

  function resetChatState() {
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('')
    setIterationCount(0)
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    setInputValue('')
  }

  return {
    chatItems,
    setChatItems,
    inputValue,
    setInputValue,
    isLoading,
    setIsLoading,
    isStopped,
    setIsStopped,
    isStopping,
    setIsStopping,
    currentPhase,
    setCurrentPhase,
    attackPathType,
    setAttackPathType,
    iterationCount,
    setIterationCount,
    todoList,
    setTodoList,
    isRestoringConversation,
    itemIdCounter,
    groupedChatItems,
    resetChatState,
  }
}
