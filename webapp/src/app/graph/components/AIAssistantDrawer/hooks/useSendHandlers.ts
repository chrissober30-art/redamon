import { useCallback, useRef, KeyboardEvent } from 'react'
import type { ApprovalRequestPayload, QuestionRequestPayload, ToolConfirmationRequestPayload } from '@/lib/websocket-types'
import type { ChatItem, Message } from '../types'

interface SendHandlersDeps {
  // Chat state
  inputValue: string
  setInputValue: (v: string) => void
  isLoading: boolean
  setIsLoading: (v: boolean) => void
  setIsStopped: (v: boolean) => void
  setIsStopping: (v: boolean) => void
  setChatItems: React.Dispatch<React.SetStateAction<ChatItem[]>>
  chatItems: ChatItem[]
  // Interaction state
  awaitingApproval: boolean
  setAwaitingApproval: (v: boolean) => void
  setApprovalRequest: (v: ApprovalRequestPayload | null) => void
  modificationText: string
  setModificationText: (v: string) => void
  awaitingQuestion: boolean
  setAwaitingQuestion: (v: boolean) => void
  questionRequest: QuestionRequestPayload | null
  setQuestionRequest: (v: QuestionRequestPayload | null) => void
  answerText: string
  setAnswerText: (v: string) => void
  selectedOptions: string[]
  setSelectedOptions: (v: string[]) => void
  awaitingToolConfirmation: boolean
  setAwaitingToolConfirmation: (v: boolean) => void
  setToolConfirmationRequest: (v: ToolConfirmationRequestPayload | null) => void
  // Refs
  isProcessingApproval: React.MutableRefObject<boolean>
  awaitingApprovalRef: React.MutableRefObject<boolean>
  isProcessingQuestion: React.MutableRefObject<boolean>
  awaitingQuestionRef: React.MutableRefObject<boolean>
  isProcessingToolConfirmation: React.MutableRefObject<boolean>
  awaitingToolConfirmationRef: React.MutableRefObject<boolean>
  pendingApprovalToolId: React.MutableRefObject<string | null>
  pendingApprovalWaveId: React.MutableRefObject<string | null>
  // WebSocket senders
  sendQuery: (q: string) => void
  sendGuidance: (m: string) => void
  sendApproval: (decision: 'approve' | 'modify' | 'abort', modification?: string) => void
  sendToolConfirmation: (decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => void
  sendAnswer: (answer: string) => void
  sendStop: () => void
  sendResume: () => void
  // Conversation
  conversationId: string | null
  setConversationId: (v: string | null) => void
  projectId: string
  userId: string
  sessionId: string
  createConversation: (sessionId: string) => Promise<any>
  saveMessage: (type: string, data: any) => void
  updateConvMeta: (updates: Record<string, any>) => Promise<void>
}

export function useSendHandlers(deps: SendHandlersDeps) {
  const {
    inputValue, setInputValue,
    isLoading, setIsLoading, setIsStopped, setIsStopping,
    setChatItems, chatItems,
    awaitingApproval, setAwaitingApproval, setApprovalRequest, modificationText, setModificationText,
    awaitingQuestion, setAwaitingQuestion, questionRequest, setQuestionRequest,
    answerText, setAnswerText, selectedOptions, setSelectedOptions,
    awaitingToolConfirmation, setAwaitingToolConfirmation, setToolConfirmationRequest,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    sendQuery, sendGuidance, sendApproval, sendToolConfirmation, sendAnswer, sendStop, sendResume,
    conversationId, setConversationId, projectId, userId, sessionId,
    createConversation, saveMessage, updateConvMeta,
  } = deps

  const inputRef = useRef<HTMLTextAreaElement>(null)

  const handleSend = useCallback(async () => {
    const question = inputValue.trim()
    if (!question || awaitingApproval || awaitingQuestion || awaitingToolConfirmation) return

    if (!conversationId && projectId && userId && sessionId) {
      const conv = await createConversation(sessionId)
      if (conv) {
        setConversationId(conv.id)
      }
    }

    if (isLoading) {
      const guidanceMessage: Message = {
        type: 'message',
        id: `guidance-${Date.now()}`,
        role: 'user',
        content: question,
        isGuidance: true,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, guidanceMessage])
      setInputValue('')
      sendGuidance(question)
      saveMessage('guidance', { content: question, isGuidance: true })
    } else {
      const userMessage: Message = {
        type: 'message',
        id: `user-${Date.now()}`,
        role: 'user',
        content: question,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, userMessage])
      setInputValue('')
      setIsLoading(true)

      const hasUserMessage = chatItems.some((item: ChatItem) => 'role' in item && item.role === 'user')
      if (!hasUserMessage) {
        updateConvMeta({ title: question.substring(0, 100) })
      }

      try {
        sendQuery(question)
      } catch {
        setIsLoading(false)
      }
    }
  }, [inputValue, isLoading, awaitingApproval, awaitingQuestion, awaitingToolConfirmation,
      sendQuery, sendGuidance, conversationId, projectId, userId, sessionId,
      createConversation, saveMessage, updateConvMeta, chatItems,
      setChatItems, setInputValue, setIsLoading, setConversationId])

  const handleApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    if (!awaitingApproval || isProcessingApproval.current || !awaitingApprovalRef.current) return

    isProcessingApproval.current = true
    awaitingApprovalRef.current = false

    setAwaitingApproval(false)
    setApprovalRequest(null)
    setIsLoading(true)

    const decisionMessage: Message = {
      type: 'message',
      id: `decision-${Date.now()}`,
      role: 'user',
      content: decision === 'approve'
        ? 'Approved phase transition'
        : decision === 'modify'
        ? `Modified: ${modificationText}`
        : 'Aborted phase transition',
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, decisionMessage])

    try {
      sendApproval(decision, decision === 'modify' ? modificationText : undefined)
      setModificationText('')
    } catch {
      setIsLoading(false)
      awaitingApprovalRef.current = false
      isProcessingApproval.current = false
    } finally {
      setTimeout(() => { isProcessingApproval.current = false }, 1000)
    }
  }, [modificationText, sendApproval, awaitingApproval,
      setAwaitingApproval, setApprovalRequest, setIsLoading, setChatItems, setModificationText])

  const handleTimelineToolConfirmation = useCallback((itemId: string, decision: 'approve' | 'reject') => {
    if (isProcessingToolConfirmation.current) return
    isProcessingToolConfirmation.current = true

    setAwaitingToolConfirmation(false)
    awaitingToolConfirmationRef.current = false
    setToolConfirmationRequest(null)
    setIsLoading(true)

    if (decision === 'reject') {
      setChatItems((prev: ChatItem[]) => prev.map((item: ChatItem) => {
        if (!('type' in item)) return item
        if (item.type === 'tool_execution' && item.id === itemId) {
          return { ...item, status: 'error' as const, final_output: 'Rejected by user' }
        }
        if (item.type === 'plan_wave' && item.id === itemId) {
          return { ...item, status: 'error' as const, interpretation: 'Rejected by user' }
        }
        return item
      }))
      pendingApprovalToolId.current = null
      pendingApprovalWaveId.current = null
    } else {
      setChatItems((prev: ChatItem[]) => {
        const matchingItem = prev.find((item: ChatItem) =>
          'type' in item && item.id === itemId && (item.type === 'plan_wave' || item.type === 'tool_execution')
        )
        if (matchingItem && 'type' in matchingItem) {
          if (matchingItem.type === 'plan_wave') {
            pendingApprovalWaveId.current = itemId
            pendingApprovalToolId.current = null
          } else {
            pendingApprovalToolId.current = itemId
            pendingApprovalWaveId.current = null
          }
        }
        return prev
      })
    }

    try {
      sendToolConfirmation(decision)
    } catch {
      setIsLoading(false)
    } finally {
      setTimeout(() => { isProcessingToolConfirmation.current = false }, 1000)
    }
  }, [sendToolConfirmation,
      setAwaitingToolConfirmation, setToolConfirmationRequest, setIsLoading, setChatItems])

  const handleAnswer = useCallback(() => {
    if (!awaitingQuestion || isProcessingQuestion.current || !awaitingQuestionRef.current) return
    if (!questionRequest) return

    isProcessingQuestion.current = true
    awaitingQuestionRef.current = false

    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setIsLoading(true)

    const answer = questionRequest.format === 'text'
      ? answerText
      : selectedOptions.join(', ')

    const answerMessage: Message = {
      type: 'message',
      id: `answer-${Date.now()}`,
      role: 'user',
      content: `Answer: ${answer}`,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, answerMessage])

    try {
      sendAnswer(answer)
      setAnswerText('')
      setSelectedOptions([])
    } catch {
      setIsLoading(false)
      awaitingQuestionRef.current = false
      isProcessingQuestion.current = false
    } finally {
      setTimeout(() => { isProcessingQuestion.current = false }, 1000)
    }
  }, [questionRequest, answerText, selectedOptions, sendAnswer, awaitingQuestion,
      setAwaitingQuestion, setQuestionRequest, setIsLoading, setChatItems, setAnswerText, setSelectedOptions])

  const handleStop = useCallback(() => {
    setIsStopping(true)
    sendStop()
  }, [sendStop, setIsStopping])

  const handleResume = useCallback(() => {
    sendResume()
    setIsStopped(false)
    setIsStopping(false)
    setIsLoading(true)
  }, [sendResume, setIsStopped, setIsStopping, setIsLoading])

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  return {
    inputRef,
    handleSend,
    handleApproval,
    handleTimelineToolConfirmation,
    handleAnswer,
    handleStop,
    handleResume,
    handleKeyDown,
    handleInputChange,
  }
}
