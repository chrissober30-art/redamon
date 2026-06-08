/**
 * AI Assistant Drawer - WebSocket Version
 *
 * Thin orchestrator: wires hooks together and renders sub-components.
 * All state logic lives in hooks/; all JSX sections live in sub-components.
 */

'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import type { ActiveSkill } from './hooks/useSendHandlers'
import styles from './AIAssistantDrawer.module.css'

// Hooks
import { useLoadingWord } from './hooks/useLoadingWord'
import { useChatState } from './hooks/useChatState'
import { useInteractionState } from './hooks/useInteractionState'
import { useScrollBehavior } from './hooks/useScrollBehavior'
import { useAttackSkillData } from './hooks/useAttackSkillData'
import { useApiKeyModal, API_KEY_INFO } from './hooks/useApiKeyModal'
import { useModelPicker } from './hooks/useModelPicker'
import { useSettingsModal } from './hooks/useSettingsModal'
import { useWebSocketHandler } from './hooks/useWebSocketHandler'
import { useConversationRestoration } from './hooks/useConversationRestoration'
import { useSendHandlers } from './hooks/useSendHandlers'
import { useDownloadMarkdown } from './hooks/useDownloadMarkdown'

// External hooks
import { useAgentWebSocket } from '@/hooks/useAgentWebSocket'
import { useConversations } from '@/hooks/useConversations'
import { useChatPersistence } from '@/hooks/useChatPersistence'

// Sub-components
import { DrawerHeader } from './DrawerHeader'
import { PhaseIndicatorBar } from './PhaseIndicatorBar'
import { SettingsModal } from './SettingsModal'
import { ModelPickerModal } from './ModelPickerModal'
import { ChatArea } from './ChatArea'
import { ApprovalDialog } from './ApprovalDialog'
import { QuestionDialog } from './QuestionDialog'
import { InputArea } from './InputArea'
import { ApiKeyModal } from './ApiKeyModal'

// Types
import type { AIAssistantDrawerProps } from './types'

// Persisted drawer width (per-user via localStorage)
const WIDTH_STORAGE_KEY = 'redamon-ai-assistant-drawer-width'
const DEFAULT_WIDTH_PX = 672
const MIN_WIDTH_PX = 360
const MAX_WIDTH_PX = 1400

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
  onSwitchSession,
  modelName,
  onModelChange,
  toolPhaseMap,
  stealthMode = false,
  onToggleStealth,
  onRefetchGraph,
  isOtherChainsHidden = false,
  onToggleOtherChains,
  hasOtherChains = false,
  requireToolConfirmation = true,
  graphViewCypher,
  onOpenFileSystem,
}: AIAssistantDrawerProps) {
  // ─── State hooks ─────────────────────────────────────────────────────────────
  const [activeSkill, setActiveSkill] = useState<ActiveSkill | null>(null)
  const statusWord = useLoadingWord()

  const {
    chatItems, setChatItems,
    inputValue, setInputValue,
    isLoading, setIsLoading,
    isStopped, setIsStopped,
    isStopping, setIsStopping,
    currentPhase, setCurrentPhase,
    attackPathType, setAttackPathType,
    iterationCount, setIterationCount,
    todoList, setTodoList,
    isRestoringConversation,
    itemIdCounter,
    groupedChatItems,
    resetChatState,
  } = useChatState()

  const {
    awaitingApproval, setAwaitingApproval,
    approvalRequest, setApprovalRequest,
    modificationText, setModificationText,
    awaitingToolConfirmation, setAwaitingToolConfirmation,
    setToolConfirmationRequest,
    awaitingQuestion, setAwaitingQuestion,
    questionRequest, setQuestionRequest,
    answerText, setAnswerText,
    selectedOptions, setSelectedOptions,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    resetInteractionState,
  } = useInteractionState()

  const {
    messagesEndRef, messagesContainerRef,
    shouldAutoScroll,
    scrollToBottom, checkIfAtBottom, resetScrollState,
  } = useScrollBehavior(chatItems)

  const { skillData } = useAttackSkillData(userId, projectId)

  const {
    missingApiKeys,
    apiKeyModal,
    apiKeyValue, setApiKeyValue,
    apiKeyVisible, setApiKeyVisible,
    apiKeySaving,
    openApiKeyModal, closeApiKeyModal, saveApiKey,
    fetchApiKeyStatus,
  } = useApiKeyModal(userId)

  const {
    showModelModal, setShowModelModal,
    modelSearch, setModelSearch,
    modelsLoading, modelsError,
    filteredModels,
    handleSelectModel,
    modelSearchRef,
  } = useModelPicker(userId, onModelChange)

  const {
    showSettingsDropdown, setShowSettingsDropdown,
    settingsModal, setSettingsModal,
    projectFormData, updateProjectField,
    settingsDropdownRef,
  } = useSettingsModal(projectId)

  // ─── Conversation persistence ─────────────────────────────────────────────
  const {
    conversations,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
  } = useConversations(projectId, userId)

  // ─── handleNewChat (cross-cutting — touches state from multiple hooks) ─────
  // Defined before useConversationRestoration via a stable ref pattern
  const handleNewChatRef = useRef<() => void>(() => {})
  const updateConvMetaRef = useRef<(updates: Record<string, any>) => Promise<void>>(async () => {})

  // ─── Conversation restoration ──────────────────────────────────────────────
  const {
    conversationId, setConversationId,
    showHistory, setShowHistory,
    handleSelectConversation,
    handleHistoryNewChat,
    handleDeleteConversation,
  } = useConversationRestoration({
    loadConversation,
    deleteConversation,
    fetchConversations,
    onSwitchSession,
    onRefetchGraph,
    projectId,
    userId,
    setChatItems,
    setCurrentPhase,
    setAttackPathType,
    setIterationCount,
    setIsLoading,
    setIsStopped,
    setTodoList,
    isRestoringConversation,
    shouldAutoScroll,
    setAwaitingApproval,
    setApprovalRequest,
    setAwaitingQuestion,
    setQuestionRequest,
    setAwaitingToolConfirmation,
    setToolConfirmationRequest,
    awaitingApprovalRef,
    awaitingQuestionRef,
    awaitingToolConfirmationRef,
    pendingApprovalToolId,
    pendingApprovalWaveId,
    setActiveSkill,
    updateConvMeta: useCallback((updates: Record<string, any>) => updateConvMetaRef.current(updates), []),
    handleNewChat: useCallback(() => handleNewChatRef.current(), []),
  })

  const { saveMessage, updateConversation: updateConvMeta } = useChatPersistence(conversationId)

  // Keep ref up-to-date for useConversationRestoration
  useEffect(() => { updateConvMetaRef.current = updateConvMeta }, [updateConvMeta])

  // Now that we have setConversationId and setShowHistory, define handleNewChat
  const handleNewChat = useCallback(() => {
    resetChatState()
    resetInteractionState()
    resetScrollState()
    setConversationId(null)
    setShowHistory(false)
    setActiveSkill(null)
    onResetSession?.()
  }, [resetChatState, resetInteractionState, resetScrollState, setConversationId, setShowHistory, setActiveSkill, onResetSession])

  // Keep ref up-to-date
  useEffect(() => { handleNewChatRef.current = handleNewChat }, [handleNewChat])

  // ─── WebSocket ────────────────────────────────────────────────────────────
  const { handleWebSocketMessage } = useWebSocketHandler({
    setChatItems, setIsLoading, setIsStopped, setIsStopping,
    setCurrentPhase, setIterationCount, setAttackPathType, setTodoList,
    todoList, itemIdCounter,
    setAwaitingApproval, setApprovalRequest,
    setAwaitingQuestion, setQuestionRequest,
    setAwaitingToolConfirmation, setToolConfirmationRequest,
    awaitingApprovalRef, isProcessingApproval,
    awaitingQuestionRef, isProcessingQuestion,
    awaitingToolConfirmationRef, isProcessingToolConfirmation,
    pendingApprovalToolId, pendingApprovalWaveId,
    onGraphMutation: onRefetchGraph,
  })

  const {
    status, isConnected, reconnectAttempt,
    sendQuery, sendGuidance, sendApproval, sendToolConfirmation,
    sendFireteamMemberConfirmation,
    sendAnswer, sendSkillInject, sendStop, sendResume, sendToolStop,
  } = useAgentWebSocket({
    userId,
    projectId,
    sessionId,
    graphViewCypher,
    enabled: isOpen,
    onMessage: handleWebSocketMessage,
  })

  // ─── Send handlers ────────────────────────────────────────────────────────
  const {
    inputRef,
    handleSend,
    handleApproval,
    handleTimelineToolConfirmation,
    handleAnswer,
    handleStop,
    handleResume,
    handleToolStop,
    handleKeyDown,
    handleInputChange,
    activateSkill,
    userResizedRef,
  } = useSendHandlers({
    inputValue, setInputValue,
    isLoading, setIsLoading, setIsStopped, setIsStopping,
    setChatItems, chatItems,
    activeSkill, setActiveSkill,
    awaitingApproval, setAwaitingApproval, setApprovalRequest, modificationText, setModificationText,
    awaitingQuestion, setAwaitingQuestion, questionRequest, setQuestionRequest,
    answerText, setAnswerText, selectedOptions, setSelectedOptions,
    awaitingToolConfirmation, setAwaitingToolConfirmation, setToolConfirmationRequest,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    sendQuery, sendGuidance, sendSkillInject, sendApproval, sendToolConfirmation, sendFireteamMemberConfirmation, sendAnswer, sendStop, sendResume, sendToolStop,
    conversationId, setConversationId, projectId, userId, sessionId,
    createConversation, saveMessage, updateConvMeta,
  })

  // ─── Markdown download ────────────────────────────────────────────────────
  const { handleDownloadMarkdown } = useDownloadMarkdown({
    chatItems,
    currentPhase,
    iterationCount,
    modelName: modelName ?? '',
    todoList,
  })

  // ─── Side effects ─────────────────────────────────────────────────────────
  // Fetch API key status when connected
  useEffect(() => {
    if (isConnected) fetchApiKeyStatus()
  }, [isConnected, fetchApiKeyStatus])

  // Focus input + force scroll when drawer opens
  useEffect(() => {
    if (isOpen && inputRef.current && !awaitingApproval) {
      setTimeout(() => {
        inputRef.current?.focus()
        scrollToBottom(true)
      }, 300)
    }
  }, [isOpen, awaitingApproval, scrollToBottom, inputRef])

  // Reset state when session changes (skip when restoring a conversation)
  useEffect(() => {
    if (isRestoringConversation.current) {
      isRestoringConversation.current = false
      return
    }
    resetChatState()
    resetInteractionState()
    resetScrollState()
    setConversationId(null)
    setActiveSkill(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // ─── Drawer width (persisted per-user, drag handle on left edge) ───────────
  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    if (typeof window === 'undefined') return DEFAULT_WIDTH_PX
    const raw = window.localStorage.getItem(WIDTH_STORAGE_KEY)
    if (!raw) return DEFAULT_WIDTH_PX
    const n = parseInt(raw, 10)
    if (!Number.isFinite(n)) return DEFAULT_WIDTH_PX
    return Math.min(Math.max(n, MIN_WIDTH_PX), MAX_WIDTH_PX)
  })
  const [isResizing, setIsResizing] = useState(false)
  const lastWidthRef = useRef<number>(drawerWidth)

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    setIsResizing(true)
  }, [])

  useEffect(() => {
    if (!isResizing) return
    const handleMouseMove = (e: MouseEvent) => {
      const raw = window.innerWidth - e.clientX
      const clamped = Math.min(Math.max(raw, MIN_WIDTH_PX), MAX_WIDTH_PX)
      lastWidthRef.current = clamped
      setDrawerWidth(clamped)
    }
    const handleMouseUp = () => {
      setIsResizing(false)
      try {
        window.localStorage.setItem(WIDTH_STORAGE_KEY, String(Math.round(lastWidthRef.current)))
      } catch {
        // localStorage unavailable — width still applies for the session.
      }
    }
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    const prevUserSelect = document.body.style.userSelect
    const prevCursor = document.body.style.cursor
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'
    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.userSelect = prevUserSelect
      document.body.style.cursor = prevCursor
    }
  }, [isResizing])

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''} ${isResizing ? styles.drawerResizing : ''}`}
      style={{ width: `${drawerWidth}px` }}
      aria-hidden={!isOpen}
    >
      {isOpen && (
        <div
          className={styles.resizeHandle}
          onMouseDown={handleResizeStart}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize drawer"
        />
      )}
      <DrawerHeader
        status={status}
        reconnectAttempt={reconnectAttempt}
        sessionId={sessionId}
        requireToolConfirmation={requireToolConfirmation}
        hasOtherChains={hasOtherChains}
        isOtherChainsHidden={isOtherChainsHidden}
        onToggleOtherChains={onToggleOtherChains}
        showHistory={showHistory}
        setShowHistory={setShowHistory}
        handleNewChat={handleNewChat}
        handleDownloadMarkdown={handleDownloadMarkdown}
        chatItems={chatItems}
        onClose={onClose}
        onOpenFileSystem={onOpenFileSystem}
        conversations={conversations}
        handleSelectConversation={handleSelectConversation}
        handleDeleteConversation={handleDeleteConversation}
        handleHistoryNewChat={handleHistoryNewChat}
      />

      <PhaseIndicatorBar
        currentPhase={currentPhase}
        toolPhaseMap={toolPhaseMap}
        attackPathType={attackPathType}
        skillData={skillData}
        iterationCount={iterationCount}
        stealthMode={stealthMode}
        onToggleStealth={onToggleStealth}
        settingsDropdownRef={settingsDropdownRef}
        showSettingsDropdown={showSettingsDropdown}
        setShowSettingsDropdown={setShowSettingsDropdown}
        setSettingsModal={setSettingsModal}
        modelName={modelName}
        setShowModelModal={setShowModelModal}
      />

      <SettingsModal
        settingsModal={settingsModal}
        setSettingsModal={setSettingsModal}
        projectFormData={projectFormData}
        updateProjectField={updateProjectField}
      />

      <ModelPickerModal
        showModelModal={showModelModal}
        setShowModelModal={setShowModelModal}
        modelSearch={modelSearch}
        setModelSearch={setModelSearch}
        modelSearchRef={modelSearchRef}
        modelsLoading={modelsLoading}
        modelsError={modelsError}
        filteredModels={filteredModels}
        modelName={modelName}
        onModelChange={onModelChange}
        handleSelectModel={handleSelectModel}
      />

      <ChatArea
        messagesContainerRef={messagesContainerRef}
        messagesEndRef={messagesEndRef}
        checkIfAtBottom={checkIfAtBottom}
        chatItems={chatItems}
        groupedChatItems={groupedChatItems}
        isLoading={isLoading}
        todoList={todoList}
        statusWord={statusWord}
        isConnected={isConnected}
        setInputValue={setInputValue}
        missingApiKeys={missingApiKeys}
        openApiKeyModal={openApiKeyModal}
        handleTimelineToolConfirmation={handleTimelineToolConfirmation}
        handleToolStop={handleToolStop}
      />

      <ApprovalDialog
        awaitingApproval={awaitingApproval}
        approvalRequest={approvalRequest}
        modificationText={modificationText}
        isLoading={isLoading}
        setModificationText={setModificationText}
        handleApproval={handleApproval}
      />

      <QuestionDialog
        awaitingQuestion={awaitingQuestion}
        questionRequest={questionRequest}
        answerText={answerText}
        selectedOptions={selectedOptions}
        isLoading={isLoading}
        setAnswerText={setAnswerText}
        setSelectedOptions={setSelectedOptions}
        handleAnswer={handleAnswer}
      />

      <InputArea
        inputRef={inputRef}
        inputValue={inputValue}
        handleInputChange={handleInputChange}
        handleKeyDown={handleKeyDown}
        handleSend={handleSend}
        handleStop={handleStop}
        handleResume={handleResume}
        isConnected={isConnected}
        isLoading={isLoading}
        isStopped={isStopped}
        isStopping={isStopping}
        awaitingApproval={awaitingApproval}
        awaitingQuestion={awaitingQuestion}
        awaitingToolConfirmation={awaitingToolConfirmation}
        userId={userId}
        setInputValue={setInputValue}
        activeSkill={activeSkill}
        setActiveSkill={setActiveSkill}
        onSkillActivate={activateSkill}
        userResizedRef={userResizedRef}
      />

      <ApiKeyModal
        apiKeyModal={apiKeyModal}
        apiKeyInfo={API_KEY_INFO}
        apiKeyValue={apiKeyValue}
        apiKeyVisible={apiKeyVisible}
        apiKeySaving={apiKeySaving}
        setApiKeyValue={setApiKeyValue}
        setApiKeyVisible={setApiKeyVisible}
        closeApiKeyModal={closeApiKeyModal}
        saveApiKey={saveApiKey}
      />
    </div>
  )
}
