'use client'

import React, { KeyboardEvent } from 'react'
import { Send, Loader2, Square, Play } from 'lucide-react'
import styles from './AIAssistantDrawer.module.css'

interface InputAreaProps {
  inputRef: React.RefObject<HTMLTextAreaElement | null>
  inputValue: string
  handleInputChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  handleKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void
  handleSend: () => void
  handleStop: () => void
  handleResume: () => void
  isConnected: boolean
  isLoading: boolean
  isStopped: boolean
  isStopping: boolean
  awaitingApproval: boolean
  awaitingQuestion: boolean
  awaitingToolConfirmation: boolean
}

export function InputArea({
  inputRef,
  inputValue,
  handleInputChange,
  handleKeyDown,
  handleSend,
  handleStop,
  handleResume,
  isConnected,
  isLoading,
  isStopped,
  isStopping,
  awaitingApproval,
  awaitingQuestion,
  awaitingToolConfirmation,
}: InputAreaProps) {
  return (
    <div className={styles.inputContainer}>
      <div className={styles.inputWrapper}>
        <textarea
          ref={inputRef}
          className={styles.input}
          value={inputValue}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          placeholder={
            !isConnected
              ? 'Connecting to agent...'
              : awaitingApproval
              ? 'Respond to the approval request above...'
              : awaitingQuestion
              ? 'Answer the question above...'
              : isStopped
              ? 'Agent stopped. Click resume to continue...'
              : isLoading
              ? 'Send guidance to the agent...'
              : 'Ask a question...'
          }
          rows={2}
          disabled={awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
        />
        <div className={styles.inputActions}>
          {(isLoading || isStopped || isStopping) && (
            <button
              className={`${styles.stopResumeButton} ${isStopped ? styles.resumeButton : styles.stopButton}`}
              onClick={isStopped ? handleResume : handleStop}
              disabled={isStopping}
              aria-label={isStopping ? 'Stopping...' : isStopped ? 'Resume agent' : 'Stop agent'}
              title={isStopping ? 'Stopping...' : isStopped ? 'Resume execution' : 'Stop execution'}
            >
              {isStopping ? <Loader2 size={13} className={styles.spinner} /> : isStopped ? <Play size={13} /> : <Square size={13} />}
            </button>
          )}
          <button
            className={styles.sendButton}
            onClick={handleSend}
            disabled={!inputValue.trim() || awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
            aria-label="Send message"
          >
            <Send size={13} />
          </button>
        </div>
      </div>
      <span className={styles.inputHint}>
        {isConnected
          ? isLoading
            ? 'Send guidance or stop the agent'
            : 'Press Enter to send, Shift+Enter for new line'
          : 'Waiting for connection...'}
      </span>
    </div>
  )
}
