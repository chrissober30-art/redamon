'use client'

import { useState, useRef, useCallback, ReactNode, useEffect } from 'react'
import { createPortal } from 'react-dom'
import styles from './Tooltip.module.css'

interface TooltipProps {
  /** The content to show in the tooltip */
  content: ReactNode
  /** The trigger element */
  children: ReactNode
  /** Position of the tooltip */
  position?: 'top' | 'bottom' | 'left' | 'right'
  /** Delay before showing (ms) */
  delay?: number
  /** Whether tooltip is disabled */
  disabled?: boolean
  /** Override default max-width (CSS default is 260px) */
  maxWidth?: number | string
  /** When true, the tooltip stays open while the mouse is over its body —
   *  needed so the user can scroll inside the tooltip or click links inside it.
   *  Default: false (legacy hover-and-leave behavior). */
  interactive?: boolean
}

interface Position {
  top: number
  left: number
}

export function Tooltip({
  content,
  children,
  position = 'top',
  delay = 200,
  disabled = false,
  maxWidth,
  interactive = false,
}: TooltipProps) {
  const [isVisible, setIsVisible] = useState(false)
  const [tooltipPosition, setTooltipPosition] = useState<Position>({ top: 0, left: 0 })
  const triggerRef = useRef<HTMLDivElement>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)
  const timeoutRef = useRef<NodeJS.Timeout | null>(null)
  const hideTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const calculatePosition = useCallback(() => {
    if (!triggerRef.current || !tooltipRef.current) return

    const triggerRect = triggerRef.current.getBoundingClientRect()
    const tooltipRect = tooltipRef.current.getBoundingClientRect()
    const gap = 8

    let top = 0
    let left = 0

    switch (position) {
      case 'top':
        top = triggerRect.top - tooltipRect.height - gap
        left = triggerRect.left + (triggerRect.width - tooltipRect.width) / 2
        break
      case 'bottom':
        top = triggerRect.bottom + gap
        left = triggerRect.left + (triggerRect.width - tooltipRect.width) / 2
        break
      case 'left':
        top = triggerRect.top + (triggerRect.height - tooltipRect.height) / 2
        left = triggerRect.left - tooltipRect.width - gap
        break
      case 'right':
        top = triggerRect.top + (triggerRect.height - tooltipRect.height) / 2
        left = triggerRect.right + gap
        break
    }

    // Keep tooltip within viewport
    const padding = 8
    top = Math.max(padding, Math.min(top, window.innerHeight - tooltipRect.height - padding))
    left = Math.max(padding, Math.min(left, window.innerWidth - tooltipRect.width - padding))

    setTooltipPosition({ top, left })
  }, [position])

  const showTooltip = useCallback(() => {
    if (disabled) return
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current)
      hideTimeoutRef.current = null
    }
    timeoutRef.current = setTimeout(() => {
      setIsVisible(true)
    }, delay)
  }, [delay, disabled])

  const hideTooltip = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
    if (interactive) {
      // Defer hide so the mouse has time to enter the tooltip body.
      // onMouseEnter on the tooltip cancels this timeout.
      hideTimeoutRef.current = setTimeout(() => {
        setIsVisible(false)
        hideTimeoutRef.current = null
      }, 150)
    } else {
      setIsVisible(false)
    }
  }, [interactive])

  const cancelPendingHide = useCallback(() => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current)
      hideTimeoutRef.current = null
    }
  }, [])

  useEffect(() => {
    if (isVisible) {
      calculatePosition()
    }
  }, [isVisible, calculatePosition])

  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
      if (hideTimeoutRef.current) {
        clearTimeout(hideTimeoutRef.current)
      }
    }
  }, [])

  const positionClass = {
    top: styles.tooltipTop,
    bottom: styles.tooltipBottom,
    left: styles.tooltipLeft,
    right: styles.tooltipRight,
  }[position]

  return (
    <>
      <div
        ref={triggerRef}
        className={styles.trigger}
        onMouseEnter={showTooltip}
        onMouseLeave={hideTooltip}
        onFocus={showTooltip}
        onBlur={hideTooltip}
      >
        {children}
      </div>

      {isVisible &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            ref={tooltipRef}
            className={`${styles.tooltip} ${positionClass}`}
            style={{
              top: tooltipPosition.top,
              left: tooltipPosition.left,
              ...(maxWidth !== undefined ? { maxWidth } : {}),
              ...(interactive ? { pointerEvents: 'auto' } : {}),
            }}
            role="tooltip"
            onMouseEnter={interactive ? cancelPendingHide : undefined}
            onMouseLeave={interactive ? hideTooltip : undefined}
          >
            {content}
          </div>,
          document.body
        )}
    </>
  )
}
