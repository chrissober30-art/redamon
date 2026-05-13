'use client'

import { useEffect } from 'react'

const isChunkLoadError = (error: Error) =>
  error.name === 'ChunkLoadError' ||
  /Loading chunk [\w/.-]+ failed/i.test(error.message) ||
  /Failed to load chunk/i.test(error.message)

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    if (isChunkLoadError(error)) {
      window.location.reload()
      return
    }
    console.error('App error boundary:', error)
  }, [error])

  if (isChunkLoadError(error)) {
    return null
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '60vh',
        padding: 'var(--space-8)',
        textAlign: 'center',
      }}
    >
      <h2
        style={{
          fontSize: 'var(--text-2xl)',
          fontWeight: 'var(--font-bold)',
          color: 'var(--text-primary)',
          marginBottom: 'var(--space-3)',
        }}
      >
        Something went wrong
      </h2>
      <p
        style={{
          color: 'var(--text-secondary)',
          marginBottom: 'var(--space-6)',
          maxWidth: '480px',
        }}
      >
        {error.message || 'An unexpected error occurred.'}
      </p>
      <button
        type="button"
        onClick={reset}
        style={{
          background: 'var(--accent-primary)',
          color: 'var(--text-on-accent, #fff)',
          border: 'none',
          padding: 'var(--space-3) var(--space-6)',
          borderRadius: 'var(--radius-md)',
          fontSize: 'var(--text-base)',
          fontWeight: 'var(--font-medium)',
          cursor: 'pointer',
          transition: 'var(--transition-all)',
        }}
      >
        Try again
      </button>
    </div>
  )
}
