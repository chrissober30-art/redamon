'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { Search, Loader2 } from 'lucide-react'
import {
  type ModelOption,
  formatContextLength,
  getDisplayName,
} from '@/app/graph/components/AIAssistantDrawer/modelUtils'
import styles from '@/components/projects/ProjectForm/ProjectForm.module.css'

interface ModelPickerProps {
  userId?: string | null
  value: string
  onChange: (modelId: string) => void
  placeholder?: string
}

/**
 * Reusable model picker that mirrors the AgentBehaviourSection LLM selector.
 * Fetches the user's available models from /api/models?userId=, groups by
 * provider, supports search-as-you-type, and falls back to a manual text
 * input when /api/models fails. Shared by AgentBehaviourSection (agent
 * conversational model) and TargetSection (recon AI hook model).
 */
export function ModelPicker({ userId, value, onChange, placeholder }: ModelPickerProps) {
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(true)
  const [modelsError, setModelsError] = useState(false)
  const [search, setSearch] = useState('')
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    fetch('/api/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userId ? { userId } : {}),
      cache: 'no-store',
    })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => {
        if (data && typeof data === 'object' && !data.error) {
          setAllModels(data)
        } else {
          setModelsError(true)
        }
      })
      .catch(() => setModelsError(true))
      .finally(() => setModelsLoading(false))
  }, [userId])

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
        setSearch('')
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const selectModel = useCallback((id: string) => {
    onChange(id)
    setDropdownOpen(false)
    setSearch('')
  }, [onChange])

  const filteredModels: Record<string, ModelOption[]> = {}
  const lowerSearch = search.toLowerCase()
  for (const [provider, models] of Object.entries(allModels)) {
    const filtered = models.filter(m =>
      m.id.toLowerCase().includes(lowerSearch) ||
      m.name.toLowerCase().includes(lowerSearch) ||
      m.description.toLowerCase().includes(lowerSearch)
    )
    if (filtered.length > 0) filteredModels[provider] = filtered
  }

  return (
    <div className={styles.modelSelector} ref={dropdownRef}>
      <div
        className={`${styles.modelSelectorInput} ${dropdownOpen ? styles.modelSelectorInputFocused : ''}`}
        onClick={() => {
          setDropdownOpen(true)
          setTimeout(() => inputRef.current?.focus(), 0)
        }}
      >
        {dropdownOpen ? (
          <input
            ref={inputRef}
            className={styles.modelSearchInput}
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={placeholder || 'Search models...'}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setDropdownOpen(false)
                setSearch('')
              }
            }}
          />
        ) : (
          <span className={styles.modelSelectedText}>
            {modelsLoading ? 'Loading models...' : getDisplayName(value, allModels)}
          </span>
        )}
        {modelsLoading ? (
          <Loader2 size={12} className={styles.modelSelectorSpinner} />
        ) : (
          <Search size={12} className={styles.modelSelectorIcon} />
        )}
      </div>

      {dropdownOpen && (
        <div className={styles.modelDropdown}>
          {modelsError ? (
            <div className={styles.modelDropdownEmpty}>
              <span>Failed to load models. Type a model ID manually:</span>
              <input
                className="textInput"
                type="text"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                placeholder="e.g. claude-opus-4-6, gpt-5.2, openrouter/meta-llama/llama-4-maverick"
                style={{ marginTop: 'var(--space-1)' }}
              />
            </div>
          ) : Object.keys(filteredModels).length === 0 ? (
            <div className={styles.modelDropdownEmpty}>
              {search ? `No models matching "${search}"` : 'No providers configured'}
            </div>
          ) : (
            Object.entries(filteredModels).map(([provider, models]) => (
              <div key={provider} className={styles.modelGroup}>
                <div className={styles.modelGroupHeader}>{provider}</div>
                {models.map(model => (
                  <div
                    key={model.id}
                    className={`${styles.modelOption} ${model.id === value ? styles.modelOptionSelected : ''}`}
                    onClick={() => selectModel(model.id)}
                  >
                    <div className={styles.modelOptionMain}>
                      <span className={styles.modelOptionName}>{model.name}</span>
                      {model.context_length && (
                        <span className={styles.modelOptionCtx}>{formatContextLength(model.context_length)}</span>
                      )}
                    </div>
                    {model.description && (
                      <span className={styles.modelOptionDesc}>{model.description}</span>
                    )}
                  </div>
                ))}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}
