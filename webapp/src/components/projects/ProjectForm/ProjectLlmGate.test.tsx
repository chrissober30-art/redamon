/**
 * Component tests for the project LLM gate modals.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/ProjectLlmGate.test.tsx
 *
 * ModelPicker is stubbed (its real implementation fetches /api/models on mount);
 * next/navigation is mocked so ProviderRequiredModal's router.push is observable.
 * These cover the user-facing contract: the provider gate routes to settings,
 * and the model gate blocks Save until both models are chosen.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

const mockPush = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: mockPush }),
}))

// Stub ModelPicker: a plain input keyed by its placeholder so the two pickers
// in ModelSelectionModal are individually addressable, and onChange is wired.
vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({
    value,
    onChange,
    placeholder,
  }: {
    value: string
    onChange: (id: string) => void
    placeholder?: string
  }) => (
    <input
      aria-label={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}))

import { ProviderRequiredModal, ModelSelectionModal } from './ProjectLlmGate'

beforeEach(() => {
  mockPush.mockReset()
})
afterEach(() => cleanup())

// ---------------------------------------------------------------------------
// ProviderRequiredModal
// ---------------------------------------------------------------------------

describe('ProviderRequiredModal', () => {
  test('renders the blocking message', () => {
    render(<ProviderRequiredModal onCancel={() => {}} />)
    expect(screen.getByText(/configure an llm provider first/i)).toBeInTheDocument()
  })

  test('"Configure Provider" navigates to /settings', () => {
    render(<ProviderRequiredModal onCancel={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /configure provider/i }))
    expect(mockPush).toHaveBeenCalledWith('/settings')
  })

  test('"Back to Projects" calls onCancel and does not navigate', () => {
    const onCancel = vi.fn()
    render(<ProviderRequiredModal onCancel={onCancel} />)
    fireEvent.click(screen.getByRole('button', { name: /back to projects/i }))
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(mockPush).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// ModelSelectionModal
// ---------------------------------------------------------------------------

function renderModal(overrides: Partial<React.ComponentProps<typeof ModelSelectionModal>> = {}) {
  const props = {
    userId: 'u1',
    agentModel: '',
    aiPipelineModel: '',
    onChangeAgent: vi.fn(),
    onChangeAiPipeline: vi.fn(),
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
    ...overrides,
  }
  render(<ModelSelectionModal {...props} />)
  return props
}

function saveButton() {
  return screen.getByRole('button', { name: /save project/i }) as HTMLButtonElement
}

describe('ModelSelectionModal: Save gating', () => {
  test('Save disabled when both models blank', () => {
    renderModal({ agentModel: '', aiPipelineModel: '' })
    expect(saveButton().disabled).toBe(true)
  })

  test('Save disabled when only agent model set', () => {
    renderModal({ agentModel: 'deepseek/deepseek-chat', aiPipelineModel: '' })
    expect(saveButton().disabled).toBe(true)
  })

  test('Save disabled when only pipeline model set', () => {
    renderModal({ agentModel: '', aiPipelineModel: 'deepseek/deepseek-chat' })
    expect(saveButton().disabled).toBe(true)
  })

  test('Save enabled when both models set', () => {
    renderModal({ agentModel: 'deepseek/deepseek-chat', aiPipelineModel: 'deepseek/deepseek-reasoner' })
    expect(saveButton().disabled).toBe(false)
  })

  test('whitespace-only models keep Save disabled', () => {
    renderModal({ agentModel: '   ', aiPipelineModel: '   ' })
    expect(saveButton().disabled).toBe(true)
  })

  test('clicking enabled Save calls onConfirm', () => {
    const props = renderModal({ agentModel: 'a', aiPipelineModel: 'b' })
    fireEvent.click(saveButton())
    expect(props.onConfirm).toHaveBeenCalledTimes(1)
  })

  test('disabled Save does not call onConfirm', () => {
    const props = renderModal({ agentModel: '', aiPipelineModel: '' })
    fireEvent.click(saveButton())
    expect(props.onConfirm).not.toHaveBeenCalled()
  })
})

describe('ModelSelectionModal: picker wiring', () => {
  test('changing the agent picker calls onChangeAgent', () => {
    const props = renderModal()
    fireEvent.change(screen.getByLabelText('Search agent models...'), {
      target: { value: 'deepseek/deepseek-chat' },
    })
    expect(props.onChangeAgent).toHaveBeenCalledWith('deepseek/deepseek-chat')
  })

  test('changing the pipeline picker calls onChangeAiPipeline', () => {
    const props = renderModal()
    fireEvent.change(screen.getByLabelText('Search pipeline models...'), {
      target: { value: 'deepseek/deepseek-reasoner' },
    })
    expect(props.onChangeAiPipeline).toHaveBeenCalledWith('deepseek/deepseek-reasoner')
  })

  test('Cancel calls onCancel', () => {
    const props = renderModal()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(props.onCancel).toHaveBeenCalledTimes(1)
  })
})
