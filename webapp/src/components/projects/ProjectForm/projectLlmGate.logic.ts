/**
 * Pure decision logic for the project LLM provider/model gate.
 *
 * Extracted from ProjectForm so the rules can be unit-tested in isolation,
 * without rendering the (very large) form. Keep these functions side-effect
 * free — they take plain data and return plain data/booleans.
 */

/** Shape of the bits of the user record the gate cares about. */
export interface UserModelDefaults {
  defaultAgentModel?: string | null
  defaultAiPipelineModel?: string | null
}

export interface SeededModels {
  agentOpenaiModel: string
  aiPipelineModel: string
}

/**
 * Seed the two model fields for a NEW project from the user's remembered
 * choices, falling back to empty string (which forces an explicit pick via the
 * model gate). A null/undefined user (no record, or fetch failed) yields blanks.
 */
export function seedInitialModels(user: UserModelDefaults | null | undefined): SeededModels {
  return {
    agentOpenaiModel: user?.defaultAgentModel || '',
    aiPipelineModel: user?.defaultAiPipelineModel || '',
  }
}

/**
 * Whether the forced model-selection gate must open before saving.
 * Only applies on create; either model being blank (after trim) triggers it.
 */
export function needsModelGate(
  mode: 'create' | 'edit',
  agentModel: string | null | undefined,
  aiPipelineModel: string | null | undefined,
): boolean {
  if (mode !== 'create') return false
  return !agentModel?.trim() || !aiPipelineModel?.trim()
}

/**
 * Whether the hard provider gate must block creation: true when the user has no
 * LLM provider configured. A non-array (e.g. an error payload) is treated as
 * "no providers" only when explicitly empty/absent — callers pass the parsed
 * list; anything that isn't a non-empty array counts as missing.
 */
export function hasNoConfiguredProvider(providers: unknown): boolean {
  return !Array.isArray(providers) || providers.length === 0
}

/**
 * Whether both models are chosen (gate satisfied). Mirrors the modal's
 * confirm-enabled condition so UI and logic can't drift.
 */
export function bothModelsSelected(
  agentModel: string | null | undefined,
  aiPipelineModel: string | null | undefined,
): boolean {
  return !!agentModel?.trim() && !!aiPipelineModel?.trim()
}

/**
 * Project fields holding an LLM model id that have a schema @default. A blank
 * value for these must never be persisted (it would override the default with
 * ""), so the server drops them and lets Prisma apply the default.
 */
export const MODEL_DEFAULT_FIELDS = new Set(['agentOpenaiModel', 'aiPipelineModel'])

/**
 * Server-side backstop for the client model-gate: true when a project field is
 * one of the model fields set to a blank string and must be dropped on create.
 */
export function isBlankModelField(key: string, value: unknown): boolean {
  return MODEL_DEFAULT_FIELDS.has(key) && typeof value === 'string' && value.trim() === ''
}
