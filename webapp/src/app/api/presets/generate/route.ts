import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { reconPresetSchema, extractJson, RECON_PARAMETER_CATALOG } from '@/lib/recon-preset-schema'

// ---------------------------------------------------------------------------
// POST /api/presets/generate
// Calls the user's configured LLM to generate a recon preset from a natural
// language description.  Validates the output with Zod before returning.
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a recon pipeline configuration expert for RedAmon, an AI-powered red-team reconnaissance platform.

Given a user's natural-language description, produce a JSON object whose keys are recon pipeline parameters and whose values configure the scan strategy.

RULES:
- Output ONLY a raw JSON object. No markdown, no explanation, no wrapping.
- Only include parameters you explicitly want to change. Omitted parameters keep their defaults.
- Booleans must be true or false (not strings).
- Numbers must be plain integers or floats (not strings).
- Arrays must use JSON array syntax.
- Do NOT include target-specific fields (targetDomain, subdomainList, ipMode, etc.).
- Do NOT include agent behaviour, attack skills, RoE, or CypherFix fields.
- Focus on enabling/disabling tools and tuning their numeric settings to match the user's intent.

AVAILABLE PARAMETERS:

${RECON_PARAMETER_CATALOG}
`

/**
 * Resolve provider type from model name, mirroring the Python logic in
 * agentic/orchestrator_helpers/llm_setup.py:parse_model_provider()
 */
function resolveProviderType(model: string): { providerType: string; modelId: string } {
  const prefixMap: Record<string, string> = {
    'custom/': 'openai_compatible',
    'openrouter/': 'openrouter',
    'bedrock/': 'bedrock',
    'deepseek/': 'deepseek',
    'gemini/': 'gemini',
    'glm/': 'glm',
    'kimi/': 'kimi',
    'qwen/': 'qwen',
    'xai/': 'xai',
    'mistral/': 'mistral',
  }
  for (const [prefix, type] of Object.entries(prefixMap)) {
    if (model.startsWith(prefix)) {
      return { providerType: type, modelId: model.slice(prefix.length) }
    }
  }
  if (model.startsWith('claude-')) {
    return { providerType: 'anthropic', modelId: model }
  }
  // Default: OpenAI
  return { providerType: 'openai', modelId: model }
}

/**
 * Returns the OpenAI-compatible base URL for each provider type. Stays in sync
 * with agentic/orchestrator_helpers/llm_setup.py setup_llm branches.
 */
function defaultBaseUrlFor(providerType: string): string {
  switch (providerType) {
    case 'openai': return 'https://api.openai.com/v1'
    case 'openrouter': return 'https://openrouter.ai/api/v1'
    case 'deepseek': return 'https://api.deepseek.com/v1'
    case 'gemini': return 'https://generativelanguage.googleapis.com/v1beta/openai'
    case 'glm': return 'https://open.bigmodel.cn/api/paas/v4'
    case 'kimi': return 'https://api.moonshot.ai/v1'
    case 'qwen': return 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'
    case 'xai': return 'https://api.x.ai/v1'
    case 'mistral': return 'https://api.mistral.ai/v1'
    default: return 'https://api.openai.com/v1'
  }
}

/**
 * Call an OpenAI-compatible chat completions endpoint.
 */
async function callOpenAICompatible(
  baseUrl: string,
  apiKey: string,
  modelId: string,
  systemPrompt: string,
  userPrompt: string,
  extraHeaders?: Record<string, string>,
  timeout?: number,
): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (timeout || 120) * 1000)

  try {
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        ...extraHeaders,
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.3,
        max_tokens: 4096,
        response_format: { type: 'json_object' },
      }),
      signal: controller.signal,
    })

    if (!res.ok) {
      const errText = await res.text().catch(() => 'Unknown error')
      throw new Error(`LLM API returned ${res.status}: ${errText}`)
    }

    const data = await res.json()
    return data.choices?.[0]?.message?.content ?? ''
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Call the Anthropic Messages API.
 */
async function callAnthropic(
  apiKey: string,
  modelId: string,
  systemPrompt: string,
  userPrompt: string,
  timeout?: number,
): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (timeout || 120) * 1000)

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: modelId,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
        max_tokens: 4096,
        temperature: 0.3,
      }),
      signal: controller.signal,
    })

    if (!res.ok) {
      const errText = await res.text().catch(() => 'Unknown error')
      throw new Error(`Anthropic API returned ${res.status}: ${errText}`)
    }

    const data = await res.json()
    // Anthropic returns content as an array of blocks
    const textBlock = data.content?.find((b: { type: string }) => b.type === 'text')
    return textBlock?.text ?? ''
  } finally {
    clearTimeout(timer)
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { userId, model, prompt } = body as {
      userId?: string
      model?: string
      prompt?: string
    }

    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 })
    }
    if (!model) {
      return NextResponse.json({ error: 'model is required' }, { status: 400 })
    }
    if (!prompt || !prompt.trim()) {
      return NextResponse.json({ error: 'prompt is required' }, { status: 400 })
    }

    // 1. Resolve provider type from model name
    const { providerType, modelId } = resolveProviderType(model)

    if (providerType === 'bedrock') {
      return NextResponse.json(
        { error: 'AWS Bedrock is not yet supported for preset generation. Please configure an OpenAI, Anthropic, or OpenRouter provider.' },
        { status: 400 },
      )
    }

    // 2. Find matching provider in user's configured LLM providers
    const providers = await prisma.userLlmProvider.findMany({
      where: { userId },
    })

    const provider = providers.find((p) => p.providerType === providerType)

    if (!provider) {
      const friendlyNames: Record<string, string> = {
        anthropic: 'Anthropic',
        openai: 'OpenAI',
        openrouter: 'OpenRouter',
        openai_compatible: 'OpenAI-Compatible',
        deepseek: 'DeepSeek',
        gemini: 'Google Gemini',
        glm: 'GLM (Zhipu AI)',
        kimi: 'Kimi (Moonshot)',
        qwen: 'Qwen (Alibaba)',
        xai: 'xAI (Grok)',
        mistral: 'Mistral AI',
      }
      return NextResponse.json(
        {
          error: `No ${friendlyNames[providerType] || providerType} provider configured. Add one in Global Settings to use model "${model}".`,
        },
        { status: 400 },
      )
    }

    // 3. Call the LLM
    let rawResponse: string

    if (providerType === 'anthropic') {
      rawResponse = await callAnthropic(
        provider.apiKey,
        modelId,
        SYSTEM_PROMPT,
        prompt.trim(),
        provider.timeout,
      )
    } else {
      // OpenAI-compatible: openai, openrouter, deepseek, gemini, glm, kimi,
      // qwen, xai, mistral, and user-defined openai_compatible. Per-provider
      // user override (provider.baseUrl) wins over the registry default.
      const baseUrl = (provider.baseUrl || defaultBaseUrlFor(providerType)).replace(/\/+$/, '')

      const extraHeaders = (provider.defaultHeaders && typeof provider.defaultHeaders === 'object')
        ? provider.defaultHeaders as Record<string, string>
        : undefined

      rawResponse = await callOpenAICompatible(
        baseUrl,
        provider.apiKey,
        modelId,
        SYSTEM_PROMPT,
        prompt.trim(),
        extraHeaders,
        provider.timeout,
      )
    }

    if (!rawResponse) {
      return NextResponse.json(
        { error: 'LLM returned an empty response' },
        { status: 502 },
      )
    }

    // 4. Parse JSON from response
    const jsonStr = extractJson(rawResponse)
    let parsed: unknown
    try {
      parsed = JSON.parse(jsonStr)
    } catch {
      return NextResponse.json(
        { error: 'LLM returned invalid JSON. Please try again with a clearer description.' },
        { status: 422 },
      )
    }

    // 5. Validate with Zod
    const result = reconPresetSchema.safeParse(parsed)
    if (!result.success) {
      const issues = result.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`)
      return NextResponse.json(
        {
          error: 'Generated preset has invalid fields',
          details: issues,
        },
        { status: 422 },
      )
    }

    return NextResponse.json({ parameters: result.data })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'

    // Distinguish abort (timeout) from other errors
    if (error instanceof Error && error.name === 'AbortError') {
      return NextResponse.json(
        { error: 'LLM request timed out. Try a simpler description or check your provider settings.' },
        { status: 504 },
      )
    }

    console.error('Preset generation failed:', message)
    return NextResponse.json(
      { error: `Failed to generate preset: ${message}` },
      { status: 502 },
    )
  }
}
