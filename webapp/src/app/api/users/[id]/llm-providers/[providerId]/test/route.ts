import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/users/[id]/llm-providers/[providerId]/test
// Also supports testing unsaved configs by passing full config in body
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const body = await request.json()

    let config: Record<string, unknown>

    if (providerId === 'unsaved') {
      // Testing an unsaved config — full config in body
      config = body
    } else {
      // Testing a saved config: start from DB (has full secrets), then
      // overlay any fields the operator has edited in the form. Secret
      // fields (apiKey, awsAccessKeyId, awsSecretKey) are returned masked
      // by GET; if the body still carries the mask, keep the DB value.
      // Otherwise the form-edited value wins (so a freshly typed key is
      // actually what gets tested).
      const provider = await prisma.userLlmProvider.findFirst({
        where: { id: providerId, userId: id },
      })
      if (!provider) {
        return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
      }
      const isMasked = (v: unknown) => typeof v === 'string' && v.startsWith('••••')
      const SECRET_FIELDS = new Set(['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'])
      config = { ...(provider as unknown as Record<string, unknown>) }
      for (const [key, value] of Object.entries(body)) {
        if (SECRET_FIELDS.has(key) && isMasked(value)) {
          // Keep DB value — user did not retype the secret
          continue
        }
        config[key] = value
      }
    }

    // Proxy to agent test endpoint
    const agentResp = await fetch(`${AGENT_API_URL}/llm-provider/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    })

    const result = await agentResp.json()
    return NextResponse.json(result, { status: agentResp.status })
  } catch (error) {
    console.error('Failed to test LLM provider:', error)
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 }
    )
  }
}
