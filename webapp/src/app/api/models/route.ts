import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/models { userId? } - Fetch available AI models from all configured providers.
// Body-based (not query-string) so plaintext apiKey values never appear in access logs.
export async function POST(request: NextRequest) {
  try {
    const { userId } = await request.json().catch(() => ({ userId: null }))

    let providers: unknown[] = []
    if (userId) {
      providers = await prisma.userLlmProvider.findMany({ where: { userId } })
    }

    const res = await fetch(`${AGENT_API_URL}/models`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providers: providers.length > 0 ? providers : null }),
      cache: 'no-store',
    })

    if (!res.ok) {
      console.error('Failed to fetch models from agent API:', await res.text())
      return NextResponse.json(
        { error: 'Failed to fetch models from agent API' },
        { status: 503 }
      )
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Failed to connect to agent API for models:', error)
    return NextResponse.json(
      { error: 'Failed to connect to agent API' },
      { status: 503 }
    )
  }
}
