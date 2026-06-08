import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function POST(request: NextRequest) {
  let body: { projectId?: string; path?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  if (!body.projectId || !body.path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  try {
    const resp = await fetch(`${AGENT_API_URL}/workspace/mkdir`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await resp.json()
    return NextResponse.json(data, { status: resp.status })
  } catch (error) {
    console.error('workspace/mkdir proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to mkdir' },
      { status: 502 }
    )
  }
}
