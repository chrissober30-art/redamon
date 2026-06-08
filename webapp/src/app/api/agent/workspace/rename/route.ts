import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function POST(request: NextRequest) {
  let body: { projectId?: string; path?: string; newName?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }

  if (!body.projectId || !body.path || !body.newName) {
    return NextResponse.json({ error: 'projectId, path, newName required' }, { status: 400 })
  }

  try {
    const resp = await fetch(`${AGENT_API_URL}/workspace/rename`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!resp.ok) {
      const text = await resp.text()
      return NextResponse.json({ error: text }, { status: resp.status })
    }
    return NextResponse.json(await resp.json())
  } catch (error) {
    console.error('workspace/rename proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to rename' },
      { status: 502 }
    )
  }
}
