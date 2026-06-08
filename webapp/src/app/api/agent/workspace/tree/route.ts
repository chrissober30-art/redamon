import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const path = request.nextUrl.searchParams.get('path') ?? '.'
  const maxDepth = request.nextUrl.searchParams.get('maxDepth') ?? '3'
  const maxEntries = request.nextUrl.searchParams.get('maxEntries') ?? '500'

  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }

  try {
    const url = `${AGENT_API_URL}/workspace/tree?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&maxDepth=${maxDepth}&maxEntries=${maxEntries}`
    const resp = await fetch(url, { cache: 'no-store' })
    if (!resp.ok) {
      const text = await resp.text()
      return NextResponse.json({ error: text }, { status: resp.status })
    }
    return NextResponse.json(await resp.json())
  } catch (error) {
    console.error('workspace/tree proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to fetch tree' },
      { status: 502 }
    )
  }
}
