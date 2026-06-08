import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const path = request.nextUrl.searchParams.get('path')
  const maxBytes = request.nextUrl.searchParams.get('maxBytes')

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  try {
    let url = `${AGENT_API_URL}/workspace/preview?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`
    if (maxBytes) url += `&maxBytes=${encodeURIComponent(maxBytes)}`
    const resp = await fetch(url, { cache: 'no-store' })
    const data = await resp.json()
    return NextResponse.json(data, { status: resp.status })
  } catch (error) {
    console.error('workspace/preview proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to preview' },
      { status: 502 }
    )
  }
}
