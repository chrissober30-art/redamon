import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function DELETE(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const path = request.nextUrl.searchParams.get('path')
  const recursive = request.nextUrl.searchParams.get('recursive') === 'true'

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  try {
    const url = `${AGENT_API_URL}/workspace?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&recursive=${recursive}`
    const resp = await fetch(url, { method: 'DELETE' })
    if (!resp.ok) {
      const text = await resp.text()
      return NextResponse.json({ error: text }, { status: resp.status })
    }
    return NextResponse.json(await resp.json())
  } catch (error) {
    console.error('workspace/delete proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to delete' },
      { status: 502 }
    )
  }
}
