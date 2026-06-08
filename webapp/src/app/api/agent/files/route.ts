import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function GET(request: NextRequest) {
  const path = request.nextUrl.searchParams.get('path')
  const projectId = request.nextUrl.searchParams.get('projectId')

  if (!path) {
    return NextResponse.json({ error: 'Missing path parameter' }, { status: 400 })
  }

  try {
    // When projectId is provided, use the project-scoped workspace download
    // (direct bind-mount read, no kali_shell base64 round-trip). Falls back
    // to the legacy /files endpoint for the existing /tmp/-only flow so we
    // don't break in-chat downloads from older messages.
    const agentUrl = projectId
      ? `${AGENT_API_URL}/workspace/download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`
      : `${AGENT_API_URL}/files?path=${encodeURIComponent(path)}`
    const resp = await fetch(agentUrl)

    if (!resp.ok) {
      const text = await resp.text()
      return NextResponse.json({ error: text }, { status: resp.status })
    }

    const buffer = await resp.arrayBuffer()
    const contentDisposition = resp.headers.get('Content-Disposition') || `attachment; filename="${path.split('/').pop()}"`
    const contentType = resp.headers.get('Content-Type') || 'application/octet-stream'

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': contentDisposition,
        'Content-Length': String(buffer.byteLength),
        'Cache-Control': 'no-cache',
      },
    })
  } catch (error) {
    console.error('File proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to download file' },
      { status: 500 }
    )
  }
}
