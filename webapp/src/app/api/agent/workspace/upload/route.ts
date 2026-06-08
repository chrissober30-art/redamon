import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

// Increase body size limit so this proxy can stream large uploads.
export const runtime = 'nodejs'
export const maxDuration = 60

export async function POST(request: NextRequest) {
  // Pass the original multipart body straight through; FastAPI parses it.
  const formData = await request.formData()
  const projectId = formData.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }
  const file = formData.get('file')
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'file required' }, { status: 400 })
  }

  try {
    // Re-encode as multipart for upstream. fetch() handles this for FormData.
    const resp = await fetch(`${AGENT_API_URL}/workspace/upload`, {
      method: 'POST',
      body: formData,
    })
    const data = await resp.json()
    return NextResponse.json(data, { status: resp.status })
  } catch (error) {
    console.error('workspace/upload proxy error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to upload' },
      { status: 502 }
    )
  }
}
