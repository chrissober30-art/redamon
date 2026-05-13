/** POST /api/mcp/test — proxy to agent's /mcp/test for live MCP draft validation.
 *
 * Body shape: { server: MCPServer, userId: string }.
 * userId is required (and explicit, not relying on middleware headers) so
 * we can restore a masked auth.token from the user's saved DB record. The
 * UI sends it from the same `userId` prop already used by the form's CRUD
 * endpoints — no JWT header juggling.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { MASK_PREFIX, type MCPServer } from '@/lib/mcp/schema'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json() as { server: MCPServer; userId?: string }
    const body = payload.server
    const userId = payload.userId

    if (!body) {
      return NextResponse.json(
        { ok: false, error: 'request body must include `server`', discovered_tools: [], warnings: [], elapsed_ms: 0 },
        { status: 400 },
      )
    }

    // If the user clicked Test on a saved server, the token field is the
    // mask. Substitute the real token from the DB before forwarding.
    if (body.auth?.token?.startsWith(MASK_PREFIX)) {
      if (!userId) {
        return NextResponse.json({
          ok: false,
          error: 'token is masked but request did not include userId — cannot restore from DB',
          discovered_tools: [], warnings: [], elapsed_ms: 0,
        }, { status: 400 })
      }
      const settings = await prisma.userSettings.findUnique({
        where: { userId },
        select: { mcpServers: true },
      })
      const saved = (Array.isArray(settings?.mcpServers) ? settings!.mcpServers : []) as MCPServer[]
      const existing = saved.find(s => s.id === body.id)
      if (existing?.auth?.token && !existing.auth.token.startsWith(MASK_PREFIX)) {
        body.auth = { ...body.auth, token: existing.auth.token }
      } else {
        return NextResponse.json({
          ok: false,
          error: `token is masked and no saved literal for server '${body.id}' — paste the token again`,
          discovered_tools: [], warnings: [], elapsed_ms: 0,
        }, { status: 400 })
      }
    }

    const upstream = await fetch(`${AGENT_API_URL}/mcp/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(35_000),
    })
    const data = await upstream.json().catch(() => ({}))
    return NextResponse.json(data, { status: upstream.status })
  } catch (error) {
    console.error('Failed to proxy /mcp/test:', error)
    const message = error instanceof Error ? error.message : 'unknown error'
    return NextResponse.json(
      { ok: false, error: `proxy failed: ${message}`, discovered_tools: [], warnings: [], elapsed_ms: 0 },
      { status: 502 },
    )
  }
}
