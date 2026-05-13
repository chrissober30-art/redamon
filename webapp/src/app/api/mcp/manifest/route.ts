/**
 * GET /api/mcp/manifest — proxy to agent's /mcp/manifest.
 *
 * Returns the merged view (system + user MCP servers) the agent currently
 * has loaded. Used by ToolMatrixSection to render dynamic phase toggles.
 */
import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

export async function GET(_request: NextRequest) {
  try {
    const upstream = await fetch(`${AGENT_API_URL}/mcp/manifest`, {
      signal: AbortSignal.timeout(10_000),
    })
    const data = await upstream.json().catch(() => ({}))
    return NextResponse.json(data, { status: upstream.status })
  } catch (error) {
    console.error('Failed to proxy /mcp/manifest:', error)
    return NextResponse.json(
      { servers: [], errors: [], warnings: [], system_server_ids: [] },
      { status: 200 },  // graceful: UI can render built-ins-only when agent unreachable
    )
  }
}
