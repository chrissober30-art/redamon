/**
 * GET  /api/users/[id]/mcp        — list user's MCP servers
 * POST /api/users/[id]/mcp        — add a new MCP server
 *
 * Triggers async POST ${AGENT_API_URL}/mcp/reload after a successful write
 * so the running agent picks up changes without manual intervention.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { mcpServerSchema, validateMcpServers, MASK_PREFIX, type MCPServer } from '@/lib/mcp/schema'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

interface RouteParams {
  params: Promise<{ id: string }>
}

async function fireReload(userMcpServers: unknown) {
  // Fire-and-forget: log a failure but don't block the request.
  try {
    await fetch(`${AGENT_API_URL}/mcp/reload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userMcpServers }),
    })
  } catch (e) {
    console.warn('Failed to ping agent /mcp/reload:', e)
  }
}

/** Mask a secret showing only the last 4 characters (matches user_settings route). */
function maskSecret(value: string): string {
  if (!value) return ''
  if (value.length <= 4) return '••••'
  return '••••••••' + value.slice(-4)
}

/** Replace literal auth.token values with masked placeholders in-place. */
export function maskMcpServersForApi(servers: MCPServer[]): MCPServer[] {
  return servers.map(srv => {
    if (srv.auth && srv.auth.token) {
      return { ...srv, auth: { ...srv.auth, token: maskSecret(srv.auth.token) } }
    }
    return srv
  })
}

/** When the user submits a server with a masked token (••••), preserve the
 *  existing one from the DB rather than writing the placeholder. */
export function restoreMaskedToken(incoming: MCPServer, existing: MCPServer | undefined): MCPServer {
  if (!incoming.auth || !incoming.auth.token) return incoming
  if (!incoming.auth.token.startsWith(MASK_PREFIX)) return incoming
  if (existing?.auth?.token) {
    return { ...incoming, auth: { ...incoming.auth, token: existing.auth.token } }
  }
  // Masked sent for a server with no prior token — strip the placeholder so
  // the schema's at-least-one validator triggers.
  return { ...incoming, auth: { ...incoming.auth, token: undefined } }
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const settings = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const raw = (settings?.mcpServers as unknown) ?? []
    const servers = Array.isArray(raw) ? (raw as MCPServer[]) : []
    return NextResponse.json({ servers: maskMcpServersForApi(servers) })
  } catch (error) {
    console.error('Failed to list MCP servers:', error)
    return NextResponse.json({ error: 'Failed to list MCP servers' }, { status: 500 })
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const parsed = mcpServerSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({
        error: 'invalid MCP server',
        issues: parsed.error.issues.map(i => ({ path: i.path, message: i.message })),
      }, { status: 400 })
    }
    const newServer: MCPServer = parsed.data

    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const current = (Array.isArray(existing?.mcpServers) ? existing!.mcpServers : []) as MCPServer[]

    if (current.some((s) => s.id === newServer.id)) {
      return NextResponse.json({ error: `server id '${newServer.id}' already exists` }, { status: 409 })
    }

    const next = [...current, newServer]

    // Re-validate with cross-server checks (tool-name collisions, etc.)
    const { valid, errors } = validateMcpServers(next)
    if (errors.length > 0 || valid.length !== next.length) {
      return NextResponse.json({ error: 'cross-server validation failed', issues: errors }, { status: 400 })
    }

    await prisma.userSettings.upsert({
      where: { userId: id },
      update: { mcpServers: next as unknown as object },
      create: { userId: id, mcpServers: next as unknown as object },
    })

    void fireReload(next)
    // Mask the literal token in the response so the UI shows the placeholder.
    const [returned] = maskMcpServersForApi([newServer])
    return NextResponse.json({ server: returned, servers: maskMcpServersForApi(next) }, { status: 201 })
  } catch (error) {
    console.error('Failed to add MCP server:', error)
    return NextResponse.json({ error: 'Failed to add MCP server' }, { status: 500 })
  }
}
