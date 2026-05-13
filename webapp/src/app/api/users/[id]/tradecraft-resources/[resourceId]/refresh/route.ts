import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/users/[id]/tradecraft-resources/[resourceId]/refresh
//   Same as /verify with force=true and bumps lastRefreshedAt.
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    const userSettings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })
    const tokenForFetch =
      (existing.githubTokenOverride && existing.githubTokenOverride.length > 0)
        ? existing.githubTokenOverride
        : ((userSettings as unknown as Record<string, string> | null)?.githubAccessToken || '')

    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 240_000)

    let agentResp: Response
    try {
      agentResp = await fetch(`${AGENT_API_URL}/tradecraft/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: existing.url,
          user_id: id,
          github_token: tokenForFetch,
          force: true,
        }),
        signal: controller.signal,
      })
    } finally {
      clearTimeout(t)
    }

    if (!agentResp.ok) {
      const errText = await agentResp.text()
      const updated = await prisma.userTradecraftResource.update({
        where: { id: resourceId },
        data: { lastError: `refresh failed (${agentResp.status}): ${errText.slice(0, 500)}` },
      })
      return NextResponse.json(updated, { status: agentResp.status })
    }

    const result = await agentResp.json()
    const now = new Date()
    const updated = await prisma.userTradecraftResource.update({
      where: { id: resourceId },
      data: {
        summary: result.summary ?? '',
        resourceType: result.resource_type ?? existing.resourceType,
        sitemap: result.sitemap ?? {},
        crawlStoppedBecause: result.crawl_stopped_because ?? '',
        crawlStats: result.crawl_stats ?? {},
        lastError: result.last_error ?? '',
        lastVerifiedAt: now,
        lastRefreshedAt: now,
      },
    })
    return NextResponse.json(updated)
  } catch (error: unknown) {
    const e = error as { name?: string }
    if (e?.name === 'AbortError') {
      return NextResponse.json({ error: 'refresh timed out' }, { status: 504 })
    }
    console.error('Failed to refresh tradecraft resource:', error)
    return NextResponse.json(
      { error: 'Failed to refresh tradecraft resource' },
      { status: 500 }
    )
  }
}
