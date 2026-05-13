import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

function maskResource(r: Record<string, unknown>): Record<string, unknown> {
  return {
    ...r,
    githubTokenOverride: maskSecret(r.githubTokenOverride as string),
  }
}

// GET /api/users/[id]/tradecraft-resources/[resourceId]
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    const resource = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!resource) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    if (internal) {
      return NextResponse.json(resource)
    }
    return NextResponse.json(maskResource(resource as unknown as Record<string, unknown>))
  } catch (error) {
    console.error('Failed to fetch tradecraft resource:', error)
    return NextResponse.json(
      { error: 'Failed to fetch tradecraft resource' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/tradecraft-resources/[resourceId]
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const body = await request.json()

    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }

    // Strip server-managed fields
    const updateData: Record<string, unknown> = { ...body }
    delete updateData.id
    delete updateData.userId
    delete updateData.slug              // slug is immutable
    delete updateData.createdAt
    delete updateData.updatedAt
    delete updateData.lastVerifiedAt
    delete updateData.lastRefreshedAt
    delete updateData.summary           // summary set by /verify
    delete updateData.sitemap           // sitemap set by /verify
    delete updateData.resourceType      // type set by /verify
    delete updateData.crawlStoppedBecause
    delete updateData.crawlStats

    // Preserve masked github token
    if ('githubTokenOverride' in updateData) {
      const val = updateData.githubTokenOverride as string
      if (typeof val === 'string' && val.startsWith('••••')) {
        updateData.githubTokenOverride = existing.githubTokenOverride
      }
    }

    const updated = await prisma.userTradecraftResource.update({
      where: { id: resourceId },
      data: updateData,
    })
    return NextResponse.json(maskResource(updated as unknown as Record<string, unknown>))
  } catch (error) {
    console.error('Failed to update tradecraft resource:', error)
    return NextResponse.json(
      { error: 'Failed to update tradecraft resource' },
      { status: 500 }
    )
  }
}

// DELETE /api/users/[id]/tradecraft-resources/[resourceId]
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const existing = await prisma.userTradecraftResource.findFirst({
      where: { id: resourceId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    await prisma.userTradecraftResource.delete({ where: { id: resourceId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete tradecraft resource:', error)
    return NextResponse.json(
      { error: 'Failed to delete tradecraft resource' },
      { status: 500 }
    )
  }
}
