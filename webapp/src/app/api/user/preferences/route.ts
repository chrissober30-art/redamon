import { NextRequest, NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'

export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session

  try {
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { uiPreferences: true },
    })
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }
    const prefs = (user.uiPreferences ?? {}) as Prisma.JsonObject
    return NextResponse.json(prefs)
  } catch (error) {
    console.error('Failed to fetch user preferences:', error)
    return NextResponse.json({ error: 'Failed to fetch preferences' }, { status: 500 })
  }
}

export async function PATCH(request: NextRequest) {
  const session = await requireSession()
  if (session instanceof NextResponse) return session

  let body: { featureKey?: unknown; value?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const { featureKey, value } = body
  if (typeof featureKey !== 'string' || featureKey.length === 0) {
    return NextResponse.json({ error: 'featureKey must be a non-empty string' }, { status: 400 })
  }
  if (value === undefined) {
    return NextResponse.json({ error: 'value is required' }, { status: 400 })
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { uiPreferences: true },
    })
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }
    const current = (user.uiPreferences ?? {}) as Prisma.InputJsonObject
    const next: Prisma.InputJsonObject = { ...current, [featureKey]: value as Prisma.InputJsonValue }
    const updated = await prisma.user.update({
      where: { id: session.userId },
      data: { uiPreferences: next },
      select: { uiPreferences: true },
    })
    return NextResponse.json(updated.uiPreferences ?? {})
  } catch (error) {
    console.error('Failed to update user preferences:', error)
    return NextResponse.json({ error: 'Failed to update preferences' }, { status: 500 })
  }
}
