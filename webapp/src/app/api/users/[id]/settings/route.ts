import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Mask a secret string to show only the last 4 characters. */
function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

// GET /api/users/[id]/settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    let settings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    if (!settings) {
      // Return empty defaults (don't create yet)
      return NextResponse.json({
        tavilyApiKey: '',
        shodanApiKey: '',
        serpApiKey: '',
      })
    }

    if (!internal) {
      // Mask secrets for frontend
      settings = {
        ...settings,
        tavilyApiKey: maskSecret(settings.tavilyApiKey),
        shodanApiKey: maskSecret(settings.shodanApiKey),
        serpApiKey: maskSecret(settings.serpApiKey),
      }
    }

    return NextResponse.json(settings)
  } catch (error) {
    console.error('Failed to fetch user settings:', error)
    return NextResponse.json(
      { error: 'Failed to fetch user settings' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/settings - Upsert user settings
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    // If a masked value is sent back, preserve the existing value
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    const data: Record<string, string> = {}
    const fields = ['tavilyApiKey', 'shodanApiKey', 'serpApiKey'] as const

    for (const field of fields) {
      if (field in body) {
        const val = body[field] as string
        // If the value starts with '••••', keep existing
        if (val.startsWith('••••') && existing) {
          data[field] = existing[field]
        } else {
          data[field] = val
        }
      }
    }

    const settings = await prisma.userSettings.upsert({
      where: { userId: id },
      update: data,
      create: { userId: id, ...data },
    })

    // Return masked
    return NextResponse.json({
      ...settings,
      tavilyApiKey: maskSecret(settings.tavilyApiKey),
      shodanApiKey: maskSecret(settings.shodanApiKey),
      serpApiKey: maskSecret(settings.serpApiKey),
    })
  } catch (error) {
    console.error('Failed to update user settings:', error)
    return NextResponse.json(
      { error: 'Failed to update user settings' },
      { status: 500 }
    )
  }
}
