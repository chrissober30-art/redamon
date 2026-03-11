import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/users/[id]/attack-skills — List skills (id, name, createdAt; exclude content)
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const skills = await prisma.userAttackSkill.findMany({
      where: { userId: id },
      select: { id: true, name: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })

    return NextResponse.json(skills)
  } catch (error) {
    console.error('Failed to fetch attack skills:', error)
    return NextResponse.json(
      { error: 'Failed to fetch attack skills' },
      { status: 500 }
    )
  }
}

const MAX_CONTENT_SIZE = 50 * 1024 // 50KB
const MAX_SKILLS_PER_USER = 20

// POST /api/users/[id]/attack-skills — Create skill { name, content }
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const { name, content } = body
    if (!name || typeof name !== 'string' || !name.trim()) {
      return NextResponse.json(
        { error: 'name is required' },
        { status: 400 }
      )
    }
    if (!content || typeof content !== 'string') {
      return NextResponse.json(
        { error: 'content is required' },
        { status: 400 }
      )
    }
    if (content.length > MAX_CONTENT_SIZE) {
      return NextResponse.json(
        { error: `content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB` },
        { status: 400 }
      )
    }

    // Check skill count limit
    const count = await prisma.userAttackSkill.count({ where: { userId: id } })
    if (count >= MAX_SKILLS_PER_USER) {
      return NextResponse.json(
        { error: `Maximum of ${MAX_SKILLS_PER_USER} skills per user reached` },
        { status: 400 }
      )
    }

    const skill = await prisma.userAttackSkill.create({
      data: {
        userId: id,
        name: name.trim(),
        content,
      },
      select: { id: true, name: true, createdAt: true },
    })

    return NextResponse.json(skill, { status: 201 })
  } catch (error) {
    console.error('Failed to create attack skill:', error)
    return NextResponse.json(
      { error: 'Failed to create attack skill' },
      { status: 500 }
    )
  }
}
