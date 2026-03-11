import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

const BUILT_IN_SKILLS = [
  {
    id: 'cve_exploit',
    name: 'CVE Exploit',
    description: 'Exploit known CVEs using Metasploit modules against target services',
  },
  {
    id: 'brute_force_credential_guess',
    name: 'Brute Force',
    description: 'Password and credential attacks using Hydra against login services',
  },
  {
    id: 'phishing_social_engineering',
    name: 'Phishing / Social Engineering',
    description: 'Payload generation, malicious documents, and email delivery to human targets',
  },
]

// GET /api/users/[id]/attack-skills/available — Built-in + user skills for project toggle UI
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const userSkills = await prisma.userAttackSkill.findMany({
      where: { userId: id },
      select: { id: true, name: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })

    return NextResponse.json({
      builtIn: BUILT_IN_SKILLS,
      user: userSkills,
    })
  } catch (error) {
    console.error('Failed to fetch available attack skills:', error)
    return NextResponse.json(
      { error: 'Failed to fetch available attack skills' },
      { status: 500 }
    )
  }
}
