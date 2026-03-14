'use client'

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useSearchParams, useRouter, usePathname } from 'next/navigation'

export interface ProjectSummary {
  id: string
  name: string
  targetDomain: string
  ipMode?: boolean
  targetIps?: string[]
  subdomainList?: string[]
  description?: string
  agentOpenaiModel?: string
  agentToolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  agentDeepThinkEnabled?: boolean
  roeEnabled?: boolean
  createdAt: string
  updatedAt: string
}

interface ProjectContextValue {
  currentProject: ProjectSummary | null
  setCurrentProject: (project: ProjectSummary | null) => void
  projectId: string | null
  userId: string | null
  setUserId: (id: string | null) => void
  isLoading: boolean
}

const ProjectContext = createContext<ProjectContextValue | null>(null)

const STORAGE_KEY_PROJECT = 'redamon-current-project'
const STORAGE_KEY_USER = 'redamon-current-user'

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [currentProject, setCurrentProjectState] = useState<ProjectSummary | null>(null)
  const [userId, setUserIdState] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const searchParams = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()

  // Initialize from URL or localStorage
  useEffect(() => {
    const urlProjectId = searchParams.get('project')
    const savedProjectId = localStorage.getItem(STORAGE_KEY_PROJECT)
    const savedUserId = localStorage.getItem(STORAGE_KEY_USER)
    const projectIdToLoad = urlProjectId || savedProjectId

    // Load user ID
    if (savedUserId) {
      setUserIdState(savedUserId)
    }

    // Load project
    if (projectIdToLoad) {
      fetch(`/api/projects/${projectIdToLoad}`)
        .then(res => res.ok ? res.json() : null)
        .then(project => {
          if (project) {
            setCurrentProjectState({
              id: project.id,
              name: project.name,
              targetDomain: project.targetDomain,
              ipMode: project.ipMode,
              targetIps: project.targetIps,
              subdomainList: project.subdomainList,
              description: project.description,
              agentOpenaiModel: project.agentOpenaiModel,
              agentToolPhaseMap: typeof project.agentToolPhaseMap === 'string'
                ? JSON.parse(project.agentToolPhaseMap)
                : project.agentToolPhaseMap,
              stealthMode: project.stealthMode,
              agentDeepThinkEnabled: project.agentDeepThinkEnabled,
              roeEnabled: project.roeEnabled,
              createdAt: project.createdAt,
              updatedAt: project.updatedAt
            })
            localStorage.setItem(STORAGE_KEY_PROJECT, project.id)
          } else {
            // Remove stale project ID from localStorage if project no longer exists
            localStorage.removeItem(STORAGE_KEY_PROJECT)
          }
        })
        .catch(console.error)
        .finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [searchParams])

  const setCurrentProject = useCallback((project: ProjectSummary | null) => {
    setCurrentProjectState(project)
    if (project) {
      localStorage.setItem(STORAGE_KEY_PROJECT, project.id)
      // Update URL without navigation if we're on a page that uses project context
      if (pathname.startsWith('/graph') || pathname.startsWith('/projects') || pathname.startsWith('/insights')) {
        const params = new URLSearchParams(searchParams.toString())
        params.set('project', project.id)
        router.replace(`${pathname}?${params.toString()}`, { scroll: false })
      }
    } else {
      localStorage.removeItem(STORAGE_KEY_PROJECT)
      // Remove project from URL
      const params = new URLSearchParams(searchParams.toString())
      params.delete('project')
      const newUrl = params.toString() ? `${pathname}?${params.toString()}` : pathname
      router.replace(newUrl, { scroll: false })
    }
  }, [searchParams, router, pathname])

  const setUserId = useCallback((id: string | null) => {
    setUserIdState(id)
    if (id) {
      localStorage.setItem(STORAGE_KEY_USER, id)
    } else {
      localStorage.removeItem(STORAGE_KEY_USER)
    }
  }, [])

  return (
    <ProjectContext.Provider value={{
      currentProject,
      setCurrentProject,
      projectId: currentProject?.id || null,
      userId,
      setUserId,
      isLoading,
    }}>
      {children}
    </ProjectContext.Provider>
  )
}

export function useProject() {
  const context = useContext(ProjectContext)
  if (!context) {
    throw new Error('useProject must be used within ProjectProvider')
  }
  return context
}
