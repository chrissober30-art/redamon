'use client'

import { useState, useEffect, useCallback } from 'react'
import { Plus, Pencil, Trash2, Loader2, Eye, EyeOff, Upload, Download, Swords } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import type { ProviderData } from '@/components/settings/LlmProviderForm'
import { PROVIDER_TYPES } from '@/lib/llmProviderPresets'
import { Modal } from '@/components/ui/Modal/Modal'
import styles from '@/components/settings/Settings.module.css'

interface UserSettings {
  tavilyApiKey: string
  shodanApiKey: string
  serpApiKey: string
  nvdApiKey: string
  urlscanApiKey: string
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
}

const EMPTY_SETTINGS: UserSettings = {
  tavilyApiKey: '',
  shodanApiKey: '',
  serpApiKey: '',
  nvdApiKey: '',
  urlscanApiKey: '',
  ngrokAuthtoken: '',
  chiselServerUrl: '',
  chiselAuth: '',
}

function getProviderIcon(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.icon || '⚙️'
}

function getProviderLabel(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.name || providerType
}

export default function SettingsPage() {
  const { userId } = useProject()

  // LLM Providers
  const [providers, setProviders] = useState<ProviderData[]>([])
  const [providersLoading, setProvidersLoading] = useState(true)
  const [showProviderForm, setShowProviderForm] = useState(false)
  const [editingProvider, setEditingProvider] = useState<ProviderData | null>(null)

  // User Settings
  const [settings, setSettings] = useState<UserSettings>(EMPTY_SETTINGS)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [visibleFields, setVisibleFields] = useState<Record<string, boolean>>({})

  // Attack Skills
  const [attackSkills, setAttackSkills] = useState<{ id: string; name: string; description?: string | null; createdAt: string }[]>([])
  const [skillsLoading, setSkillsLoading] = useState(true)
  const [skillNameModal, setSkillNameModal] = useState(false)
  const [pendingSkillContent, setPendingSkillContent] = useState('')
  const [pendingSkillName, setPendingSkillName] = useState('')
  const [pendingSkillDescription, setPendingSkillDescription] = useState('')
  const [skillUploading, setSkillUploading] = useState(false)
  // Edit description modal
  const [editDescModal, setEditDescModal] = useState(false)
  const [editingSkillId, setEditingSkillId] = useState('')
  const [editingSkillDescription, setEditingSkillDescription] = useState('')
  const [editDescSaving, setEditDescSaving] = useState(false)
  // Fetch attack skills
  const fetchSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) setAttackSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch attack skills:', err)
    } finally {
      setSkillsLoading(false)
    }
  }, [userId])

  // Upload skill from .md file — read file then open name modal
  const handleSkillUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return

    const reader = new FileReader()
    reader.onload = () => {
      setPendingSkillContent(reader.result as string)
      setPendingSkillName(file.name.replace(/\.md$/i, ''))
      setSkillNameModal(true)
    }
    reader.readAsText(file)
    e.target.value = '' // Reset input
  }, [userId])

  // Confirm skill upload from modal
  const confirmSkillUpload = useCallback(async () => {
    if (!userId || !pendingSkillName.trim()) return
    setSkillUploading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: pendingSkillName.trim(), description: pendingSkillDescription.trim() || null, content: pendingSkillContent }),
      })
      if (resp.ok) {
        fetchSkills()
        setSkillNameModal(false)
        setPendingSkillContent('')
        setPendingSkillName('')
        setPendingSkillDescription('')
      } else {
        const err = await resp.json()
        alert(err.error || 'Failed to upload skill')
      }
    } catch (err) {
      console.error('Failed to upload skill:', err)
    } finally {
      setSkillUploading(false)
    }
  }, [userId, pendingSkillName, pendingSkillDescription, pendingSkillContent, fetchSkills])

  // Download skill as .md
  const downloadSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        const blob = new Blob([skill.content], { type: 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${skillName}.md`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Failed to download skill:', err)
    }
  }, [userId])

  // Delete skill
  const deleteSkill = useCallback(async (skillId: string) => {
    if (!userId || !confirm('Delete this skill? It will be removed from all projects.')) return
    try {
      await fetch(`/api/users/${userId}/attack-skills/${skillId}`, { method: 'DELETE' })
      fetchSkills()
    } catch (err) {
      console.error('Failed to delete skill:', err)
    }
  }, [userId, fetchSkills])

  // Open edit description modal
  const openEditDescription = useCallback(async (skillId: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        setEditingSkillId(skillId)
        setEditingSkillDescription(skill.description || '')
        setEditDescModal(true)
      }
    } catch (err) {
      console.error('Failed to fetch skill:', err)
    }
  }, [userId])

  // Save edited description
  const saveEditDescription = useCallback(async () => {
    if (!userId || !editingSkillId) return
    setEditDescSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${editingSkillId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: editingSkillDescription.trim() || null }),
      })
      if (resp.ok) {
        fetchSkills()
        setEditDescModal(false)
        setEditingSkillId('')
        setEditingSkillDescription('')
      } else {
        const err = await resp.json()
        alert(err.error || 'Failed to update description')
      }
    } catch (err) {
      console.error('Failed to update skill description:', err)
    } finally {
      setEditDescSaving(false)
    }
  }, [userId, editingSkillId, editingSkillDescription, fetchSkills])

  // Fetch providers
  const fetchProviders = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/llm-providers`)
      if (resp.ok) setProviders(await resp.json())
    } catch (err) {
      console.error('Failed to fetch providers:', err)
    } finally {
      setProvidersLoading(false)
    }
  }, [userId])

  // Fetch user settings
  const fetchSettings = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/settings`)
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err)
    } finally {
      setSettingsLoading(false)
    }
  }, [userId])

  useEffect(() => {
    fetchProviders()
    fetchSettings()
    fetchSkills()
  }, [fetchProviders, fetchSettings, fetchSkills])

  // Delete provider
  const deleteProvider = useCallback(async (providerId: string) => {
    if (!userId || !confirm('Delete this provider? Models from it will no longer be available.')) return
    try {
      await fetch(`/api/users/${userId}/llm-providers/${providerId}`, { method: 'DELETE' })
      fetchProviders()
    } catch (err) {
      console.error('Failed to delete provider:', err)
    }
  }, [userId, fetchProviders])

  // Save user settings
  const saveSettings = useCallback(async () => {
    if (!userId) return
    setSettingsSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      })
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
        setSettingsDirty(false)
      }
    } catch (err) {
      console.error('Failed to save settings:', err)
    } finally {
      setSettingsSaving(false)
    }
  }, [userId, settings])

  const updateSetting = useCallback(<K extends keyof UserSettings>(field: K, value: string) => {
    setSettings(prev => ({ ...prev, [field]: value }))
    setSettingsDirty(true)
  }, [])

  const toggleFieldVisibility = useCallback((field: string) => {
    setVisibleFields(prev => ({ ...prev, [field]: !prev[field] }))
  }, [])

  if (!userId) {
    return (
      <div className={styles.page}>
        <h1 className={styles.pageTitle}>Global Settings</h1>
        <div className={styles.emptyState}>Select a user to configure settings.</div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.pageTitle}>Global Settings</h1>

      {/* Section 1: LLM Providers */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>LLM Providers</h2>
          {!showProviderForm && !editingProvider && (
            <button className="primaryButton" onClick={() => setShowProviderForm(true)}>
              <Plus size={14} /> Add Provider
            </button>
          )}
        </div>
        <p className={styles.sectionHint}>
          Models from all providers appear in every project&apos;s LLM selector. Key-based providers auto-discover available models.
        </p>

        {/* Provider form */}
        {(showProviderForm || editingProvider) && (
          <LlmProviderForm
            userId={userId}
            provider={editingProvider}
            onSave={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
              fetchProviders()
            }}
            onCancel={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
            }}
          />
        )}

        {/* Provider list */}
        {!showProviderForm && !editingProvider && (
          providersLoading ? (
            <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
          ) : providers.length === 0 ? (
            <div className={styles.emptyState}>No providers configured. Add one to get started.</div>
          ) : (
            <div className={styles.providerList}>
              {providers.map((p: ProviderData) => (
                <div key={p.id} className={styles.providerCard}>
                  <span className={styles.providerIcon}>{getProviderIcon(p.providerType)}</span>
                  <div className={styles.providerInfo}>
                    <div className={styles.providerName}>{p.name}</div>
                    <div className={styles.providerMeta}>
                      {getProviderLabel(p.providerType)}
                      {p.providerType === 'openai_compatible' && p.modelIdentifier && ` — ${p.modelIdentifier}`}
                    </div>
                  </div>
                  <div className={styles.providerActions}>
                    <button className="iconButton" title="Edit" onClick={() => setEditingProvider(p)}>
                      <Pencil size={14} />
                    </button>
                    <button className="iconButton" title="Delete" onClick={() => deleteProvider(p.id!)}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      {/* Section 2: Tool API Keys */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>Tool API Keys</h2>
        </div>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="Tavily API Key"
              hint="Enables web_search tool for CVE research and exploit lookups"
              signupUrl="https://app.tavily.com/home"
              badges={['AI Agent']}
              value={settings.tavilyApiKey}
              visible={!!visibleFields.tavilyApiKey}
              onToggle={() => toggleFieldVisibility('tavilyApiKey')}
              onChange={v => updateSetting('tavilyApiKey', v)}
            />
            <SecretField
              label="Shodan API Key"
              hint="Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)"
              signupUrl="https://account.shodan.io/"
              badges={['AI Agent', 'Recon Pipeline']}
              value={settings.shodanApiKey}
              visible={!!visibleFields.shodanApiKey}
              onToggle={() => toggleFieldVisibility('shodanApiKey')}
              onChange={v => updateSetting('shodanApiKey', v)}
            />
            <SecretField
              label="SerpAPI Key"
              hint="Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:). Free: 250 searches/month"
              signupUrl="https://serpapi.com/manage-api-key"
              badges={['AI Agent']}
              value={settings.serpApiKey}
              visible={!!visibleFields.serpApiKey}
              onToggle={() => toggleFieldVisibility('serpApiKey')}
              onChange={v => updateSetting('serpApiKey', v)}
            />
            <SecretField
              label="NVD API Key"
              hint="NIST NVD API key — increases CVE lookup rate limit from 5 to 120 requests/30s"
              signupUrl="https://nvd.nist.gov/developers/request-an-api-key"
              badges={['Recon Pipeline']}
              value={settings.nvdApiKey}
              visible={!!visibleFields.nvdApiKey}
              onToggle={() => toggleFieldVisibility('nvdApiKey')}
              onChange={v => updateSetting('nvdApiKey', v)}
            />
            <SecretField
              label="URLScan API Key"
              hint="Optional — used by URLScan.io OSINT enrichment for higher rate limits. Works without key (public results only)"
              signupUrl="https://urlscan.io/user/signup"
              badges={['Recon Pipeline']}
              value={settings.urlscanApiKey}
              visible={!!visibleFields.urlscanApiKey}
              onToggle={() => toggleFieldVisibility('urlscanApiKey')}
              onChange={v => updateSetting('urlscanApiKey', v)}
            />
          </div>
        )}
        {settingsDirty && !settingsSaving && (
          <div className={styles.formActions} style={{ justifyContent: 'flex-end', marginTop: '12px' }}>
            <button className="primaryButton" onClick={saveSettings} disabled={settingsSaving}>
              Save Settings
            </button>
          </div>
        )}
      </div>

      {/* Section 3: Tunneling */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>Tunneling</h2>
        </div>
        <p className={styles.sectionHint}>
          Configure reverse shell tunneling. Choose ngrok (free, single port) or chisel (multi-port, requires VPS). Changes apply immediately.
        </p>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="ngrok Auth Token"
              hint="Enables ngrok TCP tunnel for reverse shells on port 4444. Stageless payloads only."
              signupUrl="https://dashboard.ngrok.com/get-started/your-authtoken"
              value={settings.ngrokAuthtoken}
              visible={!!visibleFields.ngrokAuthtoken}
              onToggle={() => toggleFieldVisibility('ngrokAuthtoken')}
              onChange={v => updateSetting('ngrokAuthtoken', v)}
            />
            <div className="formGroup">
              <label className="formLabel">Chisel Server URL</label>
              <input
                className="textInput"
                type="text"
                value={settings.chiselServerUrl}
                onChange={e => updateSetting('chiselServerUrl', e.target.value)}
                placeholder="e.g. http://your-vps.com:9090"
              />
              <span className="formHint">
                Your VPS chisel server URL. Run on VPS: <code>chisel server -p 9090 --reverse</code>. Tunnels ports 4444 (handler) + 8080 (web delivery).
              </span>
            </div>
            <SecretField
              label="Chisel Auth"
              hint="user:pass for chisel server authentication (optional — only if your chisel server requires auth)"
              value={settings.chiselAuth}
              visible={!!visibleFields.chiselAuth}
              onToggle={() => toggleFieldVisibility('chiselAuth')}
              onChange={v => updateSetting('chiselAuth', v)}
            />
          </div>
        )}
        {settingsDirty && !settingsSaving && (
          <div className={styles.formActions} style={{ justifyContent: 'flex-end', marginTop: '12px' }}>
            <button className="primaryButton" onClick={saveSettings} disabled={settingsSaving}>
              Save Settings
            </button>
          </div>
        )}
      </div>

      {/* Section 4: Agent Skills */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}><Swords size={16} /> Agent Skills</h2>
          <label className="primaryButton" style={{ cursor: 'pointer' }}>
            <Upload size={14} /> Upload Skill
            <input
              type="file"
              accept=".md"
              style={{ display: 'none' }}
              onChange={handleSkillUpload}
            />
          </label>
        </div>
        <p className={styles.sectionHint}>
          Upload .md files defining custom attack skill workflows. Skills become available as toggles in all project settings.
        </p>

        {skillsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : attackSkills.length === 0 ? (
          <div className={styles.emptyState}>No custom skills uploaded yet. Upload a .md file to get started.</div>
        ) : (
          <div className={styles.providerList}>
            {attackSkills.map(skill => (
              <div key={skill.id} className={styles.providerCard}>
                <span className={styles.providerIcon}><Swords size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={styles.providerName}>{skill.name}</div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit description" onClick={() => openEditDescription(skill.id)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => downloadSkill(skill.id, skill.name)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => deleteSkill(skill.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Skill upload modal */}
      <Modal
        isOpen={skillNameModal}
        onClose={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
        title="Upload Attack Skill"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={!pendingSkillName.trim() || skillUploading}
              onClick={confirmSkillUpload}
            >
              {skillUploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
              Upload
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Skill Name</label>
          <input
            className="textInput"
            type="text"
            value={pendingSkillName}
            onChange={(e) => setPendingSkillName(e.target.value)}
            placeholder="e.g. SQL Injection Workflow"
            autoFocus
          />
          <span className="formHint">
            This name appears in project settings and classification badges.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={pendingSkillDescription}
            onChange={(e) => setPendingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>

      {/* Edit description modal */}
      <Modal
        isOpen={editDescModal}
        onClose={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
        title="Edit Skill Description"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={editDescSaving}
              onClick={saveEditDescription}
            >
              {editDescSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={editingSkillDescription}
            onChange={(e) => setEditingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
            autoFocus
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>
    </div>
  )
}

// Badge color mapping
const BADGE_STYLES: Record<string, React.CSSProperties> = {
  'AI Agent': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(139, 92, 246, 0.15)',
    color: 'rgb(167, 139, 250)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'Recon Pipeline': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(20, 184, 166, 0.15)',
    color: 'rgb(94, 234, 212)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
}

// Reusable secret field component
function SecretField({
  label,
  hint,
  signupUrl,
  badges,
  value,
  visible,
  onToggle,
  onChange,
}: {
  label: string
  hint: string
  signupUrl?: string
  badges?: string[]
  value: string
  visible: boolean
  onToggle: () => void
  onChange: (v: string) => void
}) {
  return (
    <div className="formGroup">
      <label className="formLabel">
        {label}
        {badges?.map(badge => (
          <span key={badge} style={BADGE_STYLES[badge] || BADGE_STYLES['AI Agent']}>
            {badge}
          </span>
        ))}
      </label>
      <div className={styles.secretInputWrapper}>
        <input
          className="textInput"
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={`Enter ${label.toLowerCase()}`}
        />
        <button className={styles.secretToggle} onClick={onToggle} type="button">
          {visible ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
      <span className="formHint">
        {hint}
        {signupUrl && (
          <>
            {' — '}
            <a href={signupUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
              Get API key
            </a>
          </>
        )}
      </span>
    </div>
  )
}
