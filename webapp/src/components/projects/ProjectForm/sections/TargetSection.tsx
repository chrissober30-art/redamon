'use client'

import { useState, useMemo, useEffect } from 'react'
import { ChevronDown, Target, ShieldAlert, AlertTriangle } from 'lucide-react'
import { AiToggleLabel } from '../AiToggleLabel'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import { FileImportButton } from '../FileImportButton'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TargetSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  mode?: 'create' | 'edit'
}

// Helper to convert stored format (with dots) to display format (without dots)
function toDisplayPrefixes(subdomainList: string[]): string {
  return subdomainList
    .filter(s => s !== '.')  // Exclude root domain marker
    .map(s => s.endsWith('.') ? s.slice(0, -1) : s)  // Remove trailing dot
    .join(', ')
}

// Helper to convert display format to stored format (with trailing dots)
function toStoredPrefixes(displayValue: string, includeRoot: boolean): string[] {
  const prefixes = displayValue
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.endsWith('.') ? s : s + '.')  // Add trailing dot if missing

  if (includeRoot) {
    prefixes.push('.')
  }

  return prefixes
}

// Helper to parse IP textarea into array
function parseIpList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map(s => s.trim())
    .filter(Boolean)
}

export function TargetSection({ data, updateField, mode = 'create' }: TargetSectionProps) {
  const isLocked = mode === 'edit'
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()

  const ipMode = data.ipMode || false

  // Check if root domain is included in the list
  const includesRootDomain = useMemo(() => data.subdomainList.includes('.'), [data.subdomainList])

  // Display value without dots
  const displayPrefixes = useMemo(() => toDisplayPrefixes(data.subdomainList), [data.subdomainList])

  // Display value for IP textarea
  const displayIps = useMemo(() => (data.targetIps || []).join('\n'), [data.targetIps])

  // Hard guardrail: deterministic check for government/public domains (non-disableable)
  const hardBlockResult = useMemo(
    () => (!ipMode && data.targetDomain ? isHardBlockedDomain(data.targetDomain) : { blocked: false, reason: '' }),
    [ipMode, data.targetDomain]
  )

  const handlePrefixesChange = (value: string) => {
    updateField('subdomainList', toStoredPrefixes(value, includesRootDomain))
  }

  const handleRootDomainToggle = (checked: boolean) => {
    const currentPrefixes = toDisplayPrefixes(data.subdomainList)
    updateField('subdomainList', toStoredPrefixes(currentPrefixes, checked))
  }

  // When subdomain discovery is OFF and no prefixes are set, the only valid
  // target is the root domain. Force-enable "Include Root Domain" and lock it
  // so the pipeline cannot be started with zero targets (which would silently
  // produce empty results). Runs in edit mode too — it's a system-driven
  // safety net, not user editing of scope.
  const forceIncludeRootDomain = !ipMode
    && !data.subdomainDiscoveryEnabled
    && displayPrefixes.trim().length === 0

  // When the user supplies explicit Subdomain Prefixes, the pipeline runs in
  // FILTERED mode and the entire Subdomain Discovery group (Subfinder, Amass,
  // crt.sh, HackerTarget, Knockpy, puredns) is silently skipped. Force the
  // master toggle OFF so the UI matches what the backend actually does.
  const prefixesPresent = !ipMode && !isLocked && displayPrefixes.trim().length > 0

  useEffect(() => {
    if (forceIncludeRootDomain && !includesRootDomain) {
      handleRootDomainToggle(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [forceIncludeRootDomain, includesRootDomain])

  useEffect(() => {
    if (prefixesPresent && data.subdomainDiscoveryEnabled) {
      updateField('subdomainDiscoveryEnabled', false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefixesPresent, data.subdomainDiscoveryEnabled])

  const handleIpModeToggle = (checked: boolean) => {
    updateField('ipMode', checked)
    if (checked) {
      updateField('targetDomain', '')
      updateField('subdomainList', [])
    } else {
      updateField('targetIps', [])
    }
  }

  const handleIpsChange = (text: string) => {
    updateField('targetIps', parseIpList(text))
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Target size={16} />
          Target Configuration
          <WikiInfoButton target="Target" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Define the primary target for your security assessment. Choose between domain-based
            or IP-based targeting mode.
          </p>

          {/* IP Mode Toggle - locked in edit mode */}
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Start from IP</span>
              <p className={styles.toggleDescription}>
                Target IP addresses or CIDR ranges instead of a domain. The pipeline will
                attempt reverse DNS to discover hostnames.
              </p>
            </div>
            <Toggle
              checked={ipMode}
              onChange={handleIpModeToggle}
              disabled={isLocked}
            />
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Project Name
              </label>
              <input
                type="text"
                className="textInput"
                value={data.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="My Security Project"
              />
            </div>

            {!ipMode && (
              <div className={styles.fieldGroup}>
                <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                  Target Domain
                </label>
                <input
                  type="text"
                  className="textInput"
                  value={data.targetDomain}
                  onChange={(e) => updateField('targetDomain', e.target.value)}
                  placeholder="example.com"
                  disabled={isLocked}
                  title={isLocked ? 'Target domain cannot be changed after creation. Create a new project instead.' : undefined}
                />
              </div>
            )}
          </div>

          {/* Hard guardrail warning for government/public domains */}
          {hardBlockResult.blocked && (
            <div className={styles.shodanWarning} style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)' }}>
              <ShieldAlert size={14} style={{ color: '#ef4444' }} />
              <span>
                <strong>Target permanently blocked:</strong> Government, military, educational, and international
                organization websites (.gov, .mil, .edu, .int, etc.) are always blocked and cannot be used as targets,
                regardless of guardrail settings. This restriction cannot be disabled.
              </span>
            </div>
          )}

          {/* IP Mode: Target IPs textarea */}
          {ipMode && (
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Target IPs / CIDRs
              </label>
              <div className={styles.fileImportWrap}>
                <textarea
                  className="textarea"
                  value={displayIps}
                  onChange={(e) => handleIpsChange(e.target.value)}
                  placeholder={"192.168.1.1\n10.0.0.0/24\n2001:db8::1"}
                  rows={4}
                  disabled={isLocked}
                  title={isLocked ? 'Target IPs cannot be changed after creation.' : undefined}
                />
                {!isLocked && (
                  <FileImportButton
                    variant="textarea"
                    fieldName="target IPs / CIDRs"
                    onImport={(values) => updateField('targetIps', values)}
                  />
                )}
              </div>
              <span className={styles.fieldHint}>
                {isLocked
                  ? 'Target IPs are locked after project creation. Create a new project to change them.'
                  : 'Enter one IP or CIDR per line, or comma-separated. IPv4, IPv6, and CIDR ranges supported. Max /24 (256 hosts).'}
              </span>
            </div>
          )}

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Description</label>
            <textarea
              className="textarea"
              value={data.description || ''}
              onChange={(e) => updateField('description', e.target.value)}
              placeholder="Project description (optional)"
              rows={2}
            />
          </div>

          {/* Domain-mode only fields */}
          {!ipMode && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Subdomain Prefixes</label>
                <div className={styles.fileImportWrap}>
                  <input
                    type="text"
                    className="textInput"
                    value={displayPrefixes}
                    onChange={(e) => handlePrefixesChange(e.target.value)}
                    placeholder="www, api, admin (comma-separated)"
                    disabled={isLocked}
                    title={isLocked ? 'Subdomain list cannot be changed after creation. Create a new project instead.' : undefined}
                  />
                  {!isLocked && (
                    <FileImportButton
                      fieldName="subdomain prefixes"
                      onImport={(values) => handlePrefixesChange(values.join(', '))}
                    />
                  )}
                </div>
                <span className={styles.fieldHint}>
                  {isLocked
                    ? 'Target domain and subdomains are locked after project creation to keep graph data consistent. To change them, create a new project.'
                    : 'Leave empty to discover all subdomains. Enter prefixes without dots (e.g., "www, api, admin").'}
                </span>
                {!isLocked && displayPrefixes.trim().length === 0 && (
                  <div
                    className={styles.shodanWarning}
                    style={{
                      marginTop: 'var(--space-2)',
                      marginBottom: 0,
                      padding: 'var(--space-3) var(--space-4)',
                      fontSize: 'var(--text-sm)',
                      borderWidth: '2px',
                      borderColor: 'rgba(251, 146, 60, 0.5)',
                      background: 'rgba(251, 146, 60, 0.12)',
                      alignItems: 'center',
                    }}
                  >
                    <AlertTriangle size={22} style={{ color: '#fb923c' }} />
                    <span>
                      <strong>Heads up:</strong> Leaving Subdomain Prefixes empty starts full
                      subdomain enumeration across the entire domain. This will take
                      <strong> much, much longer </strong>
                      than scanning a specific set of prefixes.
                    </span>
                  </div>
                )}
                {prefixesPresent && (
                  <div
                    className={styles.shodanWarning}
                    style={{
                      marginTop: 'var(--space-2)',
                      marginBottom: 0,
                      padding: 'var(--space-3) var(--space-4)',
                      fontSize: 'var(--text-sm)',
                      borderWidth: '2px',
                      borderColor: 'rgba(96, 165, 250, 0.5)',
                      background: 'rgba(96, 165, 250, 0.12)',
                      alignItems: 'center',
                    }}
                  >
                    <AlertTriangle size={22} style={{ color: '#60a5fa' }} />
                    <span>
                      <strong>Filtered mode:</strong> with explicit prefixes the pipeline scans
                      only the subdomains you listed. <strong>Subdomain Discovery has been
                      automatically turned off</strong> and locked (Subfinder, Amass, crt.sh,
                      HackerTarget, Knockpy, puredns will not run). Clear the prefixes if you
                      want full enumeration.
                    </span>
                  </div>
                )}
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Include Root Domain</span>
                  <p className={styles.toggleDescription}>
                    Also scan the root domain (e.g., example.com without subdomain)
                    {forceIncludeRootDomain && (
                      <>
                        {' '}
                        <strong>Locked ON: Subdomain Discovery is disabled and no prefixes are set, so the root domain is the only valid target.</strong>
                      </>
                    )}
                  </p>
                </div>
                <Toggle
                  checked={includesRootDomain}
                  onChange={handleRootDomainToggle}
                  disabled={isLocked || forceIncludeRootDomain}
                />
              </div>

              {/* AI in Pipeline (master toggle, model picker, per-tool toggles) */}
              <div className={styles.subSection}>
                <div className={styles.toggleRow} style={{ gap: 'var(--space-4)', alignItems: 'center' }}>
                  <AiToggleLabel
                    label="Enable AI in Pipeline"
                    tooltip={
                      'Master switch that unlocks every per-tool AI toggle below. ' +
                      'When OFF, all per-tool AI flags are forced OFF and disabled, ' +
                      'no LLM calls are made by the recon pipeline. When ON, each ' +
                      'per-tool toggle becomes editable and individual AI hooks can ' +
                      'be turned on or off independently. Pick the model used by ' +
                      'every hook just below.'
                    }
                  />
                  <Toggle
                    checked={data.aiInPipeline}
                    onChange={(checked) => {
                      updateField('aiInPipeline', checked)
                      // When master flips, cascade to every per-tool flag so the
                      // form state matches the backend defense-in-depth contract.
                      updateField('ffufAiExtensions', checked)
                      updateField('nucleiAiTags', checked)
                      updateField('wafAiClassifier', checked)
                      updateField('nucleiAiResponseFilter', checked)
                      updateField('takeoverAiClassifier', checked)
                    }}
                  />
                </div>
                {data.aiInPipeline && (
                  <>
                    <div className={styles.fieldRow} style={{ marginTop: 'var(--space-3)' }}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>AI Model</label>
                        <ModelPicker
                          userId={userId}
                          value={data.aiPipelineModel}
                          onChange={(id) => updateField('aiPipelineModel', id)}
                        />
                        <span className={styles.fieldHint}>
                          Model used by every AI hook in recon. Independent of the
                          agent&apos;s own model selection. Pick a cheaper model here
                          if cost matters more than peak quality.
                        </span>
                      </div>
                    </div>

                    {/* Per-tool AI toggles. Each one mirrors the toggle in its tool
                        section, sharing the same form field, so flipping either
                        place updates both. The list lives inside a fixed-height
                        scroll container so adding more hooks doesn't push the
                        rest of the form down. Descriptions are rendered as
                        native title-attribute tooltips on the info icon to
                        keep each row compact. Add new entries to the
                        `aiPipelineHooks` array below as more tools gain AI
                        hooks -- no JSX changes needed. */}
                    {(() => {
                      const aiPipelineHooks: Array<{
                        field: 'ffufAiExtensions' | 'nucleiAiTags' | 'wafAiClassifier' | 'nucleiAiResponseFilter' | 'takeoverAiClassifier'
                        label: string
                        description: string
                      }> = [
                        {
                          field: 'ffufAiExtensions',
                          label: 'FFuf: Use AI for Extensions',
                          description: 'For each fuzz target, FFuf first sends a single HEAD request and asks the configured model to suggest the most likely file extensions based on the response headers (Server, X-Powered-By, X-AspNet-Version). The static FFuf extensions list in the FFuf module is ignored when this is on. Same toggle as in the FFuf module: flipping it here flips it there. A per-fingerprint cache means N hosts behind the same stack collapse to one LLM call.',
                        },
                        {
                          field: 'nucleiAiTags',
                          label: 'Nuclei: Use AI for Tag Selection',
                          description: 'Once per scan, Nuclei aggregates the detected tech stack from http_probe (Wappalyzer + Server headers) and asks the configured model to prune its include-tags list to ones matching the stack. Drops irrelevant tags like wordpress on Node sites, adds tech-specific ones like apache or wp-plugin when detected. The static Include Tags list in the Nuclei module is ignored when this is on. Same toggle as in the Nuclei module: flipping it here flips it there. Candidate tag pool is built from the live nuclei-templates volume (count >= 50, ~125 broad-category tags).',
                        },
                        {
                          field: 'wafAiClassifier',
                          label: 'Security Checks: Use AI for WAF Classification',
                          description: 'Augments the static WAF/CDN header-token check used by the Direct IP and WAF Bypass checks. When the static list misses (modern WAFs strip or rebrand their headers), the response gets a second pass through the configured model, which scores WAF presence 0-100 from headers, body fingerprints, cookies, and latency. Same toggle as in the Security Checks module: flipping it here flips it there. A per-response fingerprint cache collapses identical responses to one LLM call.',
                        },
                        {
                          field: 'nucleiAiResponseFilter',
                          label: 'Nuclei: Use AI to Filter False-Positive Block Pages',
                          description: "Augments the keyword-based WAF/rate-limit detection inside Nuclei's false-positive filter. When the static list misses (rebranded WAF blocks, AWS WAF JSON errors, custom Fortinet pages) but the response still looks like a block (suspicious status code on an injection finding), the LLM classifies the body as block-page or real hit. Suppresses fake findings and exposes real ones the keyword filter wrongly hides. Same toggle as in the Nuclei module: flipping it here flips it there. Per-response fingerprint cache keeps cost bounded.",
                        },
                        {
                          field: 'takeoverAiClassifier',
                          label: 'Takeover: Use AI to Disambiguate WAF "No-Host" Pages',
                          description: "Subjack/Nuclei takeover fingerprints can collide with WAF block pages that say \"not found\" for a hostname the WAF doesn't recognize. When AI is on, each takeover candidate is probed; if the response carries no third-party vendor token (Heroku-Request-Id, x-amz-bucket-region, etc.), the LLM classifies the body as a real unclaimed-service page or a WAF block. AI-flagged collisions get a -40 score penalty so they land in manual_review instead of being shipped as criticals. Same toggle as in the Subdomain Takeover module: flipping it here flips it there.",
                        },
                      ]
                      return (
                        <div
                          style={{
                            marginTop: 'var(--space-4)',
                            maxHeight: 240,
                            overflowY: 'auto',
                            border: '1px solid var(--border-subtle, #2a2a2a)',
                            borderRadius: 'var(--radius-2, 6px)',
                            padding: 'var(--space-2, 8px) var(--space-3, 12px)',
                            background: 'var(--surface-1, transparent)',
                          }}
                        >
                          {aiPipelineHooks.map((hook, idx) => (
                            <div
                              key={hook.field}
                              className={styles.toggleRow}
                              style={{
                                gap: 'var(--space-3)',
                                paddingTop: idx === 0 ? 0 : 'var(--space-2, 8px)',
                                paddingBottom: 'var(--space-2, 8px)',
                                borderTop: idx === 0 ? 'none' : '1px solid var(--border-subtle, #222)',
                                alignItems: 'center',
                              }}
                            >
                              <AiToggleLabel
                                label={hook.label}
                                tooltip={hook.description}
                              />
                              <Toggle
                                checked={data[hook.field]}
                                onChange={(checked) => updateField(hook.field, checked)}
                              />
                            </div>
                          ))}
                        </div>
                      )
                    })()}
                  </>
                )}
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Domain Verification</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Verify Domain Ownership</span>
                    <p className={styles.toggleDescription}>
                      Require DNS TXT record verification before scanning
                    </p>
                  </div>
                  <Toggle
                    checked={data.verifyDomainOwnership}
                    onChange={(checked) => updateField('verifyDomainOwnership', checked)}
                  />
                </div>

                {data.verifyDomainOwnership && (
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Ownership Token</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.ownershipToken}
                        onChange={(e) => updateField('ownershipToken', e.target.value)}
                      />
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>TXT Record Prefix</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.ownershipTxtPrefix}
                        onChange={(e) => updateField('ownershipTxtPrefix', e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Stealth Mode</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Stealth Mode</span>
                <p className={styles.toggleDescription}>
                  Force the entire pipeline to use only passive and low-noise techniques.
                  Active scanners (Kiterunner, banner grabbing) are disabled. Port scanning
                  switches to passive mode. Nuclei disables DAST and interactsh. The AI agent
                  uses only stealthy methods and will stop if stealth is impossible for a
                  requested action.
                </p>
              </div>
              <Toggle
                checked={data.stealthMode}
                onChange={(checked) => updateField('stealthMode', checked)}
              />
            </div>
          </div>

          {/* Target Guardrail */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Target Guardrail</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Target Guardrail</span>
                <p className={styles.toggleDescription}>
                  Block well-known public targets (major tech companies,
                  cloud providers, financial institutions, etc.) when saving the project.
                  Prevents accidental scanning of unauthorized domains.
                  Government, military, educational, and international organization domains
                  (.gov, .mil, .edu, .int) are always blocked regardless of this setting.
                </p>
              </div>
              <Toggle
                checked={data.targetGuardrailEnabled ?? true}
                onChange={(checked) => updateField('targetGuardrailEnabled', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
