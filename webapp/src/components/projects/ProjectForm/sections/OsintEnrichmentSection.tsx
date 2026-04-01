'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, ShieldCheck, Info } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface OsintEnrichmentSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

interface KeyStatus {
  censys: boolean
  fofa: boolean
  otx: boolean
  netlas: boolean
  virusTotal: boolean
  zoomEye: boolean
  criminalIp: boolean
}

export function OsintEnrichmentSection({ data, updateField }: OsintEnrichmentSectionProps) {
  const [isOpen, setIsOpen] = useState(false)
  const { userId } = useProject()
  const [keyStatus, setKeyStatus] = useState<KeyStatus | null>(null)

  const checkApiKeys = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) {
          setKeyStatus({
            censys:     !!(settings.censysApiToken && settings.censysOrgId),
            fofa:       !!settings.fofaApiKey,
            otx:        !!settings.otxApiKey,
            netlas:     !!settings.netlasApiKey,
            virusTotal: !!settings.virusTotalApiKey,
            zoomEye:    !!settings.zoomEyeApiKey,
            criminalIp: !!settings.criminalIpApiKey,
          })
        }
      })
      .catch(() => setKeyStatus({ censys: false, fofa: false, otx: false, netlas: false, virusTotal: false, zoomEye: false, criminalIp: false }))
  }, [userId])

  useEffect(() => { checkApiKeys() }, [checkApiKeys])

  const noKey = (tool: keyof KeyStatus) => !keyStatus || !keyStatus[tool]

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <ShieldCheck size={16} />
          OSINT &amp; Threat Intelligence Enrichment
          <NodeInfoTooltip section="OsintEnrichment" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Passive OSINT enrichment using external threat intelligence APIs. All tools run in
            parallel after domain discovery, without sending any traffic to your targets. Each tool
            requires an API key configured in Global Settings. Enable or disable each source
            independently per project.
          </p>

          {/* Censys */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Censys</span>
                <p className={styles.toggleDescription}>
                  Query Censys Search API v2 for host records: services, geolocation, ASN, and OS
                  metadata for discovered IPs. Requires API ID + Secret pair.
                </p>
                {noKey('censys') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Censys API credentials — add API Token &amp; Organization ID in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.censysEnabled}
                onChange={(checked) => updateField('censysEnabled', checked)}
                disabled={noKey('censys')}
              />
            </div>
          </div>

          {/* FOFA */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>FOFA</span>
                <p className={styles.toggleDescription}>
                  Query FOFA (Chinese internet intelligence) for hosts matching the target domain
                  or discovered IPs. Returns banners, ports, technologies, and TLS certificates.
                </p>
                {noKey('fofa') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No FOFA API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.fofaEnabled}
                onChange={(checked) => updateField('fofaEnabled', checked)}
                disabled={noKey('fofa')}
              />
            </div>
            {data.fofaEnabled && !noKey('fofa') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.fofaMaxResults}
                    onChange={(e) => updateField('fofaMaxResults', parseInt(e.target.value) || 1000)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum results to fetch from FOFA API (1–10 000)</span>
                </div>
              </div>
            )}
          </div>

          {/* AlienVault OTX */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>AlienVault OTX</span>
                <p className={styles.toggleDescription}>
                  Retrieve threat intelligence pulses, passive DNS records, and reputation data for
                  discovered IPs and the target domain from AlienVault OTX.
                  {noKey('otx') && <em> Works with limited public data without a key; add one in Global Settings for full pulse data.</em>}
                </p>
              </div>
              <Toggle
                checked={data.otxEnabled}
                onChange={(checked) => updateField('otxEnabled', checked)}
              />
            </div>
          </div>

          {/* Netlas */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Netlas</span>
                <p className={styles.toggleDescription}>
                  Query Netlas internet intelligence platform for host data, open ports, and
                  service banners on discovered IPs and the target domain.
                </p>
                {noKey('netlas') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Netlas API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.netlasEnabled}
                onChange={(checked) => updateField('netlasEnabled', checked)}
                disabled={noKey('netlas')}
              />
            </div>
          </div>

          {/* VirusTotal */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>VirusTotal</span>
                <p className={styles.toggleDescription}>
                  Fetch multi-engine reputation scores, malicious detection counts, and category
                  labels for the target domain and discovered IPs. Free tier: 4 req/min. Add an API key in Global Settings to enable.
                </p>
                {noKey('virusTotal') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No VirusTotal API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.virusTotalEnabled}
                onChange={(checked) => updateField('virusTotalEnabled', checked)}
                disabled={noKey('virusTotal')}
              />
            </div>
          </div>

          {/* ZoomEye */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>ZoomEye</span>
                <p className={styles.toggleDescription}>
                  Query ZoomEye cyberspace search engine for open ports, service banners, and
                  technologies associated with discovered IPs and the target domain.
                </p>
                {noKey('zoomEye') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No ZoomEye API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.zoomEyeEnabled}
                onChange={(checked) => updateField('zoomEyeEnabled', checked)}
                disabled={noKey('zoomEye')}
              />
            </div>
            {data.zoomEyeEnabled && !noKey('zoomEye') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zoomEyeMaxResults}
                    onChange={(e) => updateField('zoomEyeMaxResults', parseInt(e.target.value) || 1000)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum results to fetch from ZoomEye API (1–10 000)</span>
                </div>
              </div>
            )}
          </div>

          {/* Criminal IP */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Criminal IP</span>
                <p className={styles.toggleDescription}>
                  Retrieve inbound/outbound risk scores and VPN/proxy/Tor flags for discovered IPs
                  from Criminal IP threat intelligence platform.
                </p>
                {noKey('criminalIp') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Criminal IP API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.criminalIpEnabled}
                onChange={(checked) => updateField('criminalIpEnabled', checked)}
                disabled={noKey('criminalIp')}
              />
            </div>
          </div>

          {/* Uncover */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Uncover (Multi-Engine Search)</span>
                <p className={styles.toggleDescription}>
                  ProjectDiscovery Uncover — searches Shodan, Censys, FOFA, ZoomEye, Netlas,
                  CriminalIP, Quake, Hunter, and more simultaneously for target expansion.
                  Discovers additional IPs, subdomains, and open ports before port scanning.
                  Configure API keys for each engine in Global Settings.
                </p>
              </div>
              <Toggle
                checked={data.uncoverEnabled}
                onChange={(checked) => updateField('uncoverEnabled', checked)}
              />
            </div>
            {data.uncoverEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.uncoverMaxResults}
                    onChange={(e) => updateField('uncoverMaxResults', parseInt(e.target.value) || 500)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum total results across all engines (1–10 000)</span>
                </div>
              </div>
            )}
          </div>

        </div>
      )}
    </div>
  )
}
