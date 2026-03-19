'use client'

import { useState } from 'react'
import { ChevronDown, Code } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { SECTION_NODE_MAP } from '../nodeMapping'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface JsluiceSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function JsluiceSection({ data, updateField }: JsluiceSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Code size={16} />
          jsluice JS Analyzer
          <NodeInfoTooltip nodes={SECTION_NODE_MAP.Jsluice} />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.jsluiceEnabled}
              onChange={(checked) => updateField('jsluiceEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Static analysis of JavaScript files using jsluice from Bishop Fox. Extracts hidden API endpoints, paths, query parameters, and secrets (AWS keys, API tokens) from JS source code discovered by Katana and Hakrawler. No additional traffic to the target beyond fetching JS files.
          </p>

          {data.jsluiceEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max JS Files</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceMaxFiles}
                    onChange={(e) => updateField('jsluiceMaxFiles', parseInt(e.target.value) || 100)}
                    min={1}
                    max={1000}
                  />
                  <span className={styles.fieldHint}>Maximum number of .js files to download and analyze</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceTimeout}
                    onChange={(e) => updateField('jsluiceTimeout', parseInt(e.target.value) || 300)}
                    min={30}
                  />
                  <span className={styles.fieldHint}>Overall analysis timeout</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Concurrency</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceConcurrency}
                    onChange={(e) => updateField('jsluiceConcurrency', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Files processed concurrently by jsluice</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Extraction Modes</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Extract URLs</span>
                    <p className={styles.toggleDescription}>Find API endpoints, paths, and parameters in fetch(), XMLHttpRequest, jQuery.ajax, and string literals</p>
                  </div>
                  <Toggle
                    checked={data.jsluiceExtractUrls}
                    onChange={(checked) => updateField('jsluiceExtractUrls', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Extract Secrets</span>
                    <p className={styles.toggleDescription}>Detect AWS keys, GCP credentials, GitHub tokens, and other embedded secrets with context</p>
                  </div>
                  <Toggle
                    checked={data.jsluiceExtractSecrets}
                    onChange={(checked) => updateField('jsluiceExtractSecrets', checked)}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
