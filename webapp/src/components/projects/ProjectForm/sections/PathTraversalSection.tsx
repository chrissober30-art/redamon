'use client'

import type { Project } from '@prisma/client'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface PathTraversalSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const ROW_STYLE: React.CSSProperties = {
  marginBottom: 'var(--space-4)',
}

const GROUP_HEADER_STYLE: React.CSSProperties = {
  fontSize: 'var(--text-sm)',
  fontWeight: 'var(--font-semibold)',
  color: 'var(--text-primary)',
  marginTop: 'var(--space-5)',
  marginBottom: 'var(--space-3)',
  paddingBottom: 'var(--space-2)',
  borderBottom: '1px solid var(--border-subtle, var(--border-default))',
}

const FIRST_GROUP_HEADER_STYLE: React.CSSProperties = {
  ...GROUP_HEADER_STYLE,
  marginTop: 'var(--space-3)',
}

const CHECKBOX_LABEL_STYLE: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 'var(--space-2)',
}

export function PathTraversalSection({ data, updateField }: PathTraversalSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 8, right: 16 }}>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills" title="Open Agent Skills wiki page" />
      </div>
      <p className={styles.sectionDescription} style={{ marginBottom: 'var(--space-4)' }}>
        Configure which Path Traversal / LFI / RFI sub-workflows to inject into the agent
        prompt and tune probe parameters. Disable sub-sections you don&apos;t want for this engagement.
      </p>

      {/* === Sub-workflow toggles === */}
      <h3 style={FIRST_GROUP_HEADER_STYLE}>Sub-workflow injection</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.pathTraversalOobCallbackEnabled ?? true}
              onChange={(e) => updateField('pathTraversalOobCallbackEnabled', e.target.checked)}
            />
            OOB callback workflow (interactsh)
          </label>
          <span className={styles.fieldHint}>
            Adds the RFI / blind-LFI sub-prompt. Sends DNS and HTTP probes to the configured OOB provider.
            Disable when external callbacks are forbidden.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.pathTraversalPhpWrappersEnabled ?? true}
              onChange={(e) => updateField('pathTraversalPhpWrappersEnabled', e.target.checked)}
            />
            PHP wrappers + log poisoning sub-section
          </label>
          <span className={styles.fieldHint}>
            Adds php://filter, data://, expect://, zip:// payloads and the log-poisoning chain.
            Disable for non-PHP targets to reduce prompt bloat.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.pathTraversalArchiveExtractionEnabled ?? false}
              onChange={(e) => updateField('pathTraversalArchiveExtractionEnabled', e.target.checked)}
            />
            Archive extraction (Zip Slip) write tests
          </label>
          <span className={styles.fieldHint}>
            Allows the agent to upload crafted ZIP / TAR archives whose entries escape the destination
            directory. WRITES files to the target filesystem -- enable only with explicit RoE permission.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.pathTraversalPayloadReferenceEnabled ?? true}
              onChange={(e) => updateField('pathTraversalPayloadReferenceEnabled', e.target.checked)}
            />
            Bypass + encoding payload reference table
          </label>
          <span className={styles.fieldHint}>
            Injects the encoding / dot-trick / wrapper / parser-mismatch payload reference and the
            real-world precedents table (~3 KB extra). Disable for a leaner prompt.
          </span>
        </div>
      </div>

      {/* === Probe parameters === */}
      <h3 style={GROUP_HEADER_STYLE}>Probe parameters</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Request Timeout (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={data.pathTraversalRequestTimeout ?? 10}
            onChange={(e) => updateField('pathTraversalRequestTimeout', parseInt(e.target.value) || 10)}
            min={1}
            max={120}
          />
          <span className={styles.fieldHint}>
            curl --max-time / --connect-timeout for each traversal probe. Lower values speed up
            fuzzing loops but may miss slow file-read sinks.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>OOB Provider</label>
          <input
            type="text"
            className="textInput"
            value={data.pathTraversalOobProvider ?? 'oast.fun'}
            onChange={(e) => updateField('pathTraversalOobProvider', e.target.value)}
            placeholder="oast.fun"
          />
          <span className={styles.fieldHint}>
            interactsh-client server. Use a self-hosted instance if oast.fun is blocked. Only used
            when the OOB callback workflow is enabled.
          </span>
        </div>
      </div>
    </div>
  )
}
