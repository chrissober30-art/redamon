'use client'

import type { Project } from '@prisma/client'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RceSectionProps {
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

export function RceSection({ data, updateField }: RceSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 8, right: 16 }}>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills" title="Open Agent Skills wiki page" />
      </div>
      <p className={styles.sectionDescription} style={{ marginBottom: 'var(--space-4)' }}>
        Configure how the agent tests for RCE / command injection. Disable sub-workflows you don&apos;t want
        injected into the prompt and gate destructive payloads behind the explicit aggressive toggle.
      </p>

      <h3 style={FIRST_GROUP_HEADER_STYLE}>Sub-workflow injection</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.rceOobCallbackEnabled ?? true}
              onChange={(e) => updateField('rceOobCallbackEnabled', e.target.checked)}
            />
            OOB callback workflow (interactsh)
          </label>
          <span className={styles.fieldHint}>
            Adds the blind-RCE / OOB sub-prompt. The agent registers an oast.fun domain and uses DNS or HTTP
            callbacks as a quiet oracle for command execution. Disable when external OOB providers are off-limits.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.rceDeserializationEnabled ?? true}
              onChange={(e) => updateField('rceDeserializationEnabled', e.target.checked)}
            />
            Deserialization gadget workflow (ysoserial)
          </label>
          <span className={styles.fieldHint}>
            Adds the Java / PHP / Python / Ruby / .NET deserialization sub-prompt with ysoserial gadget-chain
            guidance (URLDNS, CommonsCollections, Spring, etc.). Disable when the target stack does not deserialize
            untrusted input or when you want a leaner prompt.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.rceAggressivePayloads ?? false}
              onChange={(e) => updateField('rceAggressivePayloads', e.target.checked)}
            />
            Aggressive payloads (file write, web shells, container escape)
          </label>
          <span className={styles.fieldHint}>
            <strong>Default OFF.</strong> When enabled, Step 7 of the workflow permits file writes outside /tmp,
            persistent web shells / cron / systemd hooks, reverse-shell handlers, and container / Kubernetes escape
            probes. Leave OFF for read-only proofs (id, whoami, /etc/passwd) which already produce a Level 3 finding.
            Only enable for engagements where critical-impact (Level 4) demonstration is explicitly authorised.
          </span>
        </div>
      </div>
    </div>
  )
}
