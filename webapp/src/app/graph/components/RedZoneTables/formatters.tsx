'use client'

import type { ReactNode } from 'react'
import { ExternalLink } from '@/components/ui'
import {
  capecToUrl,
  cveToUrl,
  cweToUrl,
  emailToMailto,
  githubSlugToUrl,
  hostPortToUrl,
  hostToUrl,
  ipToUrl,
  isGithubSlug,
  resolveLinkable,
} from '@/lib/url-utils'
import type { Severity } from './types'
import styles from './RedZoneTableRow.module.css'

const SEV_CLASS: Record<Severity, string> = {
  critical: styles.sevCritical,
  high: styles.sevHigh,
  medium: styles.sevMedium,
  low: styles.sevLow,
  info: styles.sevInfo,
  unknown: styles.sevInfo,
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${styles.sevBadge} ${SEV_CLASS[severity] || styles.sevInfo}`}>{severity}</span>
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className={styles.mono}>{children}</code>
}

export function Truncated({ text, max = 280 }: { text: string | null | undefined; max?: number }) {
  if (!text) return <span className={styles.nullCell}>-</span>
  return (
    <span className={styles.truncate} style={{ maxWidth: max }} title={text}>
      {text}
    </span>
  )
}

export function UrlCell({ url, max = 260 }: { url: string | null | undefined; max?: number }) {
  if (!url) return <span className={styles.nullCell}>-</span>
  return (
    <span className={styles.truncate} style={{ maxWidth: max }} title={url}>
      <ExternalLink href={url}>{url}</ExternalLink>
    </span>
  )
}

export function NumCell({ value, zero = '-' }: { value: number | null | undefined; zero?: string }) {
  if (value == null || value === 0) return <span className={styles.nullCell}>{zero}</span>
  return <span className={styles.numCell}>{value}</span>
}

export function CvssCell({ score }: { score: number | null | undefined }) {
  if (score == null) return <span className={styles.nullCell}>-</span>
  let cls = styles.cvssLow
  if (score >= 9) cls = styles.cvssCritical
  else if (score >= 7) cls = styles.cvssHigh
  else if (score >= 4) cls = styles.cvssMedium
  return <span className={`${styles.cvssBadge} ${cls}`}>{score.toFixed(1)}</span>
}

export function BoolChip({ value, trueLabel = 'yes', falseLabel = 'no' }: { value: boolean | null | undefined; trueLabel?: string; falseLabel?: string }) {
  if (value === null || value === undefined) return <span className={styles.nullCell}>-</span>
  return (
    <span className={value ? styles.boolTrue : styles.boolFalse}>
      {value ? trueLabel : falseLabel}
    </span>
  )
}

export function KevChip({ value }: { value: boolean | null | undefined }) {
  if (!value) return <span className={styles.nullCell}>-</span>
  return <span className={styles.kevChip}>KEV</span>
}

export function ListCell({ items, max = 3 }: { items: string[] | null | undefined; max?: number }) {
  if (!items || items.length === 0) return <span className={styles.nullCell}>-</span>
  const shown = items.slice(0, max)
  const extra = items.length - shown.length
  return (
    <span className={styles.listCell}>
      {shown.map((it, i) => {
        const href = resolveLinkable(it)
        return (
          <span key={i} className={styles.listChip}>
            {href ? <ExternalLink href={href}>{it}</ExternalLink> : it}
          </span>
        )
      })}
      {extra > 0 && <span className={styles.listMore}>+{extra}</span>}
    </span>
  )
}

/**
 * Renders an IP address as a clickable link. The optional `port` is used
 * only to build the link target (so http:// vs https:// is chosen correctly);
 * it is not appended to the displayed text. Pass `showPort` if the cell is
 * meant to display the IP:port combo together.
 */
export function IpCell({
  ip,
  port,
  showPort = false,
}: {
  ip: string | null | undefined
  port?: number | null
  showPort?: boolean
}) {
  if (!ip) return <span className={styles.nullCell}>-</span>
  const href = port ? ipToUrl(ip, port) : ipToUrl(ip)
  const label = showPort && port ? `${ip}:${port}` : ip
  return (
    <code className={styles.mono}>
      <ExternalLink href={href}>{label}</ExternalLink>
    </code>
  )
}

export function HostCell({ host }: { host: string | null | undefined }) {
  if (!host) return <span className={styles.nullCell}>-</span>
  return (
    <code className={styles.mono}>
      <ExternalLink href={hostToUrl(host)}>{host}</ExternalLink>
    </code>
  )
}

export function HostPortCell({ host, port }: { host: string | null | undefined; port: number | null | undefined }) {
  if (!host) return <span className={styles.nullCell}>-</span>
  if (!port) {
    return (
      <code className={styles.mono}>
        <ExternalLink href={hostToUrl(host)}>{host}</ExternalLink>
      </code>
    )
  }
  return (
    <code className={styles.mono}>
      <ExternalLink href={hostPortToUrl(host, port)}>{`${host}:${port}`}</ExternalLink>
    </code>
  )
}

export function EmailCell({ email }: { email: string | null | undefined }) {
  if (!email) return <span className={styles.nullCell}>-</span>
  return <ExternalLink href={emailToMailto(email)}>{email}</ExternalLink>
}

export function CveLink({ id }: { id: string | null | undefined }) {
  if (!id) return <span className={styles.nullCell}>-</span>
  return <ExternalLink href={cveToUrl(id)}>{id}</ExternalLink>
}

export function CweLink({ id }: { id: string | null | undefined }) {
  if (!id) return <span className={styles.nullCell}>-</span>
  return <ExternalLink href={cweToUrl(id)}>{id}</ExternalLink>
}

export function CapecLink({ id }: { id: string | null | undefined }) {
  if (!id) return <span className={styles.nullCell}>-</span>
  return <ExternalLink href={capecToUrl(id)}>{id}</ExternalLink>
}

export function GithubSlugCell({ slug }: { slug: string | null | undefined }) {
  if (!slug) return <span className={styles.nullCell}>-</span>
  if (!isGithubSlug(slug)) return <code className={styles.mono}>{slug}</code>
  return (
    <code className={styles.mono}>
      <ExternalLink href={githubSlugToUrl(slug)}>{slug}</ExternalLink>
    </code>
  )
}

type LinkedListKind = 'auto' | 'cve' | 'cwe' | 'capec' | 'ip' | 'host' | 'email' | 'github'

function urlForKind(item: string, kind: LinkedListKind): string | null {
  switch (kind) {
    case 'cve': return cveToUrl(item)
    case 'cwe': return cweToUrl(item)
    case 'capec': return capecToUrl(item)
    case 'ip': return ipToUrl(item)
    case 'host': return hostToUrl(item)
    case 'email': return emailToMailto(item)
    case 'github': return isGithubSlug(item) ? githubSlugToUrl(item) : null
    case 'auto':
    default:
      return resolveLinkable(item)
  }
}

export function LinkedListCell({
  items,
  max = 3,
  kind = 'auto',
}: {
  items: string[] | null | undefined
  max?: number
  kind?: LinkedListKind
}) {
  if (!items || items.length === 0) return <span className={styles.nullCell}>-</span>
  const shown = items.slice(0, max)
  const extra = items.length - shown.length
  return (
    <span className={styles.listCell}>
      {shown.map((it, i) => {
        const href = urlForKind(it, kind)
        return (
          <span key={i} className={styles.listChip}>
            {href ? <ExternalLink href={href}>{it}</ExternalLink> : it}
          </span>
        )
      })}
      {extra > 0 && <span className={styles.listMore}>+{extra}</span>}
    </span>
  )
}

export function filterRowsByText<T extends object>(rows: T[], search: string): T[] {
  if (!search) return rows
  const s = search.toLowerCase()
  return rows.filter(r => {
    for (const v of Object.values(r as Record<string, unknown>)) {
      if (v == null) continue
      if (Array.isArray(v)) {
        for (const sv of v) {
          if (sv != null && String(sv).toLowerCase().includes(s)) return true
        }
      } else if (typeof v === 'object') {
        for (const sv of Object.values(v as Record<string, unknown>)) {
          if (sv != null && String(sv).toLowerCase().includes(s)) return true
        }
      } else if (String(v).toLowerCase().includes(s)) {
        return true
      }
    }
    return false
  })
}
