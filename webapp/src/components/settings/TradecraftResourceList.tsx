'use client'

import { Pencil, Trash2, RotateCw, ExternalLink, Loader2, AlertTriangle, BookOpen } from 'lucide-react'
import styles from './Settings.module.css'
import type { TradecraftResource } from './TradecraftResourceForm'

interface CrawlStats {
  pages_fetched?: number
  llm_calls?: number
  elapsed_sec?: number
}

interface TradecraftResourceFull extends TradecraftResource {
  crawlStoppedBecause?: string
  crawlStats?: CrawlStats
  sitemap?: { nav?: unknown[]; tree?: unknown[]; pages?: unknown[]; links?: unknown[] }
}

function relTime(iso?: string | null): string {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  if (!isFinite(t)) return iso
  const diff = Date.now() - t
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}

function entriesCount(s?: TradecraftResourceFull['sitemap']): number {
  if (!s) return 0
  return (s.nav?.length || 0) + (s.tree?.length || 0) + (s.pages?.length || 0) + (s.links?.length || 0)
}

export function TradecraftResourceList({
  resources,
  loading,
  refreshingId,
  onEdit,
  onDelete,
  onRefresh,
  onToggleEnabled,
}: {
  resources: TradecraftResourceFull[]
  loading: boolean
  refreshingId: string | null
  onEdit: (r: TradecraftResourceFull) => void
  onDelete: (r: TradecraftResourceFull) => void
  onRefresh: (r: TradecraftResourceFull) => void
  onToggleEnabled: (r: TradecraftResourceFull, next: boolean) => void
}) {
  if (loading) {
    return (
      <div className={styles.emptyState}>
        <Loader2 size={16} className={styles.spin} /> Loading...
      </div>
    )
  }
  if (!resources.length) {
    return (
      <div className={styles.emptyState}>
        No tradecraft resources configured. Click <strong>Add Resource</strong> to wire up a curated knowledge URL the agent can consult during exploitation.
      </div>
    )
  }
  return (
    <div className={styles.providerList}>
      {resources.map(r => {
        const eCount = entriesCount(r.sitemap)
        const stats = r.crawlStats || {}
        // A resource is "verifying" when it has no lastVerifiedAt yet (just
        // created) OR is currently being refreshed. We surface this with a
        // spinner badge and grayed body so the user sees that fetch + sitemap
        // build + summary are still running in the background.
        const isVerifying = !r.lastVerifiedAt || refreshingId === r.id
        return (
          <div
            key={r.id}
            className={styles.providerCard}
            style={{
              opacity: r.enabled === false ? 0.55 : (isVerifying ? 0.75 : 1),
              position: 'relative',
            }}
          >
            <div className={styles.providerIcon}><BookOpen size={18} /></div>
            <div className={styles.providerInfo} style={{ minWidth: 0 }}>
              <div className={styles.providerName} style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span>{r.name}</span>
                {isVerifying ? (
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: '4px',
                    fontSize: '11px', color: 'var(--text-secondary)',
                    padding: '1px 8px', border: '1px solid var(--border)',
                    borderRadius: '10px', background: 'var(--bg-secondary, transparent)',
                  }}>
                    <Loader2 size={11} className={styles.spin} />
                    {refreshingId === r.id ? 'refreshing…' : 'verifying…'}
                  </span>
                ) : (
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)', padding: '1px 6px', border: '1px solid var(--border)', borderRadius: '10px' }}>{r.resourceType || '?'}</span>
                )}
                {r.lastError && !isVerifying && (
                  <span title={r.lastError} style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', color: 'var(--text-secondary)', fontSize: '11px' }}>
                    <AlertTriangle size={12} /> error
                  </span>
                )}
              </div>
              <div className={styles.providerMeta}>
                <a href={r.url} target="_blank" rel="noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                  {r.url} <ExternalLink size={11} />
                </a>
                <span> • {eCount} entries • verified {relTime(r.lastVerifiedAt)}</span>
              </div>
              {r.summary && (
                <details style={{ marginTop: '4px' }}>
                  <summary style={{ cursor: 'pointer', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {r.summary.slice(0, 200)}{r.summary.length > 200 ? '...' : ''}
                  </summary>
                  <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
                    {r.summary}
                  </div>
                </details>
              )}
              {r.resourceType === 'agentic-crawl' && (r.crawlStoppedBecause || stats.pages_fetched) && (
                <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Crawled {stats.pages_fetched ?? '?'} pages in {stats.elapsed_sec ?? '?'}s, stopped: {r.crawlStoppedBecause || '?'}
                </div>
              )}
              {r.lastError && (
                <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--danger, #c33)' }}>
                  {r.lastError}
                </div>
              )}
            </div>
            <div className={styles.providerActions}>
              <label className={styles.checkboxLabel} style={{ marginRight: '8px' }} title="Enabled">
                <input
                  type="checkbox"
                  checked={r.enabled !== false}
                  onChange={e => onToggleEnabled(r, e.target.checked)}
                />
              </label>
              <button
                className="secondaryButton"
                style={{ padding: '4px 8px' }}
                onClick={() => onRefresh(r)}
                disabled={refreshingId === r.id}
                title="Re-fetch and rebuild the sitemap + summary"
              >
                {refreshingId === r.id ? <Loader2 size={12} className={styles.spin} /> : <RotateCw size={12} />}
              </button>
              <button
                className="secondaryButton"
                style={{ padding: '4px 8px' }}
                onClick={() => onEdit(r)}
                title="Edit"
              >
                <Pencil size={12} />
              </button>
              <button
                className="secondaryButton"
                style={{ padding: '4px 8px' }}
                onClick={() => onDelete(r)}
                title="Delete"
              >
                <Trash2 size={12} />
              </button>
            </div>
          </div>
        )
      })}
    </div>
  )
}
