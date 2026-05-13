'use client'

import type { MouseEvent } from 'react'
import { BookOpen } from 'lucide-react'
import { getWikiUrl } from './wiki-links'
import styles from './WikiInfoButton.module.css'

interface WikiInfoButtonProps {
  /** Wiki key (PAGE_WIKI / TOOL_WIKI / SECTION_WIKI) or a fully-qualified https URL. */
  target: string
  /** Optional label rendered next to the icon. */
  label?: string
  /** Override the tooltip; defaults to "View wiki documentation". */
  title?: string
  /** Icon size (px). */
  size?: number
  /** Extra class names. */
  className?: string
  /** Stop click propagation so collapsible section headers don't toggle. */
  stopPropagation?: boolean
}

export function WikiInfoButton({
  target,
  label,
  title = 'View wiki documentation',
  size = 13,
  className,
  stopPropagation = true,
}: WikiInfoButtonProps) {
  const href = target.startsWith('http') ? target : getWikiUrl(target)
  if (!href) return null

  const handleClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (stopPropagation) e.stopPropagation()
  }

  const cls = [styles.button, !label ? styles.iconOnly : '', className]
    .filter(Boolean)
    .join(' ')

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={cls}
      title={title}
      aria-label={title}
      onClick={handleClick}
    >
      <BookOpen size={size} />
      {label && <span className={styles.label}>{label}</span>}
    </a>
  )
}
