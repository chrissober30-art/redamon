import { Fragment, type ReactNode } from 'react'
import { ExternalLink } from '@/components/ui'
import { resolveLinkable } from '@/lib/url-utils'
import { formatPropertyValue } from './formatters'

function linkify(item: unknown): ReactNode {
  const text = formatPropertyValue(item)
  const href = resolveLinkable(text)
  if (href) return <ExternalLink href={href}>{text}</ExternalLink>
  return text
}

export function renderPropertyValue(value: unknown): ReactNode {
  if (Array.isArray(value) && value.length > 0) {
    return value.map((item, i) => (
      <Fragment key={i}>
        {i > 0 && ', '}
        {linkify(item)}
      </Fragment>
    ))
  }

  return linkify(value)
}
