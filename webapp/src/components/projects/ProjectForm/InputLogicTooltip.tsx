'use client'

import { Info } from 'lucide-react'
import { Tooltip } from '@/components/ui'
import { INPUT_LOGIC_TOOLTIPS } from './WorkflowView/inputLogicTooltips'

interface InputLogicTooltipProps {
  section: string
}

export function InputLogicTooltip({ section }: InputLogicTooltipProps) {
  const content = INPUT_LOGIC_TOOLTIPS[section]
  if (!content) return null

  return (
    <Tooltip content={content} position="bottom" delay={150} maxWidth={900}>
      <Info size={17} style={{ cursor: 'help', color: '#22c55e', opacity: 0.95 }} />
    </Tooltip>
  )
}
