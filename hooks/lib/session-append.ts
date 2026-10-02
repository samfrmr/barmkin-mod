// Pure helpers for the session.append redaction/scrub backstop (R12). No `$`
// use here; register.ts's hook calls these to decide whether to rewrite a
// row before it is stored.
import type { RedactionRule } from './redaction-rules'
import { redactText } from './redaction'
import { scrubInvisible } from './scrub'

export interface BlockResult {
  block: unknown
  changed: boolean
  hiddenCount: number
}

// Rewrites a text block's `text`, or a tool_result block's `content` (a
// string, or recursively its own nested blocks). Every other block kind
// (thinking, tool_use, image, document, an unknown kind) is left untouched
// on purpose: per Claude Code's own session.append docs, "media blocks may
// be dropped or moved, not changed or added; thinking, tool_use, unknown
// kinds and every tool_result's tool_use_id are put back" regardless of what
// a hook returns for them, so rewriting them here would be silently
// discarded by the engine.
export function scrubAndRedactBlock(
  block: unknown,
  rules: RedactionRule[],
  counters: Record<string, number>,
): BlockResult {
  if (!block || typeof block !== 'object') return { block, changed: false, hiddenCount: 0 }
  const b = block as Record<string, unknown>

  if (b.type === 'text' && typeof b.text === 'string') {
    const scrubbed = scrubInvisible(b.text)
    const { text: redacted, redactedCount } = redactText(scrubbed.text, rules, counters)
    if (redactedCount === 0 && scrubbed.strippedCount === 0) return { block, changed: false, hiddenCount: 0 }
    return { block: { ...b, text: redacted }, changed: true, hiddenCount: scrubbed.hiddenCount }
  }

  if (b.type === 'tool_result') {
    if (typeof b.content === 'string') {
      const scrubbed = scrubInvisible(b.content)
      const { text: redacted, redactedCount } = redactText(scrubbed.text, rules, counters)
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return { block, changed: false, hiddenCount: 0 }
      return { block: { ...b, content: redacted }, changed: true, hiddenCount: scrubbed.hiddenCount }
    }
    if (Array.isArray(b.content)) {
      let changed = false
      let hiddenCount = 0
      const content = b.content.map((inner) => {
        const res = scrubAndRedactBlock(inner, rules, counters)
        if (res.changed) changed = true
        hiddenCount += res.hiddenCount
        return res.block
      })
      return changed ? { block: { ...b, content }, changed: true, hiddenCount } : { block, changed: false, hiddenCount: 0 }
    }
  }

  return { block, changed: false, hiddenCount: 0 }
}

export function scrubAndRedactContent(
  content: unknown[],
  rules: RedactionRule[],
  counters: Record<string, number>,
): { content: unknown[]; changed: boolean; hiddenCount: number } {
  let changed = false
  let hiddenCount = 0
  const result = content.map((block) => {
    const res = scrubAndRedactBlock(block, rules, counters)
    if (res.changed) changed = true
    hiddenCount += res.hiddenCount
    return res.block
  })
  return { content: result, changed, hiddenCount }
}
