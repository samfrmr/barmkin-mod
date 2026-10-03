import type { RedactionRule } from './redaction-rules.js'

export interface RedactionResult {
  text: string
  redactedCount: number
  categories: string[]
}

// Longest text the rules scan. A few generic-assignment value shapes backtrack
// roughly quadratically in their input: measured on the current rule set,
// 70 KB of repeated `SECRET=` takes about 0.9 s, so 16 KiB costs about 50 ms
// per such rule. That keeps the full set comfortably inside the 1-second
// guard budget. Longer text is withheld as a whole rather than scanned.
const MAX_SCANNED_CHARS = 16 * 1024

// Replaces every secret match with a placeholder token, numbered per
// category. No reversible map is kept anywhere: once a value is replaced,
// the original text is gone from this function's output, and the caller
// must not log the input. `counters` is caller-owned so a whole tool
// result (which may run several rules) gets consistent numbering, and so
// a caller can keep counting across multiple calls in the same turn.
export function redactText(
  text: string,
  rules: RedactionRule[],
  counters: Record<string, number> = {},
): RedactionResult {
  if (text.length > MAX_SCANNED_CHARS) {
    counters.oversized = (counters.oversized ?? 0) + 1
    return { text: `[REDACTED:oversized#${counters.oversized}]`, redactedCount: 1, categories: ['oversized'] }
  }
  let result = text
  let redactedCount = 0
  const categoriesHit = new Set<string>()

  for (const rule of rules) {
    result = result.replace(rule.pattern, () => {
      counters[rule.category] = (counters[rule.category] ?? 0) + 1
      redactedCount++
      categoriesHit.add(rule.category)
      return `[REDACTED:${rule.category}#${counters[rule.category]}]`
    })
  }

  return { text: result, redactedCount, categories: [...categoriesHit] }
}

// Rules carry the "g" flag for redactText's replace loop, which makes
// RegExp.prototype.test stateful (it advances lastIndex across calls on
// the same object). Reset it before each test so this can be called
// repeatedly without alternating false negatives.
export function containsAnySecret(text: string, rules: RedactionRule[]): boolean {
  if (text.length > MAX_SCANNED_CHARS) return true
  return rules.some((rule) => {
    rule.pattern.lastIndex = 0
    return rule.pattern.test(text)
  })
}
