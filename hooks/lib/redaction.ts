import type { RedactionRule } from './redaction-rules.js'

export interface RedactionResult {
  text: string
  redactedCount: number
  categories: string[]
}

// Longest text the rules scan. A few generic-assignment value shapes backtrack
// roughly quadratically in their input: measured on the current rule set,
// 70 KB of repeated `SECRET=` takes about 0.9 s, so 16 KiB costs about 50 ms
// per such rule. The JWT rule is quadratic on `eyJ-` runs too: measured at
// about 76 ms per 16 KiB string at the cap (the worst input found), so a
// result of four full strings costs about 4 x (46 ms generic + 76 ms JWT) =
// 490 ms, plus one 16 KiB screen pass of about 120 ms on the joined text, about
// 610 ms in total, inside the 1-second guard budget. Longer text is withheld as
// a whole rather than scanned.
const MAX_SCANNED_CHARS = 16 * 1024

export function exceedsScanLimit(text: string): boolean {
  return text.length > MAX_SCANNED_CHARS
}

// Total text one tool result may carry. The worst case is a result of
// strings that each sit at the per-string cap: 64 KiB / 16 KiB = 4 strings,
// each about 46 ms per quadratic rule (the value-side generic-key rule is the
// only quadratic one measured), so 4 x 46 ms = about 185 ms per tool result,
// under the 1-second guard budget. That computed bound is the accepted design.
// The model-visible `text` mirror of a result repeats the same content, so it is
// not added to the total; it still gets the per-string cap. A Read image's
// base64 payload is one of the strings: it survives only while it fits the
// per-string cap, roughly 12 KiB of image. Larger images are withheld with the
// stated reason. That is the accepted limitation: image reads above that size
// are unavailable.
const MAX_RESULT_CHARS = 64 * 1024

function textTotals(value: unknown): { total: number; longest: number } {
  if (typeof value === 'string') return { total: value.length, longest: value.length }
  const children = Array.isArray(value) ? value : value && typeof value === 'object' ? Object.values(value) : []
  return children.reduce(
    (acc: { total: number; longest: number }, child) => {
      const sub = textTotals(child)
      return { total: acc.total + sub.total, longest: Math.max(acc.longest, sub.longest) }
    },
    { total: 0, longest: 0 },
  )
}

export function exceedsResultBudget(result: unknown): boolean {
  const { total, longest } = textTotals(result)
  const rendered = typeof (result as { text?: unknown } | null)?.text === 'string' ? (result as { text: string }).text.length : 0
  return total - rendered > MAX_RESULT_CHARS || longest > MAX_SCANNED_CHARS
}

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
  if (exceedsScanLimit(text)) {
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
  if (exceedsScanLimit(text)) return false
  return rules.some((rule) => {
    rule.pattern.lastIndex = 0
    return rule.pattern.test(text)
  })
}
