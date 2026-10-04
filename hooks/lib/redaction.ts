import type { RedactionRule } from './redaction-rules.js'
import { scrubInvisible } from './scrub'

export interface RedactionResult {
  text: string
  redactedCount: number
  categories: string[]
}

// Longest text the rules scan. A few generic-assignment value shapes backtrack
// roughly quadratically in their input: measured on the current rule set,
// 70 KB of repeated `SECRET=` takes about 0.9 s, so 16 KiB costs about 50 ms
// per such rule. The JWT rule is quadratic on `eyJ-` runs too: measured at
// about 76 ms per 16 KiB string at the cap (the worst input found). One
// redaction pass over a full string costs 46 ms + 76 ms = 122 ms, and
// redactInEitherView runs two passes per string. The worst tool result is five
// full strings (see MAX_RESULT_CHARS): 5 x 2 x 122 ms = 1220 ms of redaction,
// plus one 16 KiB screen pass of about 120 ms on the joined text, plus the Jev
// payload's two passes over the same 16 KiB (about 244 ms, when a classifier is
// configured): about 1584 ms in total, above the 1-second guard budget.
// Longer text is withheld as a whole rather than scanned.
const MAX_SCANNED_CHARS = 16 * 1024

export function exceedsScanLimit(text: string): boolean {
  return text.length > MAX_SCANNED_CHARS
}

// Total text one tool result may carry, counted over `result` and its context
// strings. The worst case is 64 KiB / 16 KiB = 4 strings at the per-string cap.
// The model-visible `text` mirror repeats the same content, so it is not added
// to the total, but it still gets the per-string cap, which makes a worst-case
// result five full strings. Each full string costs about 46 ms for the generic
// key rule and 76 ms for the JWT rule per redaction pass, and redactInEitherView
// runs two passes, so the redaction passes cost 5 x 2 x 122 ms = 1220 ms, plus
// one 120 ms screen pass and the Jev payload's 244 ms: about 1584 ms per tool
// result, above the 1-second guard budget. A Read image's
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

// Matches on the original text or its scrubbed view, so a zero-width character
// can neither hide a secret from the rules nor split one into a match.
export function containsSecretInEitherView(text: string, rules: RedactionRule[]): boolean {
  return containsAnySecret(text, rules) || containsAnySecret(scrubInvisible(text).text, rules)
}

// The second pass runs on the first pass's output. A placeholder can be longer
// than the match it replaces, so that output can pass the scan limit, and
// redactText would then collapse it into an oversized placeholder. Any text that
// grows past the limit is withheld with a stated reason instead, so it is never
// passed through and never replaced by a placeholder that reads as content.
export function redactInEitherView(
  text: string,
  rules: RedactionRule[],
  counters: Record<string, number>,
): { text: string; redactedCount: number } {
  const first = redactText(text, rules, counters)
  if (exceedsScanLimit(first.text)) {
    return { text: 'barmkin-mod: withheld, the redacted text exceeds the 16 KiB scan limit', redactedCount: first.redactedCount + 1 }
  }
  const second = redactText(scrubInvisible(first.text).text, rules, counters)
  return { text: second.text, redactedCount: first.redactedCount + second.redactedCount }
}

export function containsAnySecret(text: string, rules: RedactionRule[]): boolean {
  if (exceedsScanLimit(text)) return false
  return rules.some((rule) => {
    rule.pattern.lastIndex = 0
    return rule.pattern.test(text)
  })
}
