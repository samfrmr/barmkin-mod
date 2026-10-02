import type { RedactionRule } from './redaction-rules.js'

export interface RedactionResult {
  text: string
  redactedCount: number
  categories: string[]
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

export function containsRedactionPlaceholder(text: string): boolean {
  return /\[REDACTED:[a-z0-9-]+#\d+\]/.test(text)
}

// Rules carry the "g" flag for redactText's replace loop, which makes
// RegExp.prototype.test stateful (it advances lastIndex across calls on
// the same object). Reset it before each test so this can be called
// repeatedly without alternating false negatives.
export function containsAnySecret(text: string, rules: RedactionRule[]): boolean {
  return rules.some((rule) => {
    rule.pattern.lastIndex = 0
    return rule.pattern.test(text)
  })
}
