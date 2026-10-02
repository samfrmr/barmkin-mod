// Pure helpers for reading and annotating a tool.call result. Tool results
// vary by tool: usually a string, sometimes a structured content-block
// array (MCP tools in particular). This extracts the best-effort text
// without assuming one shape, and caps length so a huge fetch doesn't blow
// the classifier call or the context we add.
const MAX_SCREEN_CHARS = 8000

export function extractResultText(result: unknown): string {
  if (result === null || result === undefined) return ''
  const r = result as { result?: unknown }
  const value = 'result' in (result as object) ? r.result : result
  if (typeof value === 'string') return value.slice(0, MAX_SCREEN_CHARS)
  if (Array.isArray(value)) {
    const text = value
      .map((block) => (block && typeof block === 'object' && typeof (block as { text?: unknown }).text === 'string' ? (block as { text: string }).text : ''))
      .filter(Boolean)
      .join('\n')
    if (text) return text.slice(0, MAX_SCREEN_CHARS)
  }
  if (typeof value === 'object' && value !== null) {
    try {
      return JSON.stringify(value).slice(0, MAX_SCREEN_CHARS)
    } catch {
      return ''
    }
  }
  return ''
}

export function appendContext<T extends { context?: unknown }>(result: T, text: string): T & { context: unknown[] } {
  const existing = Array.isArray(result?.context) ? result.context : []
  return { ...result, context: [...existing, text] }
}
