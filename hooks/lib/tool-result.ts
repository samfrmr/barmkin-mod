// Pure helpers for reading and annotating a tool.call result. Tool results
// vary by tool: usually a string, sometimes a structured content-block
// array (MCP tools in particular). This extracts the best-effort text
// without assuming one shape. The full text is returned so the local
// screens see everything Claude will; only the classifier payload is capped.

export function extractResultText(result: unknown): string {
  if (result === null || result === undefined) return ''
  const r = result as { result?: unknown }
  const value = 'result' in (result as object) ? r.result : result
  if (typeof value === 'string') return value
  if (Array.isArray(value)) {
    const text = value
      .map((block) => (block && typeof block === 'object' && typeof (block as { text?: unknown }).text === 'string' ? (block as { text: string }).text : ''))
      .filter(Boolean)
      .join('\n')
    if (text) return text
  }
  if (typeof value === 'object' && value !== null) {
    try {
      return JSON.stringify(value)
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
