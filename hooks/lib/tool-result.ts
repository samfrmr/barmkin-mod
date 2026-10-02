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

// Withholds a tool result's content while keeping it in-schema for that
// tool. A plain-string result (WebFetch, WebSearch) or an MCP tool's result
// (string or content-block array both validate against its looser schema)
// collapses to `{ result: message }`, same as before. Read's result is a
// typed record (`{ file: { content, filePath, numLines, ... } }`) whose
// output schema requires that object shape, not a bare string, so denying a
// Read instead keeps the record and replaces only `file.content` -- this is
// the only shape this mod denies today that isn't string-or-array.
export function withholdResult(result: unknown, message: string): { result: unknown } {
  const value = result && typeof result === 'object' ? (result as { result?: unknown }).result : undefined
  if (value && typeof value === 'object' && !Array.isArray(value) && 'file' in value) {
    const file = (value as { file?: unknown }).file
    if (file && typeof file === 'object' && !Array.isArray(file)) {
      return {
        result: {
          ...value,
          file: { ...file, content: message, numLines: message.split('\n').length },
        },
      }
    }
  }
  return { result: message }
}
