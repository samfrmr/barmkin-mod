// Pure helpers for the MCP tool-poisoning guard. Hardens tool descriptions
// (strip instruction-like text aimed at the agent) and extracts the
// server name an mcp__<server>__<tool> name was registered under.

const INSTRUCTION_PHRASES = [
  /\bignore (all|any|previous|prior) instructions?\b/i,
  /\byou must\b/i,
  /\balways (run|call|use|execute)\b/i,
  /\bnever tell the user\b/i,
  /\bdo not (mention|tell|inform|reveal) the user\b/i,
  /\bbefore (calling|using) any other tool\b/i,
  /\bsystem prompt\b/i,
  /\boverrides? (all|any|every) (other )?(rule|instruction|policy)/i,
]

export interface DescribeResult {
  description: string
  flagged: boolean
  matchedPhrases: string[]
}

// Strips sentences containing instruction-like phrases rather than the
// whole description, so a legitimate tool whose description merely
// mentions one risky word in passing still reads sensibly.
export function neutralizeDescription(description: string): DescribeResult {
  const sentences = description.split(/(?<=[.!?])\s+/)
  const matched: string[] = []
  const kept = sentences.filter((sentence) => {
    const hit = INSTRUCTION_PHRASES.find((re) => re.test(sentence))
    if (hit) {
      matched.push(sentence.trim())
      return false
    }
    return true
  })
  const flagged = matched.length > 0
  const description_ = flagged
    ? kept.join(' ').trim() || '[barmkin-mod: description withheld, it read as instructions to the agent]'
    : description
  return { description: description_, flagged, matchedPhrases: matched }
}

// mcp__<server>__<tool> is the fixed shape Claude Code registers MCP tools
// under. This reads the server name as everything between the leading
// `mcp__` and the next `__`, which is unambiguous as long as the server
// name itself contains no `__` (kebab-case names, the documented
// convention, never do).
export function parseMcpServerName(toolName: string): string | null {
  if (!toolName.startsWith('mcp__')) return null
  const rest = toolName.slice('mcp__'.length)
  const idx = rest.indexOf('__')
  if (idx === -1) return null
  return rest.slice(0, idx)
}

export function isAllowedServer(serverName: string, allowlist: string[]): boolean {
  if (allowlist.length === 0) return true
  return allowlist.includes(serverName)
}
