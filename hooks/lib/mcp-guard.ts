// Pure helpers for the MCP tool-poisoning guard. Hardens tool descriptions
// (strip instruction-like text aimed at the agent, flag ambiguous phrasing)
// and extracts the
// server name an mcp__<server>__<tool> name was registered under.

const INSTRUCTION_PHRASES = [
  /\bignore (all|any|previous|prior) instructions?\b/i,
  /\balways (run|call|use|execute)\b/i,
  /\bnever tell the user\b/i,
  /\bdo not (mention|tell|inform|reveal) the user\b/i,
  /\bbefore (calling|using) any other tool\b/i,
  /\boverrides? (all|any|every) (other )?(rule|instruction|policy)/i,
]

// Common in legitimate usage notes ("You must pass the repo as
// owner/name."), so a match only flags the description for review; the
// sentence is kept.
const FLAG_ONLY_PHRASES = [/\byou must\b/i, /\bsystem prompt\b/i]

export interface DescribeResult {
  description: string
  flagged: boolean
  matchedPhrases: string[]
}

// Strips sentences containing instruction-like phrases rather than the
// whole description, so a legitimate tool whose description merely
// mentions one risky word in passing still reads sensibly. Flag-only
// phrases are reported in matchedPhrases but never removed. Phrases are
// matched on a copy with sentence punctuation removed and every whitespace run
// collapsed to one space, so a phrase split by a double space, a tab, a newline
// or a full stop is still found. A phrase that still matches once the kept
// sentences are joined (one split across a sentence boundary) withholds the
// whole description.
const WITHHELD = '[barmkin-mod: description withheld, it read as instructions to the agent]'

function flatten(text: string): string {
  return text.replace(/[.!?]/g, ' ').replace(/\s+/g, ' ')
}

export function neutralizeDescription(description: string): DescribeResult {
  const sentences = description.split(/(?<=[.!?])\s+/)
  const matched: string[] = []
  let stripped = false
  const kept = sentences.filter((sentence) => {
    const flat = flatten(sentence)
    if (INSTRUCTION_PHRASES.some((re) => re.test(flat))) {
      matched.push(sentence.trim())
      stripped = true
      return false
    }
    if (FLAG_ONLY_PHRASES.some((re) => re.test(flat))) matched.push(sentence.trim())
    return true
  })
  const body = kept.join(' ').trim()
  const crossesSentences = INSTRUCTION_PHRASES.some((re) => re.test(flatten(body)))
  if (crossesSentences) matched.push(description.trim())
  const flagged = matched.length > 0
  let description_ = description
  if (crossesSentences) description_ = WITHHELD
  else if (stripped) description_ = body || WITHHELD
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
