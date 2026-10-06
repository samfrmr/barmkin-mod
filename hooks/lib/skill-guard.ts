// Pure helpers for the skill-content guards. No `$` use here: register.ts
// makes the screen, redaction and taint calls and uses these for the text it
// hands back.

import { neutralizeDescription } from './mcp-guard'

// The text that replaces a skill body the screen denied, or that could not be
// checked. The event's `skill` name stays unchanged (the dispatcher rejects a
// changed name), so only the body is replaced.
export function skillBodyWithheldText(reason: string): string {
  return "barmkin-mod: withheld this skill's body (" + reason + '). Ask the user before retrying.'
}

// The replacement for a whole skill listing the neutraliser could not check.
export function skillListingWithheldText(reason: string): string {
  return 'barmkin-mod: withheld the skill listing (' + reason + '). Ask the user before retrying.'
}

// A listing entry is `- <name>: <description>`. A name can itself hold a colon
// (plugin skills are `plugin:skill`), so the split is on the first colon that
// is followed by a space, which a name's own colon never is.
const LISTING_ENTRY = /^- (.+?): ([\s\S]*)$/

// Every line that begins with a bullet starts a new chunk. Any other line is a
// continuation of the chunk above it.
const ENTRY_START = /\n(?=- )/

// Neutralises a skill listing. A name is never rewritten: an entry whose name
// holds an instruction-like phrase is dropped, and the count of dropped entries
// is returned. Each description is neutralised like an MCP tool description. The
// descriptions are then checked again as one text, so a phrase that spans two
// entries is caught too; when one is found, the whole listing is withheld. A
// clean listing comes back byte-identical.
export function neutralizeSkillListing(text: string): { text: string; withheld: number } {
  const chunks = text.split(ENTRY_START)
  const pieces: string[] = []
  const bodies: string[] = []
  let withheld = 0
  for (const chunk of chunks) {
    const match = LISTING_ENTRY.exec(chunk)
    if (match) {
      const [, name, description] = match
      if (neutralizeDescription(name).description !== name) {
        withheld++
        continue
      }
      const neutralized = neutralizeDescription(description).description
      pieces.push('- ' + name + ': ' + neutralized)
      bodies.push(neutralized)
      continue
    }
    const bullet = chunk.startsWith('- ') ? '- ' : ''
    const body = neutralizeDescription(chunk.slice(bullet.length)).description
    pieces.push(bullet + body)
    bodies.push(body)
  }
  const joined = bodies.join(' ')
  if (neutralizeDescription(joined).description !== joined) {
    return {
      text: skillListingWithheldText('an instruction-like phrase runs across listing entries'),
      withheld: chunks.filter((chunk) => chunk.startsWith('- ')).length,
    }
  }
  return { text: pieces.join('\n'), withheld }
}
