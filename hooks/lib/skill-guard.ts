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

// Sentence punctuation and any whitespace run become single spaces, so a phrase
// is matched between its words whatever separates them.
function flatten(text: string): string {
  return text.replace(/[.!?]/g, ' ').replace(/\s+/g, ' ')
}

// Neutralises one description on its own, sentence by sentence, with the shared
// matcher. A sentence that holds an instruction-like phrase is removed. The kept
// sentences are checked again as one text, so a phrase that spans the sentences
// of this description withholds the description. Nothing is checked across
// entries.
function neutralizeEntry(description: string): string {
  const sentences = description.split(/(?<=[.!?])\s+/)
  const kept = sentences.filter((sentence) => {
    const flat = flatten(sentence)
    return neutralizeDescription(flat).description === flat
  })
  const body = flatten(kept.join(' '))
  const residual = neutralizeDescription(body).description
  if (residual !== body) return residual
  if (kept.length === sentences.length) return description
  return kept.join(' ').trim() || neutralizeDescription(flatten(description)).description
}

// Neutralises a skill listing. A name is never rewritten: an entry whose name
// holds an instruction-like phrase is not listed, and the number of such entries
// is returned. Each remaining description is neutralised on its own. A clean
// listing comes back byte-identical.
export function neutralizeSkillListing(text: string): { text: string; withheld: number } {
  const pieces: string[] = []
  let withheld = 0
  for (const chunk of text.split(ENTRY_START)) {
    const match = LISTING_ENTRY.exec(chunk)
    if (!match) {
      const bullet = chunk.startsWith('- ') ? '- ' : ''
      pieces.push(bullet + neutralizeEntry(chunk.slice(bullet.length)))
      continue
    }
    const [, name, description] = match
    const flatName = flatten(name)
    if (neutralizeDescription(flatName).description !== flatName) {
      withheld++
      continue
    }
    pieces.push('- ' + name + ': ' + neutralizeEntry(description))
  }
  return { text: pieces.join('\n'), withheld }
}
