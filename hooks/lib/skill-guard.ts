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

// An entry starts only at a line that is itself `- <name>: `. Any other line
// is a continuation of the entry above it, so a description split across
// lines is neutralised as one piece.
const ENTRY_START = /\n(?=- [^\n]*?: )/

// Runs the MCP description neutraliser over the name and the description of
// every skill listing entry. Any other chunk (the header) is neutralised as a
// whole, so instruction text cannot hide outside the expected shape. Sentences
// are stripped the same way tool descriptions are, so a clean listing comes
// back byte-identical.
export function neutralizeSkillListing(text: string): string {
  return text
    .split(ENTRY_START)
    .map((entry) => {
      const match = LISTING_ENTRY.exec(entry)
      if (!match) return neutralizeDescription(entry).description
      const name = neutralizeDescription(match[1]).description
      const description = neutralizeDescription(match[2]).description
      return '- ' + name + ': ' + description
    })
    .join('\n')
}
