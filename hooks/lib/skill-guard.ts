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

// A listing line is `- <name>: <description>`. A name can itself hold a colon
// (plugin skills are `plugin:skill`), so the split is on the first colon that
// is followed by a space, which a name's own colon never is.
const LISTING_LINE = /^(- .+?): (.*)$/

// Runs the MCP description neutraliser over every line of a skill listing.
// A skill's description is the part after `name: `; any other line (the
// header, a continuation line) is neutralised as a whole, so instruction text
// cannot hide outside the expected shape. Sentences are stripped the same way
// tool descriptions are, so a clean listing comes back byte-identical.
export function neutralizeSkillListing(text: string): { text: string; flagged: boolean } {
  let flagged = false
  const lines = text.split('\n').map((line) => {
    const match = LISTING_LINE.exec(line)
    const description = match ? match[2] : line
    const result = neutralizeDescription(description)
    if (result.flagged) flagged = true
    if (result.description === description) return line
    return match ? match[1] + ': ' + result.description : result.description
  })
  return { text: lines.join('\n'), flagged }
}
