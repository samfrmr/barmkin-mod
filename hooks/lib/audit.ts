// Pure helpers for the durable audit log (R12): formats one row and bounds
// the file's growth. No `$` use here; register.ts does the actual
// $.fs.read/write.

export interface AuditEntry {
  ts: number
  session: string
  event: string
  tool: string
  decision: string
  // A short category/question/rule name, counts included -- never a secret
  // value or raw untrusted content. Every caller in register.ts passes
  // through text that was already safe for this reason (a classifier
  // verdict's `reason`, a fixed guard message), never tool input/output.
  reason: string
}

export function formatAuditLine(entry: AuditEntry): string {
  return JSON.stringify(entry) + '\n'
}

// Keeps the audit log from growing without bound on a long-lived install:
// parses existing JSONL text, keeps at most the last `maxLines` rows (plus
// the just-appended one), and re-serializes. A line that fails to parse
// (truncated by a prior crash mid-write, hand-edited) is dropped rather
// than kept or allowed to break the parse of every line after it.
export function appendAndTrim(existingJsonl: string, entry: AuditEntry, maxLines: number): string {
  const lines = existingJsonl.split('\n').filter((line) => line.trim().length > 0)
  const kept = lines.filter((line) => {
    try {
      JSON.parse(line)
      return true
    } catch {
      return false
    }
  })
  kept.push(JSON.stringify(entry))
  const trimmed = kept.length > maxLines ? kept.slice(kept.length - maxLines) : kept
  return trimmed.join('\n') + '\n'
}

// Runs queued tasks strictly one after another, so overlapping audit writes
// (each a read-modify-write of the whole file) can't clobber each other. A
// task that throws or rejects doesn't break the chain for the next one.
export function createSerialQueue(): (task: () => Promise<void>) => Promise<void> {
  let tail: Promise<void> = Promise.resolve()
  return (task) => {
    tail = tail.then(task).catch(() => {})
    return tail
  }
}
