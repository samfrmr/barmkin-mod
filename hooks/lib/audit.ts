// Durable audit log (R12): names each session's file, bounds its rows, and
// writes rows one at a time through one serial queue. The host is reached
// only through the plain AuditStore functions register.ts supplies, so this
// module never receives the mods API object itself.

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

export interface AuditStore {
  home(): Promise<string>
  session(): Promise<string>
  read(path: string): Promise<string>
  missing(path: string): Promise<boolean>
  write(path: string, text: string): Promise<void>
}

// Each session gets its own file, so two Claude Code sessions running at
// once never read-modify-write the same file (which would drop a row; the
// in-process serial queue below can't see another process's writes). The
// session id is reduced to a safe filename so it can never name a path
// outside ~/.claude.
export function auditLogPath(home: string, session: string): string {
  const safe = session.replace(/[^A-Za-z0-9_-]/g, '_') || 'unknown'
  return home + '/.claude/barmkin-mod-audit-' + safe + '.jsonl'
}

const MAX_AUDIT_LINES = 2000

// Keeps one session's audit file from growing without bound: parses existing
// JSONL text, keeps at most the last `maxLines` rows (plus the just-appended
// one), and re-serializes. A line that fails to parse (truncated by a prior
// crash mid-write, hand-edited) is dropped rather than kept or allowed to
// break the parse of every line after it.
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

const enqueueAuditRow = createSerialQueue()

export function recordAudit(store: AuditStore, entry: Omit<AuditEntry, 'ts' | 'session'>): Promise<void> {
  const row = { ts: Date.now(), ...entry }
  return enqueueAuditRow(() => writeAuditRow(store, row))
}

async function writeAuditRow(store: AuditStore, row: Omit<AuditEntry, 'session'>): Promise<void> {
  const home = await store.home()
  if (!home) return
  const session = await store.session()
  const path = auditLogPath(home, session)
  let existing = ''
  try {
    existing = await store.read(path)
  } catch {
    if (!(await store.missing(path))) return
  }
  await store.write(path, appendAndTrim(existing, { ...row, session }, MAX_AUDIT_LINES))
}
