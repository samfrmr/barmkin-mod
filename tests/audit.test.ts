import { expect, test } from 'claude-code/testing'
import { appendAndTrim, auditLogPath, recordAudit, createSerialQueue, type AuditEntry, type AuditStore } from '../hooks/lib/audit'

const sampleEntry: AuditEntry = { ts: 1700000000000, session: 'abc123', event: 'screen', tool: 'fetch:WebFetch', decision: 'escalate', reason: 'scored 0.60 on the injection question' }

const LOG = '/home/u/.claude/barmkin-mod-audit-sess.jsonl'
const screen = { event: 'screen', tool: 'fetch:WebFetch', decision: 'pass', reason: 'scored 0.10' }

function fakeStore(options: { home?: string; initial?: Record<string, string>; readError?: string } = {}) {
  const files = new Map(Object.entries(options.initial ?? {}))
  const state = { home: options.home ?? '/home/u' }
  const store: AuditStore = {
    home: async () => state.home,
    session: async () => 'sess',
    read: async (path) => {
      if (options.readError) throw new Error(options.readError)
      if (!files.has(path)) throw new Error('no such file')
      return files.get(path) as string
    },
    missing: async (path) => !files.has(path),
    write: async (path, text) => {
      files.set(path, text)
    },
  }
  return { store, files, state }
}

function rowsOf(text: string | undefined): string[] {
  return (text ?? '').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line).reason)
}

test('appends a new row to an empty log', () => {
  const result = appendAndTrim('', sampleEntry, 100)
  const lines = result.trim().split('\n')
  expect(lines.length).toBe(1)
  expect(JSON.parse(lines[0])).toEqual(sampleEntry)
})

test('appends a new row after existing rows', () => {
  const existing = JSON.stringify({ ...sampleEntry, event: 'first' }) + '\n'
  const result = appendAndTrim(existing, { ...sampleEntry, event: 'second' }, 100)
  const lines = result.trim().split('\n')
  expect(lines.length).toBe(2)
  expect(JSON.parse(lines[0]).event).toBe('first')
  expect(JSON.parse(lines[1]).event).toBe('second')
})

test('trims to the last maxLines rows, keeping the newest', () => {
  let log = ''
  for (let i = 0; i < 5; i++) {
    log = appendAndTrim(log, { ...sampleEntry, event: 'e' + i }, 3)
  }
  const lines = log.trim().split('\n').map((l) => JSON.parse(l).event)
  expect(lines).toEqual(['e2', 'e3', 'e4'])
})

test('drops an unparseable existing line rather than corrupting the file', () => {
  const corrupted = 'not valid json\n' + JSON.stringify({ ...sampleEntry, event: 'ok' }) + '\n'
  const result = appendAndTrim(corrupted, { ...sampleEntry, event: 'new' }, 100)
  const lines = result.trim().split('\n').map((l) => JSON.parse(l).event)
  expect(lines).toEqual(['ok', 'new'])
})

test('concurrent sessions write to distinct audit files', () => {
  const a = auditLogPath('/home/u', '1f0c2b9e-aaaa-4bbb-8ccc-000000000001')
  const b = auditLogPath('/home/u', '1f0c2b9e-aaaa-4bbb-8ccc-000000000002')
  expect(a).toBe('/home/u/.claude/barmkin-mod-audit-1f0c2b9e-aaaa-4bbb-8ccc-000000000001.jsonl')
  expect(a).not.toBe(b)
})

test('a session id can never name a path outside ~/.claude', () => {
  expect(auditLogPath('/home/u', '../../etc/passwd')).toBe('/home/u/.claude/barmkin-mod-audit-______etc_passwd.jsonl')
  expect(auditLogPath('/home/u', '')).toBe('/home/u/.claude/barmkin-mod-audit-unknown.jsonl')
})

test('overlapping recordings on the production write path all land in the log', async () => {
  const { store, files } = fakeStore()
  await Promise.all(['first', 'second', 'third'].map((reason) => recordAudit(store, { ...screen, reason })))
  expect(rowsOf(files.get(LOG))).toEqual(['first', 'second', 'third'])
})

test('a transient read error on an existing log leaves its rows in place', async () => {
  const existing = JSON.stringify({ ...sampleEntry, reason: 'earlier' }) + '\n'
  const { store, files } = fakeStore({ initial: { [LOG]: existing }, readError: 'EIO: input/output error' })
  await recordAudit(store, { ...screen, reason: 'later' })
  expect(files.get(LOG)).toBe(existing)
})

test('the first row creates a missing log whatever the read error says', async () => {
  const { store, files } = fakeStore({ readError: 'ENOTFOUND: resource is gone' })
  await recordAudit(store, screen)
  expect(rowsOf(files.get(LOG))).toEqual([screen.reason])
})

test('a failed home lookup writes nothing, and a later successful one writes', async () => {
  const { store, files, state } = fakeStore({ home: '' })
  await recordAudit(store, screen)
  expect(files.size).toBe(0)
  state.home = '/home/u'
  await recordAudit(store, screen)
  expect(rowsOf(files.get(LOG))).toEqual([screen.reason])
})

test('a failing task does not stop later queued tasks', async () => {
  const enqueue = createSerialQueue()
  const ran: string[] = []
  void enqueue(async () => {
    throw new Error('disk full')
  })
  await enqueue(async () => {
    ran.push('after')
  })
  expect(ran).toEqual(['after'])
})
