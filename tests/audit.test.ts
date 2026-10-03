import { expect, test } from 'claude-code/testing'
import { appendAndTrim, auditLogPath, staleAuditFiles, createSerialQueue, type AuditEntry } from '../hooks/lib/audit'

const sampleEntry: AuditEntry = { ts: 1700000000000, session: 'abc123', event: 'screen', tool: 'fetch:WebFetch', decision: 'escalate', reason: 'scored 0.60 on the injection question' }

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

test('keeps only the newest per-session audit files', () => {
  const listing = ['barmkin-mod-audit-c.jsonl', 'barmkin-mod-audit-b.jsonl', 'barmkin-mod-audit-a.jsonl', '']
  expect(staleAuditFiles(listing, 2)).toEqual(['barmkin-mod-audit-a.jsonl'])
  expect(staleAuditFiles(listing, 5)).toEqual([])
})

test('never selects a file that is not one of this mod\'s audit files', () => {
  const listing = ['barmkin-mod-audit-new.jsonl', 'settings.json', 'barmkin-mod-audit-../x.jsonl', 'projects', 'barmkin-mod-audit-old.jsonl']
  expect(staleAuditFiles(listing, 1)).toEqual(['barmkin-mod-audit-old.jsonl'])
})

test('serialized overlapping read-modify-write appends keep every row', async () => {
  let file = ''
  const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0))
  const append = (event: string) => async () => {
    const existing = file
    await tick()
    file = appendAndTrim(existing, { ...sampleEntry, event }, 100)
  }
  const enqueue = createSerialQueue()
  await Promise.all([enqueue(append('first')), enqueue(append('second'))])
  expect(file.trim().split('\n').map((line) => JSON.parse(line).event)).toEqual(['first', 'second'])
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
