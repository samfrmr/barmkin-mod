import { expect, test } from 'claude-code/testing'
import { formatAuditLine, appendAndTrim, createSerialQueue, type AuditEntry } from '../hooks/lib/audit'

const sampleEntry: AuditEntry = { ts: 1700000000000, session: 'abc123', event: 'screen', tool: 'fetch:WebFetch', decision: 'escalate', reason: 'scored 0.60 on the injection question' }

test('formats one row as a single JSON line', () => {
  const line = formatAuditLine(sampleEntry)
  expect(line.endsWith('\n')).toBe(true)
  expect(JSON.parse(line.trim())).toEqual(sampleEntry)
})

test('appends a new row to an empty log', () => {
  const result = appendAndTrim('', sampleEntry, 100)
  const lines = result.trim().split('\n')
  expect(lines.length).toBe(1)
  expect(JSON.parse(lines[0])).toEqual(sampleEntry)
})

test('appends a new row after existing rows', () => {
  const existing = formatAuditLine({ ...sampleEntry, event: 'first' })
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
  const corrupted = 'not valid json\n' + formatAuditLine({ ...sampleEntry, event: 'ok' })
  const result = appendAndTrim(corrupted, { ...sampleEntry, event: 'new' }, 100)
  const lines = result.trim().split('\n').map((l) => JSON.parse(l).event)
  expect(lines).toEqual(['ok', 'new'])
})

test('never includes a secret value field: only categories/counts belong in reason', () => {
  const entry: AuditEntry = { ts: 1, session: 's', event: 'screen', tool: 'read:/etc/passwd', decision: 'escalate', reason: 'scored 0.70 on the credentials question' }
  const line = formatAuditLine(entry)
  expect(line).not.toContain('AKIA')
  expect(line).not.toContain('sk-')
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

test('unserialized overlapping read-modify-write appends lose a row', async () => {
  let file = ''
  const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0))
  const append = async (event: string) => {
    const existing = file
    await tick()
    file = appendAndTrim(existing, { ...sampleEntry, event }, 100)
  }
  await Promise.all([append('first'), append('second')])
  expect(file.trim().split('\n').length).toBe(1)
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
