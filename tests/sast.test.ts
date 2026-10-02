import { expect, test } from 'claude-code/testing'
import { parseSemgrepJson, worstSeverity, formatFindingsContext, buildSemgrepCandidates } from '../hooks/lib/sast'

const SAMPLE_SEMGREP_JSON = JSON.stringify({
  results: [
    {
      check_id: 'python.lang.security.audit.sql-injection',
      path: 'db.py',
      start: { line: 42 },
      extra: { severity: 'ERROR', message: 'Possible SQL injection' },
    },
    {
      check_id: 'javascript.lang.best-practice.console-log',
      path: 'app.js',
      start: { line: 7 },
      extra: { severity: 'INFO', message: 'console.log left in' },
    },
  ],
})

test('parses a semgrep --json result list', () => {
  const findings = parseSemgrepJson(SAMPLE_SEMGREP_JSON)
  expect(findings.length).toBe(2)
  expect(findings[0]).toEqual({
    ruleId: 'python.lang.security.audit.sql-injection',
    severity: 'ERROR',
    message: 'Possible SQL injection',
    path: 'db.py',
    line: 42,
  })
})

test('returns an empty list for malformed JSON instead of throwing', () => {
  expect(parseSemgrepJson('not json')).toEqual([])
})

test('returns an empty list when results is missing', () => {
  expect(parseSemgrepJson(JSON.stringify({}))).toEqual([])
})

test('worstSeverity ranks ERROR above WARNING above INFO', () => {
  const findings = parseSemgrepJson(SAMPLE_SEMGREP_JSON)
  expect(worstSeverity(findings)).toBe('ERROR')
  expect(worstSeverity([])).toBe(null)
})

test('formatFindingsContext includes every finding', () => {
  const findings = parseSemgrepJson(SAMPLE_SEMGREP_JSON)
  const context = formatFindingsContext(findings)
  expect(context).toContain('db.py:42')
  expect(context).toContain('app.js:7')
  expect(context).toContain('2 issue(s)')
})

test('formatFindingsContext is empty for no findings', () => {
  expect(formatFindingsContext([])).toBe('')
})

test('buildSemgrepCandidates tries the home-relative pipx/pip --user location first', () => {
  const candidates = buildSemgrepCandidates('/home/alice')
  expect(candidates[0]).toBe('/home/alice/.local/bin/semgrep')
  expect(candidates[candidates.length - 1]).toBe('semgrep')
})

test('buildSemgrepCandidates strips a trailing slash from the home dir', () => {
  expect(buildSemgrepCandidates('/home/alice/')[0]).toBe('/home/alice/.local/bin/semgrep')
})

test('buildSemgrepCandidates skips the home-relative candidate when home is unknown', () => {
  const candidates = buildSemgrepCandidates('')
  expect(candidates).not.toContain('/.local/bin/semgrep')
  expect(candidates[0]).toBe('/usr/local/bin/semgrep')
})

test('buildSemgrepCandidates always ends with bare semgrep as the last resort', () => {
  expect(buildSemgrepCandidates('/home/alice').at(-1)).toBe('semgrep')
  expect(buildSemgrepCandidates('').at(-1)).toBe('semgrep')
})
