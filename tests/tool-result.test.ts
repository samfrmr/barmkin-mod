import { expect, test } from 'claude-code/testing'
import { extractResultText, appendContext, withholdResult } from '../hooks/lib/tool-result'

test('extractResultText reads a plain string result', () => {
  expect(extractResultText({ result: 'hello' })).toBe('hello')
})

test('extractResultText joins an MCP content-block array', () => {
  const result = { result: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] }
  expect(extractResultText(result)).toBe('a\nb')
})

test('extractResultText stringifies a typed record like Read\'s { file }', () => {
  const result = { result: { type: 'text', file: { filePath: '/tmp/x', content: 'secret', numLines: 1 } } }
  expect(extractResultText(result)).toContain('secret')
})

test('appendContext adds to an empty context array without touching result', () => {
  const result: { result: unknown; context?: unknown } = { result: { file: { content: 'x' } } }
  const out = appendContext(result, 'warning')
  expect(out.context).toEqual(['warning'])
  expect(out.result).toEqual({ file: { content: 'x' } })
})

test('appendContext appends to an existing context array', () => {
  const result = { result: 'ok', context: ['first'] }
  const out = appendContext(result, 'second')
  expect(out.context).toEqual(['first', 'second'])
})

test('withholdResult collapses a plain-string result to { result: message }', () => {
  const out = withholdResult({ result: 'fetched page body' }, 'withheld')
  expect(out).toEqual({ result: 'withheld' })
})

test('withholdResult collapses an MCP content-block array result to { result: message }', () => {
  const out = withholdResult({ result: [{ type: 'text', text: 'leaked' }] }, 'withheld')
  expect(out).toEqual({ result: 'withheld' })
})

test('withholdResult preserves Read\'s { file } shape, replacing only file.content', () => {
  const result = { result: { type: 'text', file: { filePath: '/etc/passwd', content: 'root:x:0:0', numLines: 1 } } }
  const out = withholdResult(result, 'withheld message')
  expect(out).toEqual({
    result: { type: 'text', file: { filePath: '/etc/passwd', content: 'withheld message', numLines: 1 } },
  })
})

test('withholdResult recomputes numLines from the withhold message', () => {
  const result = { result: { file: { filePath: '/etc/passwd', content: 'line1\nline2\nline3', numLines: 3 } } }
  const out = withholdResult(result, 'one line only') as { result: { file: { numLines: number } } }
  expect(out.result.file.numLines).toBe(1)
})

test('withholdResult never leaks the original file content', () => {
  const result = { result: { file: { filePath: '/etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash' } } }
  const out = withholdResult(result, 'withheld')
  expect(JSON.stringify(out)).not.toContain('root:x:0:0')
})

test('withholdResult falls back to { result: message } for a result with no nested object', () => {
  expect(withholdResult(null, 'withheld')).toEqual({ result: 'withheld' })
  expect(withholdResult(undefined, 'withheld')).toEqual({ result: 'withheld' })
})
