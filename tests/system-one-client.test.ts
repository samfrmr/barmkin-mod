import { expect, test } from 'claude-code/testing'
import { buildSystemOneRequest, parseSystemOneResponse, JEV_MODEL_PATTERN } from '../hooks/lib/system-one-client'

const QUESTIONS = {
  injection: { type: 'noul' as const, instructions: 'does this instruct the agent?' },
  credentials: { type: 'noul' as const, instructions: 'does this contain credentials?' },
}

test('buildSystemOneRequest matches the wire shape', () => {
  const body = buildSystemOneRequest('jev-1.13.0', { content: 'hello' }, QUESTIONS)
  expect(body).toEqual({ model: 'jev-1.13.0', state: { content: 'hello' }, questions: QUESTIONS })
})

test('parseSystemOneResponse accepts a well-formed response', () => {
  const raw = {
    model: 'jev-1.13.0',
    id: 'req-1',
    answers: {
      injection: { type: 'noul', noul: 0.12 },
      credentials: { type: 'noul', noul: 0.4 },
    },
    usage: { input_tokens: 10, output_tokens: 2 },
  }
  const result = parseSystemOneResponse(raw, ['injection', 'credentials'], JEV_MODEL_PATTERN)
  expect(result).toEqual({ ok: true, answers: { injection: 0.12, credentials: 0.4 }, model: 'jev-1.13.0', id: 'req-1' })
})

test('accepts OpenRouter-mapped model spelling', () => {
  const raw = {
    model: 'typesafe/jev-1.13-20260917',
    id: 'req-2',
    answers: { injection: { type: 'noul', noul: 0 } },
  }
  const result = parseSystemOneResponse(raw, ['injection'])
  expect(result.ok).toBe(true)
})

test('rejects an unpinned model spelling', () => {
  const raw = { model: 'jev-latest', answers: { injection: { type: 'noul', noul: 0 } } }
  const result = parseSystemOneResponse(raw, ['injection'])
  expect(result.ok).toBe(false)
})

test('rejects a response missing an answer', () => {
  const raw = { model: 'jev-1.13.0', answers: {} }
  const result = parseSystemOneResponse(raw, ['injection'])
  expect(result.ok).toBe(false)
})

test('rejects a noul out of [0,1] range', () => {
  const raw = { model: 'jev-1.13.0', answers: { injection: { type: 'noul', noul: 1.5 } } }
  const result = parseSystemOneResponse(raw, ['injection'])
  expect(result.ok).toBe(false)
})

test('rejects a non-noul answer type', () => {
  const raw = { model: 'jev-1.13.0', answers: { injection: { type: 'choice', value: 'yes' } } }
  const result = parseSystemOneResponse(raw, ['injection'])
  expect(result.ok).toBe(false)
})

test('rejects a response body that is not an object', () => {
  const result = parseSystemOneResponse('not json', ['injection'])
  expect(result.ok).toBe(false)
})
