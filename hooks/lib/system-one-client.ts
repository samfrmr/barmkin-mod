// Pure wire-format helpers for Jev's "System One" protocol, reused from
// barmkin's jev.go: POST {base_url}/v1/systemone with {model, state,
// questions}; every access path (TypeSafe direct, OpenRouter, Vercel AI
// Gateway) serves the same shape. This file holds no `$` use and no
// network call: register.ts calls $.http.fetch itself and passes the raw
// response through parseSystemOneResponse.
//
// Deliberately NOT barmkin's internal gateway (captain's intent): base_url
// is always operator config pointing at an OpenRouter/Vercel-style
// fallback endpoint. Jev must never be the component that permits -- this
// client only answers Noul (probability-of-yes) questions; composition
// into a decision happens in taint.ts, and it only ever tightens.

export interface NoulQuestion {
  type: 'noul'
  instructions: string
}

export interface SystemOneRequestBody {
  model: string
  state: Record<string, string>
  questions: Record<string, NoulQuestion>
}

export function buildSystemOneRequest(
  model: string,
  state: Record<string, string>,
  questions: Record<string, NoulQuestion>,
): SystemOneRequestBody {
  return { model, state, questions }
}

export const JEV_MODEL_PATTERN = /jev-1\.13\b/

export type SystemOneParseResult =
  | { ok: true; answers: Record<string, number>; model: string; id: string }
  | { ok: false; reason: string }

// Strictly validates a System One response the way jev.go's ask() does: an
// HTTP 200 body is not yet an answer. Any shape deviation is a parse
// failure, never a best-effort partial result, so a malformed or
// adversarial response degrades through "unavailable" rather than being
// half-trusted.
export function parseSystemOneResponse(
  raw: unknown,
  questionIds: string[],
  modelPattern: RegExp = JEV_MODEL_PATTERN,
): SystemOneParseResult {
  if (typeof raw !== 'object' || raw === null) {
    return { ok: false, reason: 'response body is not an object' }
  }
  const body = raw as Record<string, unknown>
  const model = body.model
  if (typeof model !== 'string' || !modelPattern.test(model)) {
    return { ok: false, reason: `unexpected model spelling ${JSON.stringify(model)}` }
  }
  const answers = body.answers
  if (typeof answers !== 'object' || answers === null) {
    return { ok: false, reason: 'answers is not an object' }
  }
  const answersObj = answers as Record<string, unknown>
  if (Object.keys(answersObj).length !== questionIds.length) {
    return {
      ok: false,
      reason: `got ${Object.keys(answersObj).length} answers, want ${questionIds.length}`,
    }
  }
  const out: Record<string, number> = {}
  for (const id of questionIds) {
    const ans = answersObj[id] as { type?: unknown; noul?: unknown } | undefined
    if (!ans || typeof ans !== 'object') {
      return { ok: false, reason: `missing answer ${JSON.stringify(id)}` }
    }
    if (ans.type !== 'noul' || typeof ans.noul !== 'number') {
      return { ok: false, reason: `answer ${JSON.stringify(id)}: not a valid noul` }
    }
    const p = ans.noul
    if (!Number.isFinite(p) || p < 0 || p > 1) {
      return { ok: false, reason: `answer ${JSON.stringify(id)}: noul ${p} out of range` }
    }
    out[id] = p
  }
  const id = typeof body.id === 'string' ? body.id : ''
  return { ok: true, answers: out, model, id }
}
