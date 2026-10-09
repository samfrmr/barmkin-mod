// barmkin-mod: a Claude Code mods security layer. See README.md for the
// capability list and the posture this mod does and doesn't cover.
//
// Fail-closed convention: a hook that guards (can deny/consume/withhold)
// gets a `.catch` that denies on failure. A hook that's purely advisory
// (the HUD) has none, so the documented no-catch default applies: fail
// before `next()` skips the hook (the action proceeds without our
// annotation), fail after `next()` leaves the result as `next()` produced
// it. Neither path can loosen a decision someone else already made --
// these hooks only ever add a deny/consume/withhold on top, never an allow.
//
// `$` is only ever used as `$.namespace.method(...)` and only ever passed
// to a function declared at this file's top level (never into an imported
// file or a function nested inside a hook), per `claude plugin validate`'s
// static-analysis rules for the mods API.
import { atom, read, update } from 'claude-code'
import { REDACTION_RULES } from './lib/redaction-rules'
import {
  redactText,
  redactInEitherView as redactInEitherViewLib,
  classifierInput,
  WITHHELD_TEXT,
  containsAnySecret,
  containsSecretInEitherView,
  exceedsResultBudget,
  exceedsScanLimit,
} from './lib/redaction'
import { scrubInvisible } from './lib/scrub'
import {
  composeScreen,
  isOutsideCwd,
  heuristicInjectionScore,
  parseTaintClearPosture,
  promptClearsTaintUnder,
  compactClearsTaint,
  sessionEndClearsTaint,
  commandMayClearTaint,
  classifierGapReason,
  CLASSIFIER_WINDOW_CHARS,
  describeTaintClear,
  describeTaintBanner,
  UNTRUSTED_CONTENT_WARNING,
  type HeldTaint,
  type ScoreSource,
  type ScreenOutcome,
  type TaintClearPosture,
} from './lib/taint'
import {
  classifyEgress,
  decideEgress,
  touchesSecretPath,
  isInlineSkillShell,
  inlineShellDenyReason,
  type EgressCall,
  type EgressVerdict,
  type TrifectaLegs,
} from './lib/egress'
import {
  buildSystemOneRequest,
  parseSystemOneResponse,
  JEV_MODEL_PATTERN,
  type NoulQuestion,
  type SystemOneParseResult,
} from './lib/system-one-client'
import { neutralizeDescription, parseMcpServerName, isAllowedServer } from './lib/mcp-guard'
import { extractResultText, appendContext, withholdResult } from './lib/tool-result'
import { meetsMinimumVersion, MIN_CLAUDE_CODE_VERSION } from './lib/version'
import { checkPosture } from './lib/posture'
import { skillBodyWithheldText, skillListingWithheldText, neutralizeSkillListing } from './lib/skill-guard'

// ---------------------------------------------------------------------------
// $.state atoms. Declared values must match types/index.d.ts, and plugin/key
// must be string literals so `claude plugin validate` can read them.
// ---------------------------------------------------------------------------

interface Verdict {
  toolUseId: string
  question: string
  probability: number
  decision: 'pass' | 'escalate' | 'deny'
  model: string
  at: number
}

interface EgressRecord {
  tool: string
  classIds: string[]
  decision: 'deny' | 'warn'
  rule: string
  at: number
}

const tainted = atom({ plugin: 'barmkin-mod', key: 'tainted' }, false)
const taintReason = atom({ plugin: 'barmkin-mod', key: 'taintReason' }, null as string | null)
// Set when the taint needs a person's /barmkin-mod-clear-taint (the classifier
// gap): holds why. A prompt, compaction or /clear leaves the taint standing
// while this is set; only the command clears it.
const taintAckReason = atom({ plugin: 'barmkin-mod', key: 'taintAckReason' }, null as string | null)
// Trifecta leg B (sensitive access); leg A is `tainted`, leg C is evaluated per call.
const sensitiveAccess = atom({ plugin: 'barmkin-mod', key: 'sensitiveAccess' }, false)
const sensitiveReason = atom({ plugin: 'barmkin-mod', key: 'sensitiveReason' }, null as string | null)
const lastEgress = atom({ plugin: 'barmkin-mod', key: 'lastEgress' }, null as EgressRecord | null)
const lastVerdict = atom({ plugin: 'barmkin-mod', key: 'lastVerdict' }, null as Verdict | null)
const breakerOpenUntil = atom({ plugin: 'barmkin-mod', key: 'breakerOpenUntil' }, 0)
const breakerFailureCount = atom({ plugin: 'barmkin-mod', key: 'breakerFailureCount' }, 0)

// Redaction placeholder counters. Not security state (no secret value is
// ever kept, only a per-category count for unique labels), so a plain
// module variable is fine; it resets on reload like any other.
const redactionCounters: Record<string, number> = {}

const BREAKER_FAILURE_THRESHOLD = 3
const BREAKER_COOLDOWN_MS = 60_000
const JEV_TIMEOUT_MS = 700
// More than this many invisible-text carriers (scrubInvisible's
// `hiddenCount`, which leaves out ANSI/C0 terminal formatting and the
// ZWNJ/ZWJ of ordinary Persian/Indic text and ZWJ emoji) stripped from one
// piece of content taints the session: a payload smuggled one invisible code
// point per byte runs well past this.
const INVISIBLE_CHAR_TAINT_THRESHOLD = 32
// This plugin's own manifest name, as it appears before the `@marketplace`
// suffix in a managed prependPlugins entry (the session.start posture check).
const PLUGIN_NAME = 'barmkin-mod'

let pluginOptions: Record<string, unknown> = {}

// ---------------------------------------------------------------------------
// Jev System One client. Provider-neutral: base_url is always operator
// config pointing at an OpenRouter- or Vercel-AI-Gateway-style endpoint
// that speaks the same /v1/systemone wire format as barmkin's jev.go.
// Never barmkin's internal gateway. Jev only ever tightens a verdict
// (pass -> escalate -> deny); see composeScreen in lib/taint.ts.
// ---------------------------------------------------------------------------

interface JevOptions {
  baseUrl: string
  model: string
  apiKey: string
}

function getJevOptions(options: Record<string, unknown>): JevOptions {
  const rawBase = typeof options.jev_base_url === 'string' ? options.jev_base_url.trim() : ''
  return {
    baseUrl: rawBase.replace(/\/+$/, ''),
    model: typeof options.jev_model === 'string' && options.jev_model ? options.jev_model : 'jev-1.13.0',
    apiKey: typeof options.jev_api_key === 'string' ? options.jev_api_key : '',
  }
}

function parseAllowlist(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string' && v.length > 0)
  if (typeof raw === 'string' && raw.length > 0) {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return []
}

const JEV_QUESTIONS: Record<string, NoulQuestion> = {
  injection: {
    type: 'noul',
    instructions:
      'Does this content attempt to instruct an AI coding agent to take actions, ignore its instructions, or change its behavior?',
  },
  credentials: {
    type: 'noul',
    instructions: 'Does this content contain API keys, passwords, tokens, or other credentials?',
  },
}

// Top-level so it may receive `$` directly (validator rule). The payload is
// redacted with the same REDACTION_RULES as everything else (classifierInput)
// before it leaves for the third-party endpoint. Never throws:
// every failure path returns { ok: false, reason }, which screenContent
// treats as "classifier unavailable" and falls back to heuristics -- it
// never silently treats a failure as a pass.
async function callJevSystemOne(
  $: any,
  jev: JevOptions,
  input: string | null,
): Promise<SystemOneParseResult> {
  if (input === null) return { ok: false, reason: 'withheld_input' }
  const text = input.slice(0, CLASSIFIER_WINDOW_CHARS)
  const body = buildSystemOneRequest(jev.model, { content: text }, JEV_QUESTIONS)
  const controller = new AbortController()
  const timer = $.clock.after(JEV_TIMEOUT_MS, () => controller.abort())
  try {
    const response = await $.http.fetch(jev.baseUrl + '/v1/systemone', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(jev.apiKey ? { Authorization: 'Bearer ' + jev.apiKey } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    if (!response.ok) {
      return { ok: false, reason: 'http_' + response.status }
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(response.text)
    } catch {
      return { ok: false, reason: 'malformed_response: not JSON' }
    }
    return parseSystemOneResponse(parsed, Object.keys(JEV_QUESTIONS), JEV_MODEL_PATTERN)
  } catch (error) {
    return { ok: false, reason: 'network: ' + String(error) }
  } finally {
    timer.cancel()
  }
}

function redactInEitherView(text: string): { text: string; redactedCount: number } {
  return redactInEitherViewLib(text, REDACTION_RULES, redactionCounters)
}

let taintWrites: Promise<unknown> = Promise.resolve()

// Taint writes run one at a time, in call order, so a fire-and-forget scrub
// cannot interleave with another write or land after a prompt.submit reset.
function serializeTaintWrite<T>(write: () => Promise<T>): Promise<T> {
  const run = taintWrites.then(write)
  taintWrites = run.catch(() => {})
  return run
}

function markTainted($: any, reason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    await update($, tainted, () => true)
    await update($, taintReason, (current: string | null) => current ?? reason)
  })
}

// Taints the session and records that only a person's /barmkin-mod-clear-taint
// clears it. The first acknowledgement reason recorded for a session wins.
function markTaintedNeedingAck($: any, reason: string, ackReason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    await update($, tainted, () => true)
    await update($, taintReason, (current: string | null) => current ?? reason)
    await update($, taintAckReason, (current: string | null) => current ?? ackReason)
  })
}

// What a denied call tells Claude about getting unblocked.
function askAgainHint(ackReason: string | null): string {
  return ackReason === null
    ? 'Ask again after a new message.'
    : 'Ask the user to run /barmkin-mod-clear-taint to acknowledge it; a new message does not clear this taint.'
}

async function readTaint($: any): Promise<{ tainted: boolean; reason: string | null; ackReason: string | null }> {
  await taintWrites
  return { tainted: await read($, tainted), reason: await read($, taintReason), ackReason: await read($, taintAckReason) }
}

// Clears both legs (taint and sensitive access) in one queued write and
// returns what they held. Every clearing path goes through here: a human
// prompt in human-origin posture, a compaction or /clear in sticky posture,
// and /barmkin-mod-clear-taint in either. Only the command is an explicit
// acknowledgement (`acknowledge`): while a taint requires one, every other
// path leaves both legs held and returns null.
function clearTaintLegs($: any, acknowledge: boolean): Promise<HeldTaint | null> {
  return serializeTaintWrite(async () => {
    const ackReason = await read($, taintAckReason)
    if (ackReason !== null && !acknowledge) return null
    const held: HeldTaint = {
      tainted: await read($, tainted),
      taintReason: await read($, taintReason),
      sensitive: await read($, sensitiveAccess),
      sensitiveReason: await read($, sensitiveReason),
      ackReason,
    }
    await update($, tainted, () => false)
    await update($, taintReason, () => null)
    await update($, taintAckReason, () => null)
    await update($, sensitiveAccess, () => false)
    await update($, sensitiveReason, () => null)
    return held
  })
}

function taintClearPosture(): TaintClearPosture {
  return parseTaintClearPosture(pluginOptions.taint_clear)
}

// Leg B of the trifecta. Written through the same queue as the taint so a
// human prompt's reset cannot interleave with it. The first reason recorded
// for a session wins, as it does for the taint.
function markSensitive($: any, reason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    await update($, sensitiveAccess, () => true)
    await update($, sensitiveReason, (current: string | null) => current ?? reason)
  })
}

async function readLegs($: any): Promise<TrifectaLegs> {
  await taintWrites
  return {
    untrusted: await read($, tainted),
    untrustedReason: await read($, taintReason),
    sensitive: await read($, sensitiveAccess),
    sensitiveReason: await read($, sensitiveReason),
    ackRequired: (await read($, taintAckReason)) !== null,
  }
}

// Marks leg B when a call names a secret-bearing path.
async function noteSensitiveAccess($: any, call: EgressCall): Promise<void> {
  if (touchesSecretPath(call)) await markSensitive($, 'a ' + call.tool + ' call named a credential path')
}

// The egress gate for one call: notes any sensitive access in it, classifies
// it against the egress classes, and decides over the trifecta legs. A deny or
// warn is recorded for the status surface. Never answers allow.
async function egressGate($: any, call: EgressCall): Promise<EgressVerdict> {
  await noteSensitiveAccess($, call)
  const verdict = decideEgress(classifyEgress(call), await readLegs($))
  if (verdict.kind !== 'pass') {
    await update($, lastEgress, () => ({
      tool: call.tool,
      classIds: verdict.classIds,
      decision: verdict.kind,
      rule: verdict.kind === 'deny' ? verdict.rule : 'untrusted',
      at: Date.now(),
    }))
  }
  return verdict
}

// Checks and reserves the taint in one queued write, so two Skill calls
// dispatched together cannot both see an untainted session. Returns the
// standing reason when the session is already tainted (the load is denied),
// or null once this load holds the reservation. The reservation is not released
// when the load fails, so a failed or denied load leaves the session tainted.
function reserveSkillLoad(
  $: any,
  loadReason: string,
): Promise<{ standingReason: string | null; ackReason: string | null } | null> {
  return serializeTaintWrite(async () => {
    let wasTainted = false
    await update($, tainted, (current: boolean) => {
      wasTainted = current
      return true
    })
    if (wasTainted) return { standingReason: await read($, taintReason), ackReason: await read($, taintAckReason) }
    await update($, taintReason, () => loadReason)
    return null
  })
}

// Shared by every scrubInvisible call site (the outermost redaction pass, tool.describe,
// and session.receive): taints the session when a scrub stripped more than
// INVISIBLE_CHAR_TAINT_THRESHOLD characters.
// The first reason recorded for a session wins, so a later taint never
// replaces the evidence the deny message and the verdict already show.
async function taintForScrub($: any, hiddenCount: number, source: string): Promise<void> {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return
  try {
    await markTainted($, 'stripped ' + hiddenCount + ' invisible character(s) from ' + source)
  } catch {
    $.ui.log('barmkin-mod: could not record taint for ' + source + ' (' + hiddenCount + ' invisible character(s) stripped)')
  }
}

async function recordBreakerFailure($: any): Promise<void> {
  const failures = (await read($, breakerFailureCount)) + 1
  await update($, breakerFailureCount, () => failures)
  if (failures >= BREAKER_FAILURE_THRESHOLD) {
    await update($, breakerOpenUntil, () => Date.now() + BREAKER_COOLDOWN_MS)
  }
}

// Screens one piece of untrusted content (a fetched page, an MCP result, a
// file read from outside cwd, an inbound peer message) and, as a side
// effect, updates the taint and explanation-surface state. Top-level so it
// can receive `$` directly.
async function screenContent(
  $: any,
  text: string,
  label: string,
  toolUseId: string | undefined,
): Promise<ScreenOutcome> {
  const raw = text
  if (exceedsScanLimit(raw)) {
    return {
      decision: 'deny',
      tainted: false,
      reason: 'it is longer than the 16 KiB scan limit',
      question: 'injection',
      probability: 0,
      model: 'heuristic',
    }
  }
  text = scrubInvisible(raw).text
  const jev = getJevOptions(pluginOptions)
  const now = Date.now()
  const breakerUntil = await read($, breakerOpenUntil)
  const canUseJev = jev.baseUrl !== '' && breakerUntil <= now

  const local: ScoreSource = {
    model: 'heuristic',
    injection: heuristicInjectionScore(text),
    credentials: containsSecretInEitherView(raw, REDACTION_RULES) ? 0.9 : 0,
  }
  let jevScores: ScoreSource | null = null

  // What the classifier would be sent. Computed whenever Jev is configured
  // (even with the breaker open) to tell whether the content fits its window.
  const jevInput = jev.baseUrl !== '' ? classifierInput(raw, REDACTION_RULES, redactionCounters) : null

  if (canUseJev) {
    const outcome = await callJevSystemOne($, jev, jevInput)
    if (outcome.ok) {
      jevScores = {
        model: outcome.model,
        injection: outcome.answers.injection ?? 0,
        credentials: outcome.answers.credentials ?? 0,
      }
      await update($, breakerFailureCount, () => 0)
    } else if (outcome.reason !== 'withheld_input') {
      await recordBreakerFailure($)
    }
  }

  const screened = composeScreen(local, jevScores)
  // A withheld (deny) result never reaches Claude, so only content that does
  // is held to the window.
  const gap = screened.decision === 'deny' ? null : classifierGapReason(jev.baseUrl !== '', jevInput === null ? null : jevInput.length)
  const composed: ScreenOutcome = gap
    ? { ...screened, tainted: true, decision: 'escalate', reason: screened.tainted ? screened.reason : gap }
    : screened

  await update($, lastVerdict, () => ({
    toolUseId: toolUseId ?? '',
    question: label + ' (' + composed.question + ')',
    probability: composed.probability,
    decision: composed.decision,
    model: composed.model,
    at: now,
  }))

  if (gap) await markTaintedNeedingAck($, composed.reason, gap)
  else if (composed.tainted) await markTainted($, composed.reason)
  if (screened.tainted && screened.question === 'credentials') await markSensitive($, composed.reason)

  if (toolUseId) {
    try {
      // $.ui.notice's exact id field on a tool.call event is unverified
      // against this build's generated types (see README's Phase 0
      // checklist); never let a signature mismatch break the screen.
      $.ui.notice(toolUseId, 'barmkin-mod: ' + composed.model + ' scored this ' + composed.decision + ' (' + composed.reason + ')')
    } catch {
      // best-effort annotation only
    }
  }

  return composed
}

// ---------------------------------------------------------------------------
// session.start: version check, register commands.
// ---------------------------------------------------------------------------

async function sessionStartHook($: any, e: any, next: any) {
  const statusLines: string[] = []

  try {
    const version = await $.session.version()
    if (typeof version === 'string' && !meetsMinimumVersion(version)) {
      statusLines.push(
        'barmkin-mod needs Claude Code >= ' + MIN_CLAUDE_CODE_VERSION + ' (running ' + version + '); some protections may not apply',
      )
    }
  } catch {
    // $.session.version() unavailable on this build; nothing to warn about
  }

  let merged: Record<string, unknown> | null = null
  try {
    merged = await $.settings.read()
  } catch {
    // $.settings.read() unavailable or refused on this build; checkPosture reports it as unverified
  }
  if (typeof merged !== 'object') merged = null
  let policy: Record<string, unknown> | null = null
  try {
    policy = await $.settings.read({ source: 'policy' })
  } catch {
    // the policy source refused or unavailable; checkPosture reports seating as unverified
  }
  if (typeof policy !== 'object') policy = null
  const mcpAllowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
  for (const warning of checkPosture({ merged, policy }, PLUGIN_NAME, mcpAllowlist)) {
    statusLines.push('barmkin-mod posture: ' + warning)
  }

  // $.ui.status holds one line per plugin and draws a newline as U+FFFD, so each warning is its own transcript row via $.ui.log.
  for (const line of statusLines) {
    try {
      $.ui.log(line)
    } catch {
      // no log surface on this build; the commands below still register
    }
  }

  try {
    await $.command.register({ name: 'barmkin-mod-status', description: 'Show barmkin-mod taint, breaker, and last classifier verdict' })
    await $.command.register({
      name: 'barmkin-mod-clear-taint',
      description: 'Clear the barmkin-mod taint and sensitive-access flags and re-enable egress',
    })
  } catch {
    // a command name collided with another plugin; the mod still works
  }
  return next(e)
}

// ---------------------------------------------------------------------------
// prompt.submit: redact secrets the user pasted, clear taint when a human sent it.
// ---------------------------------------------------------------------------

async function promptSubmitHook($: any, e: any, next: any) {
  // In human-origin posture only a person's prompt clears the taint and the
  // sensitive-access leg: the composer or the bridge, plus an SDK prompt when
  // the headless-lane option is on. In sticky posture no prompt clears them.
  if (promptClearsTaintUnder(taintClearPosture(), e.origin, pluginOptions.sdk_prompts_clear_taint === true)) {
    await clearTaintLegs($, false)
  }

  if (typeof e.text !== 'string') return next(e)
  if (exceedsScanLimit(e.text)) {
    return { drop: 'barmkin-mod: your message is longer than the 16 KiB scan limit, so it was withheld' }
  }
  // Detection runs on the scrubbed view; the original text is forwarded unless a secret is redacted.
  const { text, redactedCount } = redactInEitherView(e.text)
  if (redactedCount === 0) return next(e)
  if (text === WITHHELD_TEXT) {
    return { drop: 'barmkin-mod: your message could not be fully scanned after redaction, so it was withheld' }
  }
  $.ui.log('barmkin-mod: redacted ' + redactedCount + ' likely secret(s) from your message before sending it')
  return next({ ...e, text })
}

// ---------------------------------------------------------------------------
// Sticky taint: the events that break the context the taint guards. Both only
// clear in sticky posture, and both only ever clear after the event stood, so
// a hook that fails leaves the taint held.
// ---------------------------------------------------------------------------

async function compactHook($: any, e: any, next: any) {
  const result = await next(e)
  if (taintClearPosture() === 'sticky' && compactClearsTaint(e.trigger, e.agentId, result)) await clearTaintLegs($, false)
  return result
}

async function sessionEndHook($: any, e: any, next: any) {
  if (taintClearPosture() === 'sticky' && sessionEndClearsTaint(e.reason)) await clearTaintLegs($, false)
  return next(e)
}

// ---------------------------------------------------------------------------
// MCP tool-poisoning guard: harden descriptions, per-server allowlist.
// ---------------------------------------------------------------------------

async function toolDescribeHook($: any, e: any, next: any) {
  const current = await next(e)
  const description = typeof current?.description === 'string' ? current.description : e.description
  if (typeof description !== 'string') return current

  const scrubbed = scrubInvisible(description)
  void taintForScrub($, scrubbed.hiddenCount, 'an MCP tool description')

  const { description: cleaned, flagged } = neutralizeDescription(scrubbed.text)
  if (!flagged) {
    return scrubbed.text === description ? current : { ...current, description: scrubbed.text }
  }
  $.ui.log('barmkin-mod: flagged instruction-like text in a tool description (' + e.tool + ')', { to: 'debug' })
  if (cleaned === description) return current
  return { ...current, description: cleaned }
}

async function mcpGuardHook($: any, e: any, next: any) {
  const serverName = parseMcpServerName(e.tool)
  if (serverName) {
    const allowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
    if (!isAllowedServer(serverName, allowlist)) {
      return { deny: 'barmkin-mod: MCP server "' + serverName + '" is not on the allowlist' }
    }
  }

  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }

  const result = await next(e)
  if (!result || result.deny || result.isError) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'mcp:' + (serverName ?? e.tool), e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, 'barmkin-mod: withheld this MCP result (' + verdict.reason + '). Ask the user before retrying.')
  }
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function mcpGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the MCP guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Untrusted-content taint + injection screen.
// ---------------------------------------------------------------------------

// One gate for every egress class that is not an MCP call or a skill load:
// shell commands, web fetches and persistence-surface writes. A deny answers
// before the tool runs; a warn lets it run and tells Claude.
async function egressGuardHook($: any, e: any, next: any) {
  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }
  const result = await next(e)
  if (egress.kind === 'warn' && result && !result.deny && !result.isError) return appendContext(result, egress.message)
  return result
}

async function egressGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the egress guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Mediation guard. A skill's inline shell (`!`command``) runs the command
// through the permission check but never through the mods' tool.call chain, so
// none of the tool.call guards above see it; tool.check is the one event it
// does fire, with an empty tool_use_id. This hook only ever answers deny or
// returns what the permission layer decided, never allow or ask.
// ---------------------------------------------------------------------------

async function toolCheckGuardHook($: any, e: any, next: any) {
  const decided = await next(e)
  if (decided && decided.decision === 'deny') return decided
  const input = e.input && typeof e.input === 'object' ? (e.input as Record<string, unknown>) : null
  if (!input || typeof input.command !== 'string') return decided

  const call: EgressCall = { tool: e.tool, input }
  if (isInlineSkillShell(e.tool_use_id)) {
    const reason = inlineShellDenyReason(call)
    if (reason) return { decision: 'deny', reason }
  }
  // Second line for an ordinary call: the same egress verdict the tool.call
  // guard reached, in case the command was rewritten after it.
  const egress = await egressGate($, call)
  if (egress.kind === 'deny') return { decision: 'deny', reason: egress.message }
  return decided
}

async function toolCheckGuardCatch($: any, e: any, next: any) {
  return { decision: 'deny', reason: 'barmkin-mod: the shell mediation guard failed (' + next.error.kind + '), so this command was not run' }
}

async function webFetchTaintHook($: any, e: any, next: any) {
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'fetch:' + e.tool, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, 'barmkin-mod: withheld this result (' + verdict.reason + '). Ask the user before retrying.')
  }
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function readTaintHook($: any, e: any, next: any) {
  await noteSensitiveAccess($, { tool: e.tool, input: e })
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  if (typeof e.file_path !== 'string') return result

  let cwd = ''
  try {
    cwd = await $.session.cwd()
  } catch {
    return result
  }
  if (!isOutsideCwd(e.file_path, cwd)) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'read:' + e.file_path, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, "barmkin-mod: withheld this file's content (" + verdict.reason + '). Ask the user before retrying.')
  }
  // appendContext only adds a sibling `context` array alongside whatever
  // `result` already is -- it never touches `result`'s own shape -- so this
  // stays schema-valid for Read's `{ file: { content, ... } }` record the
  // same way it already is for every other tool here.
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function taintScreenCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the content screen failed (' + next.error.kind + '), so this result was withheld' }
}

// ---------------------------------------------------------------------------
// Secret redaction. Outermost tool.call hook (registered first, so it wraps
// every other hook above and redacts the final composed result -- including
// any context a later hook in this file added -- before Claude reads it).
// ---------------------------------------------------------------------------

// Read's image variant carries its payload as base64 at result.result.base64
// (flat) or result.result.file.base64 (file record). Gated on the Read tool so
// an MCP result cannot hide plaintext there.
function readImageBase64(e: any, result: any): string | undefined {
  const payload = result.result
  if (e.tool !== 'Read' || !payload || typeof payload !== 'object' || payload.type !== 'image') return undefined
  const base64 = typeof payload.base64 === 'string' ? payload.base64 : payload.file?.base64
  return typeof base64 === 'string' ? base64 : undefined
}

// Decodes an image payload that already passed the per-string cap and runs the
// rules over its bytes, so a secret in a plaintext file with an image extension
// is caught. The base64 text itself also goes through the normal redaction pass.
function imagePayloadWithholdReason(base64: string): string | null {
  let bytes: string
  try {
    bytes = atob(base64)
  } catch {
    return 'this Read image payload is not valid base64'
  }
  return containsAnySecret(bytes, REDACTION_RULES) ? 'this Read image payload contains a secret-shaped value' : null
}

async function redactionHook($: any, e: any, next: any) {
  const result = await next(e)
  if (!result || result.deny) return result
  if (exceedsResultBudget(result)) {
    return { deny: 'barmkin-mod: this tool result is larger than the redaction scan budget, so it was withheld' }
  }

  const imageBase64 = readImageBase64(e, result)
  const imageReason = imageBase64 === undefined ? null : imagePayloadWithholdReason(imageBase64)
  if (imageReason) return { deny: 'barmkin-mod: ' + imageReason + ', so it was withheld' }

  let changed = false
  let hiddenCount = 0
  let redactionHits = 0
  const next_: any = { ...result }

  // Every string inside the result is rewritten in place, whatever its
  // shape: a plain string, an MCP content-block array, or a built-in tool's
  // typed record (Bash `{stdout, stderr, ...}`, Read `{file: {content}}`).
  // The record keeps its shape so core's output-schema validation passes.
  // Core's model-visible rendering in `text` is redacted the same way.
  // Scrubbed before redaction: a zero-width character spliced into a
  // token shouldn't be able to help it dodge a secret pattern either.
  const redactValue = (value: unknown): unknown => {
    if (typeof value === 'string') {
      const scrubbed = scrubInvisible(value)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(value)
      redactionHits += redactedCount
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return value
      changed = true
      return redacted
    }
    if (Array.isArray(value)) return value.map(redactValue)
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v)]))
    }
    return value
  }
  if ('result' in result) next_.result = redactValue(result.result)
  const hiddenInResult = hiddenCount
  hiddenCount = 0
  if (typeof result.text === 'string') next_.text = redactValue(result.text)
  hiddenCount = Math.max(hiddenInResult, hiddenCount)

  if (Array.isArray(result.context)) {
    const redactedContext = result.context.map((c: unknown) => {
      if (typeof c !== 'string') return c
      const scrubbed = scrubInvisible(c)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(c)
      redactionHits += redactedCount
      if (redactedCount > 0 || scrubbed.strippedCount > 0) changed = true
      return redacted
    })
    next_.context = redactedContext
  }

  // A redaction hit means a credential-shaped value just passed through this
  // session: leg B of the trifecta. Written before returning (and queued with
  // the taint writes) so the very next egress call sees it.
  if (redactionHits > 0) {
    await markSensitive($, 'a ' + (parseMcpServerName(e.tool) ? 'tool' : e.tool) + ' result held a credential-shaped value')
  }

  void taintForScrub($, hiddenCount, 'tool:' + (typeof e.tool === 'string' && parseMcpServerName(e.tool) ? 'mcp' : e.tool))

  return changed ? next_ : result
}

async function redactionCatch($: any, e: any, next: any) {
  // Fail closed regardless of whether the tool already ran (next.called):
  // we can't un-run a command, but we can stop an unredacted result from
  // reaching the model or the transcript.
  return { deny: 'barmkin-mod: secret redaction failed (' + next.error.kind + '); the result was withheld to avoid leaking an unredacted secret' }
}

// ---------------------------------------------------------------------------
// Agent-to-agent firewall.
// ---------------------------------------------------------------------------

async function sessionReceiveHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string' || e.text.length === 0) return next(e)

  const scrubbed = scrubInvisible(e.text)
  void taintForScrub($, scrubbed.hiddenCount, 'an inbound peer message')
  if (exceedsScanLimit(e.text)) {
    return { consumed: 'barmkin-mod: withheld an inbound message (it is longer than the 16 KiB scan limit)' }
  }

  const verdict = await screenContent($, e.text, 'peer:' + (e.origin?.kind ?? 'unknown'), undefined)
  if (verdict.decision === 'deny') {
    return { consumed: 'barmkin-mod: withheld an inbound message (' + verdict.reason + ')' }
  }
  return next(scrubbed.text === e.text ? e : { ...e, text: scrubbed.text })
}

async function sessionReceiveCatch($: any, e: any, next: any) {
  return { consumed: 'barmkin-mod: the a2a screen failed (' + next.error.kind + '); message withheld' }
}

async function sessionSendHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string') return next(e)
  if (exceedsScanLimit(e.text)) {
    return { isDelivered: false, reason: 'barmkin-mod: message withheld, it is longer than the 16 KiB scan limit' }
  }
  // Detection runs on the scrubbed view; the original text is delivered when no secret is found.
  if (containsSecretInEitherView(e.text, REDACTION_RULES)) {
    return { isDelivered: false, reason: 'barmkin-mod: message withheld, it appears to contain a secret' }
  }
  return next(e)
}

async function sessionSendCatch($: any, e: any, next: any) {
  return { isDelivered: false, reason: 'barmkin-mod: the DLP screen failed (' + next.error.kind + '); message not sent' }
}

async function agentSpawnHook($: any, e: any, next: any) {
  const { tainted: isTainted, reason, ackReason } = await readTaint($)
  if (isTainted) {
    return {
      deny:
        'barmkin-mod: subagent spawn blocked while this session is tainted (' +
        (reason ?? 'unspecified') +
        '). ' +
        askAgainHint(ackReason),
    }
  }
  return next(e)
}

async function agentSpawnCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the a2a spawn guard failed (' + next.error.kind + '); subagent spawn blocked' }
}

// ---------------------------------------------------------------------------
// Skill content. skill.prompt fires with each skill body, after inline-shell
// output is substituted, for inline, context: fork and agent-preloaded skills.
// Its payload is { skill: <name string>, text }; the dispatcher rejects a
// changed `skill`, so only `text` is ever rewritten. Org seat only: sec-default
// forwards skill.prompt past the user tier, so this fires only when the mod is
// seated in managed prependPlugins ahead of sec-default (README "Seat
// requirements"). Like toolDescribeHook, it calls next first and screens and
// redacts the text that came out, so redaction sees the final body last.
// ---------------------------------------------------------------------------

async function skillPromptHook($: any, e: any, next: any) {
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  void taintForScrub($, scrubInvisible(text).hiddenCount, 'a skill body')
  const verdict = await screenContent($, text, 'skill:' + e.skill, undefined)
  if (verdict.decision === 'deny') {
    return { ...(current ?? e), text: skillBodyWithheldText(verdict.reason) }
  }

  const { text: redacted, redactedCount } = redactInEitherView(text)
  if (redacted === WITHHELD_TEXT) {
    return { ...(current ?? e), text: skillBodyWithheldText('the redacted body exceeds the 16 KiB scan limit') }
  }
  if (redactedCount > 0) {
    $.ui.log('barmkin-mod: redacted ' + redactedCount + ' likely secret(s) from skill ' + e.skill)
  }
  const body = verdict.tainted ? redacted + '\n\n' + UNTRUSTED_CONTENT_WARNING : redacted
  return { ...(current ?? e), text: body }
}

async function skillPromptCatch($: any, e: any, next: any) {
  return { skill: e.skill, text: skillBodyWithheldText('the skill screen failed (' + next.error.kind + ')') }
}

// A skill listing is `prompt.attachment{type:'skill_listing', text}`, one per
// session and one per spawned subagent. The hook is registered for that type
// only, so other attachments never reach it or its catch. The dispatcher honours
// a rewritten `text` and rejects a change to `type`, `origin`, `agentId` or `detail`.
async function skillListingHook($: any, e: any, next: any) {
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  const { text: neutralized, withheld } = neutralizeSkillListing(scrubInvisible(text).text)
  if (withheld > 0) $.ui.log('barmkin-mod: withheld ' + withheld + ' skill listing entr' + (withheld === 1 ? 'y' : 'ies') + ' with instruction-like text', { to: 'debug' })
  if (neutralized === text) return current ?? e
  return { ...(current ?? e), text: neutralized }
}

async function skillListingCatch($: any, e: any, next: any) {
  return { ...e, text: skillListingWithheldText('the listing screen failed (' + next.error.kind + ')') }
}

// Gates the Skill tool itself. A loaded skill is untrusted content in its own
// right: its body is screened by skillPromptHook, and the load taints the
// session so later outward-effect Bash and further skill loads are held until
// the user's next message. The taint is reserved before the load runs, so
// concurrent calls serialise on it, and the reservation stays on failure or
// denial, so a failed or denied load leaves the session tainted.
async function skillToolGuardHook($: any, e: any, next: any) {
  const name = typeof e.skill === 'string' ? e.skill : 'unnamed'
  const standing = await reserveSkillLoad($, 'skill "' + name + '" was loaded')
  if (standing) {
    await update($, lastEgress, () => ({ tool: 'Skill', classIds: ['skill-load'], decision: 'deny' as const, rule: 'untrusted', at: Date.now() }))
    return {
      deny:
        'barmkin-mod: loading a skill is blocked while this session is handling untrusted content (' +
        (standing.standingReason ?? 'unspecified') +
        '). ' +
        askAgainHint(standing.ackReason),
    }
  }
  return next(e)
}

async function skillToolGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the skill guard failed (' + next.error.kind + '), so this skill was not loaded' }
}

// ---------------------------------------------------------------------------
// Classifier explanation surface: HUD band.
// ---------------------------------------------------------------------------

// The tainted-session panel's color: the theme's error key, red in every
// theme, so the panel matches how the session draws its own errors.
const TAINT_COLOR = 'error'

// The clear-session labels: the theme's success key (green) and warning key
// (amber); both labels lead with a castle emoji. Green means Jev is
// configured and its breaker is closed; it does not claim any request
// succeeded. Amber means Jev is not configured or its breaker is open.
const CLEAR_ACTIVE = { color: 'success', label: '🏰 Barmkin session guard active' }
const CLEAR_DEGRADED = { color: 'warning', label: '🏰 Barmkin session guard degraded' }

function clearLabelFor(breakerOpen: boolean) {
  return getJevOptions(pluginOptions).baseUrl !== '' && !breakerOpen ? CLEAR_ACTIVE : CLEAR_DEGRADED
}

async function hudHook($: any, e: any, next: any) {
  const { tainted: isTainted, ackReason } = await readTaint($)
  const isSensitive = await read($, sensitiveAccess)
  const verdict = await read($, lastVerdict)

  const { Box, Text } = $.ui.resolve(e)
  const breakerUntil = await read($, breakerOpenUntil)
  const breakerOpen = breakerUntil > Date.now()
  const parts = ['barmkin-mod', 'taint:' + (isTainted ? 'ON' : 'off'), breakerOpen ? 'classifier:degraded' : 'classifier:ok']
  if (isSensitive) parts.splice(2, 0, isTainted ? 'sensitive:ON (egress locked)' : 'sensitive:ON')
  if (verdict) {
    parts.push(verdict.decision + ' p=' + verdict.probability.toFixed(2) + ' (' + verdict.model + ')')
  }

  // One red line for as long as the taint is held: untrusted content is
  // active, what it restricts, and the clear path that works under the
  // active posture.
  let banner = null
  if (isTainted) {
    banner = Box({
      key: 'barmkin-mod-taint',
      children: [Text({ color: TAINT_COLOR, bold: true, children: [describeTaintBanner(taintClearPosture(), isSensitive, ackReason !== null)] })],
    })
  }

  // next(e) may resolve to nothing if no other mod draws in the band, so
  // filter out a falsy child rather than assume an engine placeholder.
  // The state line below appears only when there is state to report.
  const stateLine = isTainted || isSensitive || verdict ? Text({ children: [parts.join(' · ')] }) : null
  const theirs = await next(e)
  return Box({ flexDirection: 'column', children: [theirs, banner, stateLine].filter(Boolean) })
}

// The clear-session label draws as a second child of the PromptHint footer,
// directly beneath the engine's own line (mode switcher included). While
// tainted the red banner in AbovePrompt speaks instead, so the engine's
// drawing is returned unchanged.
async function hintHook($: any, e: any, next: any) {
  const theirs = await next(e)
  const { tainted: isTainted } = await readTaint($)
  if (isTainted) return theirs
  const { Box, Text } = $.ui.resolve(e)
  const breakerUntil = await read($, breakerOpenUntil)
  const clear = clearLabelFor(breakerUntil > Date.now())
  const label = Text({ key: 'barmkin-mod-active', color: clear.color, children: [clear.label] })
  return Box({ flexDirection: 'column', children: [theirs, label].filter(Boolean) })
}

async function clearTaintCommandHook($: any, e: any) {
  const posture = taintClearPosture()
  const { ackReason } = await readTaint($)
  if (!commandMayClearTaint(e.origin, pluginOptions.sdk_prompts_clear_taint === true, ackReason !== null)) {
    return { text: 'barmkin-mod: taint posture is ' + posture + '; /barmkin-mod-clear-taint was not run from a person\'s prompt, so nothing was cleared.' }
  }
  const held = await clearTaintLegs($, true)
  return { text: held ? describeTaintClear(posture, held) : 'barmkin-mod: nothing was cleared.' }
}

async function statusCommandHook($: any) {
  const { tainted: isTainted, reason, ackReason } = await readTaint($)
  const isSensitive = await read($, sensitiveAccess)
  const sensitiveWhy = await read($, sensitiveReason)
  const egress = await read($, lastEgress)
  const verdict = await read($, lastVerdict)
  const breakerUntil = await read($, breakerOpenUntil)
  const lines = [
    'barmkin-mod status',
    'taint clear posture: ' + taintClearPosture(),
    'taint: ' + (isTainted ? 'ON (' + (reason ?? 'unspecified') + ')' : 'off'),
    ...(ackReason !== null
      ? ['acknowledgement required: ' + ackReason + '; run /barmkin-mod-clear-taint (a message, /clear or /compact does not clear it)']
      : []),
    'sensitive access: ' + (isSensitive ? 'ON (' + (sensitiveWhy ?? 'unspecified') + ')' : 'off'),
    'egress: ' +
      (isTainted && isSensitive ? 'all classes denied (Rule of Two)' : isTainted ? 'gated per class (taint)' : 'open') +
      (egress ? '; last ' + egress.decision + ': ' + egress.classIds.join(', ') + ' via ' + egress.tool + ' (' + egress.rule + ')' : ''),
    'classifier breaker: ' + (breakerUntil > Date.now() ? 'open (degraded, using heuristics)' : 'closed'),
    verdict
      ? 'last verdict: ' + verdict.decision + ' p=' + verdict.probability.toFixed(2) + ' model=' + verdict.model + ' question=' + verdict.question
      : 'last verdict: none yet',
  ]
  return { text: lines.join('\n') }
}

// ---------------------------------------------------------------------------
// Registration. Order matters for tool.call: the first hook registered is
// outermost (sees the result last), so redaction is registered first to
// redact whatever every other hook below it produced.
// ---------------------------------------------------------------------------

export function register(on: any, options: Record<string, unknown>) {
  pluginOptions = options ?? {}

  on('session.start', sessionStartHook)
  on('prompt.submit', promptSubmitHook)
  on('session.compact', compactHook)
  on('session.end', sessionEndHook)
  on('tool.describe', { tool: /^mcp__/ }, toolDescribeHook)

  on('tool.call', redactionHook).catch(redactionCatch)
  on('tool.call', { tool: /^mcp__/ }, mcpGuardHook).catch(mcpGuardCatch)
  on('tool.call', { tool: ['Bash', 'PowerShell', 'WebFetch', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'] }, egressGuardHook).catch(egressGuardCatch)
  on('tool.call', { tool: ['WebFetch', 'WebSearch'] }, webFetchTaintHook).catch(taintScreenCatch)
  on('tool.call', { tool: 'Read' }, readTaintHook).catch(taintScreenCatch)

  on('tool.call', { tool: 'Skill' }, skillToolGuardHook).catch(skillToolGuardCatch)
  on('tool.check', { tool: ['Bash', 'PowerShell'] }, toolCheckGuardHook).catch(toolCheckGuardCatch)

  on('skill.prompt', skillPromptHook).catch(skillPromptCatch)
  on('prompt.attachment', { type: 'skill_listing' }, skillListingHook).catch(skillListingCatch)

  on('session.receive', sessionReceiveHook).catch(sessionReceiveCatch)
  on('session.send', sessionSendHook).catch(sessionSendCatch)
  on('agent.spawn', agentSpawnHook).catch(agentSpawnCatch)
  on('ui.render', { component: 'AbovePrompt' }, hudHook)
  on('ui.render', { component: 'PromptHint' }, hintHook)
  on('command.run', { command: 'barmkin-mod-status' }, statusCommandHook)
  on('command.run', { command: 'barmkin-mod-clear-taint' }, clearTaintCommandHook)
}
