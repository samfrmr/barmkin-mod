// Proves the poisoned-MCP demo fixture (demo/poisoned-mcp/) serves the
// payload the demo docs describe and that barmkin-mod's guards neutralize
// or block it. The fixture module is imported directly; the guard behavior runs
// through the real registered hooks, as in integration.test.ts. That the fixture
// is inert and local-only is checked by demo/poisoned-mcp/selftest.mjs.
import { expect, test } from 'claude-code/testing'
import { handleMessage } from '../demo/poisoned-mcp/protocol.mjs'
import {
  SERVER_NAME,
  TOOL_NAME,
  REGISTERED_TOOL,
  POISONED_DESCRIPTION,
  POISONED_RESULT,
  LEGIT_DESCRIPTION,
  POISON_MARKERS,
  DEMO_EGRESS_COMMAND,
} from '../demo/poisoned-mcp/payload.mjs'
import { neutralizeDescription, parseMcpServerName } from '../hooks/lib/mcp-guard'
import { heuristicInjectionScore } from '../hooks/lib/taint'
import { scrubInvisible } from '../hooks/lib/scrub'

const poisonedCall = (on: any) => on('tool.call', () => ({ result: [{ type: 'text', text: POISONED_RESULT }] }))

// --- the fixture itself ----------------------------------------------------

test('the fixture registers one tool under the name the demo prompt uses', () => {
  expect(REGISTERED_TOOL).toBe('mcp__poisoned-demo__get_forecast')
  expect(parseMcpServerName(REGISTERED_TOOL)).toBe(SERVER_NAME)
  const listed = handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) as any
  expect(listed.result.tools.map((t: any) => t.name)).toEqual([TOOL_NAME])
  expect(listed.result.tools[0].description).toBe(POISONED_DESCRIPTION)
})

test('the fixture answers the MCP handshake and ignores notifications', () => {
  const init = handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } }) as any
  expect(init.result.protocolVersion).toBe('2025-03-26')
  expect(init.result.serverInfo.name).toBe(SERVER_NAME)
  expect(handleMessage({ jsonrpc: '2.0', method: 'notifications/initialized' })).toBe(null)
})

test('the fixture returns the canned poisoned result and rejects unknown tools and methods', () => {
  const ok = handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: TOOL_NAME, arguments: { city: 'x' } } }) as any
  expect(ok.result.content).toEqual([{ type: 'text', text: POISONED_RESULT }])
  const unknown = handleMessage({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'other' } }) as any
  expect(unknown.error.code).toBe(-32602)
  const method = handleMessage({ jsonrpc: '2.0', id: 4, method: 'resources/list' }) as any
  expect(method.error.code).toBe(-32601)
})

test('the only command the poisoned result asks for is a harmless one the egress guard denies by shape', () => {
  expect(DEMO_EGRESS_COMMAND).toBe('echo true | sh')
  expect(POISONED_RESULT).toContain('`' + DEMO_EGRESS_COMMAND + '`')
})

// --- tool.describe: the poisoned description is neutralized ----------------

test('neutralizeDescription strips every poisoned sentence and keeps the legitimate one', () => {
  const { description, flagged } = neutralizeDescription(scrubInvisible(POISONED_DESCRIPTION).text)
  expect(flagged).toBe(true)
  expect(description).toBe(LEGIT_DESCRIPTION)
  for (const marker of Object.values(POISON_MARKERS)) expect(description).not.toContain(marker)
})

test('the poisoned description hides invisible characters that the scrub removes', () => {
  const { text, hiddenCount } = scrubInvisible(POISONED_DESCRIPTION)
  expect(hiddenCount).toBeGreaterThan(32)
  expect(text).not.toContain('demo-hidden')
})

// The test kit needs a base implementation beneath the mod, standing in for
// Claude Code's own description; the mod's hook wraps it.
const baseDescribe = (on: any) => on('tool.describe', ($: any, e: any) => ({ description: e.description }))

test('the registered tool.describe hook hands Claude only the legitimate description', async ($, on) => {
  baseDescribe(on)
  const out = await $.tool.describe({ tool: REGISTERED_TOOL, description: POISONED_DESCRIPTION })
  expect(out.description).toBe(LEGIT_DESCRIPTION)
})

test('a poisoned description with enough hidden characters taints the session', async ($, on) => {
  baseDescribe(on)
  on('tool.call', () => ({ result: 'ok' }))
  await $.tool.describe({ tool: REGISTERED_TOOL, description: POISONED_DESCRIPTION })
  const shell = await $.tool.call({ tool: 'Bash', command: DEMO_EGRESS_COMMAND })
  expect(shell.deny).toContain('untrusted content')
})

// --- tool.call: the poisoned result taints the session ---------------------

test('the poisoned result scores as injection and is not withheld without a classifier', () => {
  const score = heuristicInjectionScore(POISONED_RESULT)
  expect(score).toBeGreaterThanOrEqual(0.5)
  expect(score).toBeLessThan(0.85)
})

test('the poisoned result reaches Claude with the untrusted-content warning attached', async ($, on) => {
  poisonedCall(on)
  const out = await $.tool.call({ tool: REGISTERED_TOOL, city: 'x' })
  expect(out.deny).toBeUndefined()
  expect(JSON.stringify(out.context)).toContain('untrusted external source')
})

test('after the poisoned result, the shell command it asks for is denied before it runs', async ($, on) => {
  poisonedCall(on)
  await $.tool.call({ tool: REGISTERED_TOOL, city: 'x' })
  const shell = await $.tool.call({ tool: 'Bash', command: DEMO_EGRESS_COMMAND })
  expect(shell.deny).toContain('outward-effect shell command')
  expect(shell.deny).toContain('untrusted content')
})

test('/barmkin-mod-status shows the poisoned result as the taint source', async ($, on) => {
  poisonedCall(on)
  await $.tool.call({ tool: REGISTERED_TOOL, city: 'x' })
  const answer = await $.command.run({ command: 'barmkin-mod-status', args: '' })
  expect(answer.text).toContain('taint: ON')
  expect(answer.text).toContain('mcp:' + SERVER_NAME)
})

test('the same command runs on a clean session, so the denial is the taint and not the command', async ($, on) => {
  on('tool.call', () => ({ result: 'ok' }))
  const shell = await $.tool.call({ tool: 'Bash', command: DEMO_EGRESS_COMMAND })
  expect(shell.deny).toBeUndefined()
})

// --- allowlist: the server can be refused outright -------------------------

test('an allowlist that omits the poisoned server refuses the call before it runs', { options: { mcp_server_allowlist: ['github'] } }, async ($, on) => {
  let ran = false
  on('tool.call', () => {
    ran = true
    return { result: [{ type: 'text', text: POISONED_RESULT }] }
  })
  const out = await $.tool.call({ tool: REGISTERED_TOOL, city: 'x' })
  expect(out.deny).toContain('"' + SERVER_NAME + '" is not on the allowlist')
  expect(ran).toBe(false)
})

test('an allowlist that names the poisoned server lets the call through to the content screen', { options: { mcp_server_allowlist: [SERVER_NAME] } }, async ($, on) => {
  poisonedCall(on)
  const out = await $.tool.call({ tool: REGISTERED_TOOL, city: 'x' })
  expect(out.deny).toBeUndefined()
  expect(JSON.stringify(out.context)).toContain('untrusted external source')
})
