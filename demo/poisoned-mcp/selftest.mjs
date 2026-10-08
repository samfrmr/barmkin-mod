#!/usr/bin/env node
// Plain-Node check, run by CI and by the demo docs:
//   node demo/poisoned-mcp/selftest.mjs
// server.mjs speaks MCP over stdio: handshake, tools/list, tools/call.
// The guard behavior itself is covered by tests/poisoned-mcp-demo.test.ts.

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  POISONED_DESCRIPTION,
  POISONED_RESULT,
  TOOL_NAME,
  WITHHELD_TOOL_NAME,
  WITHHELD_DESCRIPTION,
  WITHHELD_RESULT,
  FLAGGED_TOOL_NAME,
  FLAGGED_DESCRIPTION,
  FLAGGED_RESULT,
} from './payload.mjs'

const here = (file) => fileURLToPath(new URL(file, import.meta.url))

const child = spawn(process.execPath, [here('server.mjs')], { stdio: ['pipe', 'pipe', 'inherit'] })
const replies = new Map()
let buffer = ''
child.stdout.setEncoding('utf8')
child.stdout.on('data', (chunk) => {
  buffer += chunk
  let newline
  while ((newline = buffer.indexOf('\n')) !== -1) {
    const message = JSON.parse(buffer.slice(0, newline))
    buffer = buffer.slice(newline + 1)
    replies.set(message.id, message)
  }
})

const send = (message) => child.stdin.write(JSON.stringify(message) + '\n')
const reply = async (id) => {
  for (let i = 0; i < 200 && !replies.has(id); i++) await new Promise((resolve) => setTimeout(resolve, 25))
  assert.ok(replies.has(id), 'no reply to request ' + id)
  return replies.get(id)
}

try {
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'selftest', version: '0' } } })
  assert.equal((await reply(1)).result.serverInfo.name, 'poisoned-demo')
  send({ jsonrpc: '2.0', method: 'notifications/initialized' })
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  const tools = (await reply(2)).result.tools
  assert.deepEqual(tools.map((t) => [t.name, t.description]), [
    [TOOL_NAME, POISONED_DESCRIPTION],
    [WITHHELD_TOOL_NAME, WITHHELD_DESCRIPTION],
    [FLAGGED_TOOL_NAME, FLAGGED_DESCRIPTION],
  ])
  const calls = [[TOOL_NAME, POISONED_RESULT], [WITHHELD_TOOL_NAME, WITHHELD_RESULT], [FLAGGED_TOOL_NAME, FLAGGED_RESULT]]
  for (const [i, [name, expected]] of calls.entries()) {
    send({ jsonrpc: '2.0', id: 3 + i, method: 'tools/call', params: { name, arguments: {} } })
    assert.equal((await reply(3 + i)).result.content[0].text, expected)
  }
  console.log('poisoned-mcp selftest: ok')
} finally {
  child.kill()
}
