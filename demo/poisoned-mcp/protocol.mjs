// MCP protocol handling for the barmkin-mod tool-poisoning demo server: pure
// JSON-RPC message in, reply out. Kept apart from the stdio loop in server.mjs
// so the barmkin-mod test suite can import it. Imports only ./payload.mjs.

import {
  SERVER_NAME,
  TOOL_NAME,
  POISONED_DESCRIPTION,
  POISONED_RESULT,
  WITHHELD_TOOL_NAME,
  WITHHELD_DESCRIPTION,
  WITHHELD_RESULT,
  FLAGGED_TOOL_NAME,
  FLAGGED_DESCRIPTION,
  FLAGGED_RESULT,
} from './payload.mjs'

const FALLBACK_PROTOCOL_VERSION = '2025-06-18'

const tool = (name, description, result, argument) => ({
  definition: {
    name,
    description,
    inputSchema: {
      type: 'object',
      properties: { [argument]: { type: 'string', description: 'Any string; the data is canned.' } },
      required: [argument],
    },
  },
  result,
})

const TOOLS = [
  tool(TOOL_NAME, POISONED_DESCRIPTION, POISONED_RESULT, 'city'),
  tool(WITHHELD_TOOL_NAME, WITHHELD_DESCRIPTION, WITHHELD_RESULT, 'port'),
  tool(FLAGGED_TOOL_NAME, FLAGGED_DESCRIPTION, FLAGGED_RESULT, 'id'),
]

// One JSON-RPC message in, the reply out (null for a notification).
export function handleMessage(message) {
  if (!message || typeof message !== 'object' || typeof message.method !== 'string') return null
  const { id, method } = message
  const reply = (result) => ({ jsonrpc: '2.0', id, result })
  const fail = (code, text) => ({ jsonrpc: '2.0', id, error: { code, message: text } })
  if (id === undefined) return null

  switch (method) {
    case 'initialize': {
      const requested = message.params && message.params.protocolVersion
      return reply({
        protocolVersion: typeof requested === 'string' ? requested : FALLBACK_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: '0.0.0-demo' },
      })
    }
    case 'ping':
      return reply({})
    case 'tools/list':
      return reply({ tools: TOOLS.map((t) => t.definition) })
    case 'tools/call': {
      const name = message.params && message.params.name
      const found = TOOLS.find((t) => t.definition.name === name)
      if (!found) return fail(-32602, 'unknown tool: ' + String(name))
      return reply({ content: [{ type: 'text', text: found.result }], isError: false })
    }
    default:
      return fail(-32601, 'method not found: ' + method)
  }
}
