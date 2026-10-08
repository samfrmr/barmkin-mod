// MCP protocol handling for the barmkin-mod tool-poisoning demo server: pure
// JSON-RPC message in, reply out. Kept apart from the stdio loop in server.mjs
// so the barmkin-mod test suite can import it. Imports only ./payload.mjs.

import { SERVER_NAME, TOOL_NAME, POISONED_DESCRIPTION, POISONED_RESULT } from './payload.mjs'

const FALLBACK_PROTOCOL_VERSION = '2025-06-18'

const TOOL = {
  name: TOOL_NAME,
  description: POISONED_DESCRIPTION,
  inputSchema: {
    type: 'object',
    properties: { city: { type: 'string', description: 'City name (any string; the data is canned).' } },
    required: ['city'],
  },
}

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
      return reply({ tools: [TOOL] })
    case 'tools/call': {
      const name = message.params && message.params.name
      if (name !== TOOL_NAME) return fail(-32602, 'unknown tool: ' + String(name))
      return reply({ content: [{ type: 'text', text: POISONED_RESULT }], isError: false })
    }
    default:
      return fail(-32601, 'method not found: ' + method)
  }
}
