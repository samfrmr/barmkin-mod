#!/usr/bin/env node
// Local-only, dependency-free MCP server for the barmkin-mod tool-poisoning
// demo. Speaks MCP's stdio transport (newline-delimited JSON-RPC 2.0) and
// exposes one tool whose description and result carry inert injection text
// (see payload.mjs). It touches only stdin and stdout: no network, no
// filesystem, no child processes, no environment access.

import { handleMessage } from './protocol.mjs'

function serve() {
  let buffer = ''
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (chunk) => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, newline).trim()
      buffer = buffer.slice(newline + 1)
      if (!line) continue
      let parsed
      try {
        parsed = JSON.parse(line)
      } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }) + '\n')
        continue
      }
      const out = handleMessage(parsed)
      if (out) process.stdout.write(JSON.stringify(out) + '\n')
    }
  })
}

serve()
