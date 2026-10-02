import { expect, test } from 'claude-code/testing'
import { checkPosture } from '../hooks/lib/posture'

const GOOD_SEAT = { merged: { sandbox: { enabled: true }, disableSkillShellExecution: true }, policy: { prependPlugins: ['barmkin-mod@acme', 'sec-default@builtin'] } }

test('warns when not seated in managed prependPlugins at all', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('not seated in managed prependPlugins'))).toBe(true)
})

test('warns when sec-default is seated ahead of this plugin', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-mod@acme'] } },
    'barmkin-mod',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('does not warn about seating when this plugin is ahead of sec-default', () => {
  const warnings = checkPosture(
    { merged: { sandbox: { enabled: true }, disableSkillShellExecution: true }, policy: { prependPlugins: ['barmkin-mod@acme', 'sec-default@builtin'] } },
    'barmkin-mod',
    ['github'],
  )
  expect(warnings.some((w) => w.includes('not seated'))).toBe(false)
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(false)
})

test('warns on bypassPermissions default mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'bypassPermissions' } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(true)
})

test('does not warn on a non-bypass permission mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'default' } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(false)
})

test('warns when the sandbox is off or unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('sandbox'))).toBe(true)
  expect(checkPosture({ merged: { sandbox: { enabled: false } }, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('sandbox'))).toBe(true)
})

test('does not warn when the sandbox is explicitly enabled', () => {
  const warnings = checkPosture({ merged: { sandbox: { enabled: true } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('sandbox'))).toBe(false)
})

test('warns when disableSkillShellExecution is unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('disableSkillShellExecution'))).toBe(true)
  expect(
    checkPosture({ merged: { disableSkillShellExecution: false }, policy: {} }, 'barmkin-mod', []).some((w) =>
      w.includes('disableSkillShellExecution'),
    ),
  ).toBe(true)
})

test('does not warn when disableSkillShellExecution is true', () => {
  const warnings = checkPosture({ merged: { disableSkillShellExecution: true }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('disableSkillShellExecution'))).toBe(false)
})

test('warns when the mcp server allowlist is empty', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(true)
})

test('does not warn when the mcp server allowlist is set', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', ['github', 'linear'])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(false)
})

test('a fully hardened posture produces no warnings', () => {
  const warnings = checkPosture(GOOD_SEAT, 'barmkin-mod', ['github'])
  expect(warnings).toEqual([])
})
