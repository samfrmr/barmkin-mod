import { expect, test } from 'claude-code/testing'
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactText, containsAnySecret } from '../hooks/lib/redaction'

test('redacts every example vector with a numbered placeholder', () => {
  // Each rule is checked against its own example in isolation. Running the
  // full rule set here would be order-dependent: e.g. bearer-header's
  // example also matches jwt (which runs first), so jwt's placeholder
  // would consume the match before bearer-header's own pattern ever saw
  // it. That's correct redaction behavior (the secret still gets caught),
  // just not what this test is checking rule-by-rule.
  for (const rule of REDACTION_RULES) {
    const { text, redactedCount, categories } = redactText(rule.example, [rule], {})
    expect(redactedCount > 0).toBe(true)
    expect(text).toMatch(new RegExp('\\[REDACTED:' + rule.category + '#\\d+\\]'))
    expect(categories).toContain(rule.category)
  }
})

test('every example vector is caught somewhere by the full rule set', () => {
  // The ordering-sensitivity above is fine as long as the full set never
  // lets an example vector through unredacted.
  for (const rule of REDACTION_RULES) {
    const { redactedCount } = redactText(rule.example, REDACTION_RULES, {})
    expect(redactedCount > 0).toBe(true)
  }
})

test('numbers placeholders per category across repeated calls', () => {
  const counters: Record<string, number> = {}
  const first = redactText('key one: AKIAIOSFODNN7EXAMPLE', REDACTION_RULES, counters)
  const second = redactText('key two: AKIAIOSFODNN7EXAMPLF', REDACTION_RULES, counters)
  expect(first.text).toContain('[REDACTED:aws-key#1]')
  expect(second.text).toContain('[REDACTED:aws-key#2]')
})

test('leaves ordinary text untouched', () => {
  const { text, redactedCount } = redactText('ls -la /tmp', REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe('ls -la /tmp')
})

test('containsAnySecret is safe to call repeatedly (no stale regex lastIndex)', () => {
  const withSecret = 'token: ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII'
  expect(containsAnySecret(withSecret, REDACTION_RULES)).toBe(true)
  expect(containsAnySecret(withSecret, REDACTION_RULES)).toBe(true)
  expect(containsAnySecret('nothing to see here', REDACTION_RULES)).toBe(false)
})

test('leaves ordinary source and prose that mention keys or Bearer unchanged', () => {
  const source = [
    "CACHE_KEY = 'user'",
    'PRIMARY_KEY = "id"',
    'SORT_KEY=name',
    'Clients use Bearer authentication for every request.',
    "headers['Authorization'] = 'Bearer ' + token",
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('still redacts real secret values assigned to *_KEY or sent as Bearer tokens', () => {
  const input = [
    'AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"',
    'Authorization: Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0',
  ].join('\n')
  const { text, redactedCount } = redactText(input, REDACTION_RULES, {})
  expect(redactedCount).toBe(3)
  expect(text).not.toContain('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
  expect(text).not.toContain('sk_live_4eC39HqLyjWDarjtT1zdp7dc')
  expect(text).not.toContain('9f8e7d6c5b4a39281706f5e4d3c2b1a0')
})

test('redacts the whole *_KEY value even when it contains punctuation', () => {
  const cases = [
    "SECRET_KEY = 'django-insecure-k3$9!x@7v#q2(w)0z+e8&r^t5u%y1i*o4p'",
    'DB_KEY=Xk9#mP2$vL8@qR4!wN7z',
    'API_KEY=f3b9c0d8a7e6152493ab',
    'CLIENT_SECRET="Zq8$w!Rk2@pL9#xV5^mN"',
  ]
  for (const line of cases) {
    const { text, redactedCount } = redactText(line, REDACTION_RULES, {})
    expect(redactedCount).toBe(1)
    expect(text).toBe('[REDACTED:env-key#1]')
  }
})

test('never redacts code expressions assigned to a *_KEY constant', () => {
  const source = [
    'CACHE_KEY = hashlib.sha256(data).hexdigest()',
    'SIGNING_KEY=settings.SECRET_KEY_V2_2024',
    'ENCRYPTION_KEY = base64.b64decode(os.environ["ENC"])',
    'const STORAGE_KEY = `app:v2:${userId}`;',
    "SESSION_KEY = 'prefix_2024_' + user_id",
    'DEPLOY_KEY=$DEPLOY_KEY_FROM_CI_2024',
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('redacts a secret literal on one line without touching its neighbours', () => {
  const input = "DEBUG = True\nSECRET_KEY = 'django-insecure-k3$9!x@7v#q2(w)0z+e8&r^t5u%y1i*o4p'\nCACHE_KEY = 'user'"
  const { text } = redactText(input, REDACTION_RULES, {})
  expect(text).toBe("DEBUG = True\n[REDACTED:env-key#1]\nCACHE_KEY = 'user'")
})
