// Secret-detection patterns. Shaped like barmkin's rules.yaml "Secrets"
// section (name/pattern/example) plus jev.go's pre-egress secretPatterns,
// unioned into one list. Kept here as TS literals rather than a parsed
// rules.yaml: mods have no file-system-relative config loading step and no
// YAML dependency, and barmkin-mod must stay decoupled from barmkin's repo
// (captain's intent: "keep this separate from barmkin"). When barmkin's
// rules.yaml secrets section changes, update this list by hand and re-check
// the `example` vectors in redaction.test.ts.
export interface RedactionRule {
  name: string
  // Must carry the "g" flag so redactText can replace every match.
  pattern: RegExp
  category: string
  example: string
}

export const REDACTION_RULES: RedactionRule[] = [
  {
    name: 'private-key-block',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    category: 'private-key',
    example: '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----',
  },
  {
    name: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    category: 'jwt',
    example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  },
  {
    name: 'anthropic-openai-key',
    pattern: /\b(sk|rk)-[A-Za-z0-9]{10,}\b/g,
    category: 'api-key',
    example: 'sk-ABCDEFGHIJ1234567890',
  },
  {
    name: 'github-token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
    category: 'github-token',
    example: 'ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII',
  },
  {
    name: 'aws-access-key',
    pattern: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
    category: 'aws-key',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'slack-token',
    pattern: /\bxox[bpras]-[A-Za-z0-9-]+/g,
    category: 'slack-token',
    example: 'xoxb-1234567890-abcdefghij',
  },
  {
    name: 'gitlab-token',
    pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
    category: 'gitlab-token',
    example: 'glpat-AAAAAAAAAAAAAAAAAAAA',
  },
  {
    name: 'generic-apikey-assignment',
    pattern: /\bapikey_[A-Za-z0-9]+\b/gi,
    category: 'api-key',
    example: 'apikey_1234567890abcdef',
  },
  {
    name: 'bearer-header',
    pattern: /\bBearer\s+(?=[A-Za-z0-9._~+\/-]*\d)[A-Za-z0-9._~+\/-]{20,}=*/gi,
    category: 'bearer-token',
    example: 'Bearer eyJhbGciOiJIUzI1NiJ9.abc.def',
  },
  // Only a bare literal counts, wherever it sits on the line: a quoted string
  // not followed by an operator or accessor, or a whole unquoted token with
  // no code syntax (calls, indexing, attribute access, template literals, a
  // leading $VAR reference or ${...} interpolation, quoted or not). Code
  // expressions assigned to a *_KEY constant are left alone, so a secret built
  // by code or containing those characters unquoted is a known gap.
  {
    name: 'generic-key-env-assignment',
    pattern:
      /\b[A-Z0-9_]*(?:_KEY|SECRET)[A-Z0-9_]*[ \t]*=[ \t]*(?:(['"])(?!\$)(?![^'"\s]*\$\{)(?=[^'"\s]*\d)[^'"\s]{16,}\1(?![ \t]*[-+*\/%.[(])|(?!\$)(?=[^\s'"`()[\]{}.;,]*\d)[^\s'"`()[\]{}.;,]{16,}(?![^\s;,'"]))/g,
    category: 'env-key',
    example: 'AWS_SECRET_KEY=abcdef0123456789',
  },
]
