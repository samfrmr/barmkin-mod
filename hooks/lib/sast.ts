// Pure parsing/formatting/resolution for the SAST UI. register.ts runs
// semgrep with $.process.run and hands the raw stdout to parseSemgrepJson.

export interface SemgrepFinding {
  ruleId: string
  severity: 'ERROR' | 'WARNING' | 'INFO'
  message: string
  path: string
  line: number
}

interface SemgrepRawResult {
  check_id?: unknown
  path?: unknown
  start?: { line?: unknown }
  extra?: { severity?: unknown; message?: unknown }
}

export function parseSemgrepJson(raw: string): SemgrepFinding[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (typeof parsed !== 'object' || parsed === null) return []
  const results = (parsed as { results?: unknown }).results
  if (!Array.isArray(results)) return []

  const findings: SemgrepFinding[] = []
  for (const r of results as SemgrepRawResult[]) {
    const ruleId = typeof r.check_id === 'string' ? r.check_id : 'unknown-rule'
    const path = typeof r.path === 'string' ? r.path : ''
    const line = typeof r.start?.line === 'number' ? r.start.line : 0
    const message = typeof r.extra?.message === 'string' ? r.extra.message : ''
    const rawSeverity = typeof r.extra?.severity === 'string' ? r.extra.severity.toUpperCase() : 'INFO'
    const severity: SemgrepFinding['severity'] =
      rawSeverity === 'ERROR' ? 'ERROR' : rawSeverity === 'WARNING' ? 'WARNING' : 'INFO'
    findings.push({ ruleId, severity, message, path, line })
  }
  return findings
}

const SEVERITY_RANK: Record<SemgrepFinding['severity'], number> = { ERROR: 2, WARNING: 1, INFO: 0 }

export function worstSeverity(findings: SemgrepFinding[]): SemgrepFinding['severity'] | null {
  if (findings.length === 0) return null
  return findings.reduce<SemgrepFinding['severity']>(
    (worst, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst] ? f.severity : worst),
    'INFO',
  )
}

export function formatFindingsContext(findings: SemgrepFinding[]): string {
  if (findings.length === 0) return ''
  const lines = findings.map(
    (f) => `- [${f.severity}] ${f.ruleId} at ${f.path}:${f.line}: ${f.message}`,
  )
  return `semgrep found ${findings.length} issue(s) in this edit:\n${lines.join('\n')}`
}

// Candidate semgrep binaries to try, in order, when the `sast_semgrep_path`
// option is unset. Plain `semgrep` only resolves through whatever PATH the
// host process itself was started with, which routinely omits per-user
// install locations like `~/.local/bin` (pipx/`pip install --user`) even
// though the user's own interactive shell sees them -- hence `homeDir`
// first, then common package-manager prefixes, with bare `semgrep` last as
// the pre-existing fallback.
export function buildSemgrepCandidates(homeDir: string): string[] {
  const candidates: string[] = []
  const home = homeDir.trim().replace(/\/+$/, '')
  if (home) candidates.push(home + '/.local/bin/semgrep')
  candidates.push(
    '/usr/local/bin/semgrep',
    '/opt/homebrew/bin/semgrep',
    '/home/linuxbrew/.linuxbrew/bin/semgrep',
    '/usr/bin/semgrep',
    'semgrep',
  )
  return candidates
}
