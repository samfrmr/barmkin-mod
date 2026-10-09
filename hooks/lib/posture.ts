// Pure helpers for the session.start posture self-check: seating in managed
// prependPlugins, plus the sandbox, permission-mode, skill-shell and MCP
// allowlist defaults. Takes already-read settings objects and this plugin's
// own manifest name so it can be unit tested without a live $.settings.read()
// call.

// `prependPlugins`/`appendPlugins` are a managed/policy-only construct (see
// sec-default's own README): a person's settings can't set or override
// them, so seating is checked against the policy-source settings alone.
// The other checks (sandbox, permissions, disableSkillShellExecution) apply
// from whatever source set them, so those are checked against the merged
// settings `$.settings.read()` already returns. A null side means that read
// failed, and the checks it feeds are reported as unverified rather than
// silently passing or dropped.
export interface PostureSettings {
  merged: Record<string, unknown> | null
  policy: Record<string, unknown> | null
}

function pluginIdName(id: string): string {
  return id.split('@')[0] ?? id
}

export function checkPosture(settings: PostureSettings, pluginName: string, mcpAllowlist: readonly string[]): string[] {
  const warnings: string[] = []

  const rawPrepend = settings.policy?.prependPlugins
  const prependPlugins = Array.isArray(rawPrepend) ? rawPrepend.filter((v): v is string => typeof v === 'string') : null

  const ourIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === pluginName) : -1
  const secDefaultIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === 'sec-default') : -1

  if (settings.policy === null) {
    warnings.push('seating unverified: policy settings read failed.')
  } else if (prependPlugins === null || ourIndex === -1) {
    warnings.push(
      pluginName + ' is not in managed prependPlugins, so it cannot see skill text or CLAUDE.md: seat it (README "Seat requirements").',
    )
  } else if (secDefaultIndex !== -1 && secDefaultIndex < ourIndex) {
    warnings.push(
      'sec-default is seated ahead of ' + pluginName + ', hiding skill.prompt, prompt.context and prompt.section: seat ' + pluginName + ' first.',
    )
  }

  if (settings.merged === null) {
    warnings.push('sandbox, defaultMode and disableSkillShellExecution unverified: settings read failed.')
  } else {
    const merged = settings.merged
    const permissions = merged.permissions
    const defaultMode =
      permissions && typeof permissions === 'object' && !Array.isArray(permissions)
        ? (permissions as Record<string, unknown>).defaultMode
        : undefined
    if (defaultMode === 'bypassPermissions') {
      warnings.push('permissions.defaultMode is bypassPermissions, skipping every tool.check prompt: use default.')
    }

    const sandbox = merged.sandbox
    const sandboxEnabled =
      sandbox && typeof sandbox === 'object' && !Array.isArray(sandbox) ? (sandbox as Record<string, unknown>).enabled : undefined
    if (sandboxEnabled !== true) {
      warnings.push('Bash sandbox is off, so no OS egress floor backs taint-gated denies: set sandbox.enabled to true.')
    }

    if (merged.disableSkillShellExecution !== true) {
      warnings.push('disableSkillShellExecution is unset, so skill inline shell bypasses tool.call guards: set it to true.')
    }
  }

  if (mcpAllowlist.length === 0) {
    warnings.push('mcp_server_allowlist is empty, so any MCP server may run tools (audit-only): list trusted servers.')
  }

  return warnings
}
