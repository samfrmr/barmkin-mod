// Pure helpers for the session.start posture self-check (R16; security
// review F4 and the C1/C5 default-posture calls). Takes already-read
// settings objects and this plugin's own manifest name so it can be unit
// tested without a live $.settings.read() call.

// `prependPlugins`/`appendPlugins` are a managed/policy-only construct (see
// sec-default's own README): a person's settings can't set or override
// them, so seating is checked against the policy-source settings alone.
// The other checks (sandbox, permissions, disableSkillShellExecution) apply
// from whatever source set them, so those are checked against the merged
// settings `$.settings.read()` already returns.
export interface PostureSettings {
  merged: Record<string, unknown>
  policy: Record<string, unknown>
}

function pluginIdName(id: string): string {
  return id.split('@')[0] ?? id
}

export function checkPosture(settings: PostureSettings, pluginName: string, mcpAllowlist: readonly string[]): string[] {
  const warnings: string[] = []

  const rawPrepend = settings.policy.prependPlugins
  const prependPlugins = Array.isArray(rawPrepend) ? rawPrepend.filter((v): v is string => typeof v === 'string') : null

  const ourIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === pluginName) : -1
  const secDefaultIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === 'sec-default') : -1

  if (prependPlugins === null || ourIndex === -1) {
    warnings.push(
      pluginName +
        ' is not seated in managed prependPlugins: skill text, CLAUDE.md and other prompt-assembly content stay out of its reach (README "Seat requirements").',
    )
  } else if (secDefaultIndex !== -1 && secDefaultIndex < ourIndex) {
    warnings.push(
      'sec-default is seated ahead of ' +
        pluginName +
        ' in prependPlugins: it still cannot see skill.prompt, prompt.context or prompt.section (README "Seat requirements").',
    )
  }

  const permissions = settings.merged.permissions
  const defaultMode =
    permissions && typeof permissions === 'object' && !Array.isArray(permissions)
      ? (permissions as Record<string, unknown>).defaultMode
      : undefined
  if (defaultMode === 'bypassPermissions') {
    warnings.push('permissions.defaultMode is "bypassPermissions": every tool.check-mediated prompt is skipped.')
  }

  const sandbox = settings.merged.sandbox
  const sandboxEnabled =
    sandbox && typeof sandbox === 'object' && !Array.isArray(sandbox) ? (sandbox as Record<string, unknown>).enabled : undefined
  if (sandboxEnabled !== true) {
    warnings.push('the Bash sandbox is off (sandbox.enabled is not true): no OS-level egress floor backs this mod\'s taint-gated denies.')
  }

  if (settings.merged.disableSkillShellExecution !== true) {
    warnings.push(
      'disableSkillShellExecution is unset: a skill\'s inline shell (`!`command``) still bypasses every tool.call-based guard this mod has.',
    )
  }

  if (mcpAllowlist.length === 0) {
    warnings.push('mcp_server_allowlist is empty: every MCP server is allowed to run tools (audit-only, not enforced).')
  }

  return warnings
}
