// $.state shape for barmkin-mod. Declared here so `claude plugin validate`
// can check hooks/register.ts against it (see plugin.json's "types" field).
declare module 'claude-code' {
  interface PluginState {
    'barmkin-mod': {
      // Untrusted-content taint (capability: taint + injection screen).
      // Set after WebFetch/WebSearch/mcp__*/out-of-cwd Read results score
      // above the injection threshold. Cleared on the next prompt a human sent (composer or bridge origin).
      tainted: boolean
      taintReason: string | null

      // Rule-of-Two tracker. Leg A is `tainted` above; leg C is evaluated
      // per call against the egress classes. Leg B (sensitive access) is set
      // when a secret path is named in a call, a tool result trips a
      // redaction rule, or content scores on the credential question. A
      // prompt a human sent clears A and B together.
      sensitiveAccess: boolean
      sensitiveReason: string | null

      // The last egress call the gate denied or warned on, for the status
      // surface.
      lastEgress: {
        tool: string
        classIds: string[]
        decision: 'deny' | 'warn'
        rule: string
        at: number
      } | null

      // Last Jev System One verdict, for the explanation surface (HUD band
      // and $.ui.notice under the permission dialog).
      lastVerdict: {
        toolUseId: string
        question: string
        probability: number
        decision: 'pass' | 'escalate' | 'deny'
        model: string
        at: number
      } | null

      // Warm breaker mirror (session-scoped). barmkin's own file breaker is
      // authoritative for the managed hook; this is only for the mod's own
      // classifier calls and the HUD's "semantic check unavailable" state.
      breakerOpenUntil: number
      breakerFailureCount: number

      // SAST findings pane state, keyed by tool_use_id of the edit that
      // produced them.
      sastFindingsByToolUse: Record<
        string,
        {
          path: string
          findings: Array<{
            ruleId: string
            severity: 'ERROR' | 'WARNING' | 'INFO'
            message: string
            line: number
          }>
          suppressed: boolean
        }
      >

      // True once no candidate semgrep binary (configured path, common
      // install locations, bare name) could be run this session. Drives the
      // findings pane's "semgrep not found / not runnable" notice so the
      // pane doesn't just render empty.
      semgrepUnavailable: boolean
    }
  }
}
