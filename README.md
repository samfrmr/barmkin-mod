# 🏰  barmkin-session-guard  🏰

A security layer for Claude Code, packaged as a Claude Code mods plugin. It redacts secrets, tracks untrusted content, and blocks the tool calls that would let an injected instruction send your data somewhere.

> [!NOTE]
> barmkin-mod only ever tightens. Every hook adds a deny, withhold or warning on top of a decision someone else made. None of them can turn a deny into an allow.

## What it does

| Capability | What happens |
|---|---|
| **Secret redaction** | Tool results and outbound messages are scanned for private keys, JWTs and AWS, Anthropic, OpenAI, GitHub, Stripe, Slack, npm and other tokens. Matches are replaced with `[REDACTED:<category>#n]`. |
| **Untrusted-content taint** | Web fetches, MCP results, reads outside the working directory, peer messages and skill loads are screened for injection. A hit taints the session. |
| **Rule-of-Two egress gate** | Combines three conditions: **A** untrusted input, **B** sensitive access, **C** an outward effect. With A alone, each egress class keeps its own posture (warn or deny). With A and B, every class denies. |
| **MCP tool-poisoning guard** | Strips instruction-like sentences from MCP tool descriptions and enforces an optional server allowlist. |
| **Skill guards** | Denies skill inline shell (`` !`command` ``) while mediation applies, and screens skill bodies and the skill listing. |
| **Agent-to-agent firewall** | Screens inbound peer messages, blocks outbound messages that contain secrets, and refuses to spawn subagents while the session is tainted. |
| **Jev System One classifier** | An optional remote classifier that can only raise suspicion, never lower it. |
| **Invisible-text scrub** | Strips ANSI escapes, bidi overrides, zero-width characters and the Unicode Tags block from tool results, descriptions and messages. |

### Egress classes

The gate recognises these outward effects:

- Outward-effect shell commands: `git push`, `curl` with a body, `scp` to a host, a pipe to `sh`, and similar.
- Web fetches, since the URL is itself a channel.
- MCP write-class tools: names containing verbs such as `create`, `send`, `post`, `update` or `delete`.
- Skill loads.
- Writes to persistence surfaces: `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, CI workflows, git hooks, shell rc files, `~/.ssh` and `~/.local/bin`.

The classifier reads only the first 4,000 characters of a piece of content, after redaction. With Jev configured, untrusted content longer than that taints the session even when nothing in it looks like an injection, because the rest was never classified. This taint needs an explicit acknowledgement: a later message, `/clear` or compaction does not clear it, whatever `taint_clear` is set to, and only `/barmkin-mod-clear-taint` from a person does. Without Jev configured, the classifier is not claimed to have read anything, so length alone does not taint.

Sensitive access (leg B) is set when a call touches a secret path such as `~/.ssh`, `~/.aws`, `.env` or `.git-credentials`, when a redaction rule fires on a tool result, or when the classifier reports credentials in the content.

## Requirements

- Claude Code **2.1.287 or later**. The mod checks at session start and warns on older builds.
- Node 22 for validation and tests.

## Install

barmkin-mod is a Claude Code plugin. Point your Claude Code plugin install at this repository, then fill in the options below when prompted.

> [!IMPORTANT]
> For full coverage, seat the plugin in managed `prependPlugins`. Unseated, it cannot see skill text, `CLAUDE.md` or other prompt-assembly content. If `sec-default` is seated ahead of it, it still cannot see `skill.prompt`, `prompt.context` or `prompt.section`.

At session start the mod runs a posture self-check and emits one concise line per condition, naming the condition, why it matters and the fix. Each line is its own transcript row (`$.ui.status` holds a single line per plugin and cannot show several). It warns when:

- the plugin is not seated in managed `prependPlugins`,
- `permissions.defaultMode` is `bypassPermissions`,
- the Bash sandbox is off, which removes the OS-level egress floor,
- `disableSkillShellExecution` is unset, so skill inline shell bypasses every `tool.call` guard,
- `mcp_server_allowlist` is empty.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `jev_base_url` | empty | System One endpoint, OpenRouter or Vercel AI Gateway style. The mod POSTs to `{base_url}/v1/systemone`. Empty disables the classifier and falls back to pattern heuristics. |
| `jev_model` | `jev-1.13.0` | Pinned Jev model id. Must match the `jev-1.13` pattern. |
| `jev_api_key` | none | Bearer credential. Stored in secure credential storage and never logged. |
| `mcp_server_allowlist` | empty | Comma-separated MCP server names allowed to run tools. Empty allows all (audit only). |
| `taint_clear` | `human-origin` | `human-origin`: a person's prompt clears the taint. `sticky`: it holds until `/compact`, `/clear` or `/barmkin-mod-clear-taint`. |
| `sdk_prompts_clear_taint` | `false` | Let SDK prompts clear the taint. For headless lanes (`claude -p`, the Agent SDK) only. |

## Commands

| Command | Description |
|---|---|
| `/barmkin-mod-status` | Show taint, circuit-breaker state and the last classifier verdict. |
| `/barmkin-mod-clear-taint` | Clear the taint, only from a person's prompt. The only way to clear a taint for content past the classifier's 4,000-character window. |

A clear session shows one line directly beneath the mode-switcher line under the prompt: green `🏰 Barmkin session guard active` when Jev is configured and its classifier breaker is closed (this does not claim any request succeeded), or amber `🏰 Barmkin session guard degraded` when Jev is not configured or the breaker is open. A single red line above the prompt (`🚨 TAINTED: untrusted content active · 🚫 outbound actions may be restricted · 🧹 clear: …`) shows when the session is tainted, and names the clear path for the active `taint_clear` posture.

## Layout

```text
hooks/register.ts       hook wiring and all runtime ($) calls
hooks/lib/              pure, unit-tested logic
  redaction*.ts         secret rules and redaction
  linear-scanners.ts    linear-time scanners for the four rules whose regexes backtrack
  scanned-prefix.ts     the span-safe prefix shown for an oversize tool result
  taint.ts, egress.ts   injection screen, Rule-of-Two gate
  mcp-guard.ts          tool-description hardening
  skill-guard.ts        skill body and listing guards
  system-one-client.ts  classifier wire format
  posture.ts            posture checks
tests/                  one test file per lib module, plus integration
.claude-plugin/         plugin manifest and option schema
```

## Development

```sh
npm ci
npm run validate   # claude plugin validate --strict .
npm test           # claude plugin test
```

CI runs both on every push to `main` and on pull requests, alongside workflow tests, a gitleaks secret scan (`.gitleaks.toml`) and CodeQL. `@anthropic-ai/claude-code` is pinned in `package.json` to the version floor, so CI is the real verification surface.

Guarding hooks fail closed: if one errors, the action is denied or the content withheld. Advisory hooks, such as the HUD, fail open and leave the result unchanged.

## Limits

- The shell denylist can be evaded. Enable the Bash sandbox so its egress allowlist sits underneath it.
- Size limits. Every redaction rule runs in time linear in the text, so a tool result is scanned whole up to 256 KiB per string and 1 MiB per result. Past those limits:
  - A string over 256 KiB in a result that no injection screen covers (Bash, Grep, Glob, a Read inside the working directory) shows a scanned prefix of about 12 KiB, cut at a line or delimiter that no secret match crosses, followed by a note with the shown and total character counts and how to page: `Read` with `offset` and `limit`, or a narrower command. The hidden part is never shown and never matched, and invisible text anywhere in the string still counts toward the taint threshold. If no safe cut exists, the result is withheld.
  - A result whose strings together pass 1 MiB, and a Read image past about 190 KiB, are withheld, since a prefix of either is not useful.
- Untrusted content is withheld over 16 KiB, never cut: web fetches and searches, MCP results, reads outside the working directory, skill bodies, peer messages, your prompts and outbound messages. The classifier reads 4,000 characters of such content, so more text would be mostly unscreened. The withhold message says it is a size limit and tells Claude to fetch the content in smaller pieces rather than ask you.
- With Jev configured, the classifier sees only the first 4,000 characters of redacted content; longer content taints the session until acknowledged with `/barmkin-mod-clear-taint`.
- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.
