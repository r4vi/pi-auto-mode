# pi-auto-mode

A pi package that re-implements the core of Claude Code's auto mode for pi.

It is modeled after [`lghupan/cc-automode`](https://github.com/lghupan/cc-automode):

- read-only tool allowlist fast path
- deterministic hard-deny checks for obviously unsafe actions
- two-stage classifier on every non-allowlisted tool call
- consecutive/total denial tracking
- auto-mode execution guidance injected into pi's system prompt
- denial history widget in the UI
- user override prompt on denials

## What it does

When enabled, the extension intercepts tool calls in pi:

1. `read`, `grep`, `find`, and `ls` are allowed immediately by default.
   - this allowlist is also extended from local Claude Code project settings in:
     - `.claude/settings.user.json`
     - `.claude/settings.json`
   - the extension reads `permissions.allow`, `permissions.allowedTools`, `allow`, and `allowedTools` arrays when present
2. obvious hard-deny patterns are blocked immediately:
   - shell profile writes
   - cron creation
   - TLS verification weakening
   - destructive deletes outside the workspace
   - SSH key injection
   - auto-mode self-modification
3. everything else is classified with a two-stage LLM check:
   - stage 1: cheap `YES` / `NO` filter
   - stage 2: full JSON decision with reasoning only if stage 1 flags the action
4. if a denial happens in interactive mode, pi asks you whether to:
   - block
   - allow once
   - disable auto mode and allow

## Install

### As a local package

From the directory containing this package:

```bash
pi install ./pi-auto-mode
```

### For one-off testing

```bash
pi -e ./pi-auto-mode/extensions/auto-mode.ts
```

## Usage

Once loaded, auto mode is enabled by default.

Commands:

```text
/auto-mode status
/auto-mode on
/auto-mode off
/auto-mode toggle
/auto-mode reset
/auto-mode reload
/auto-mode model
/auto-mode model github-copilot/gpt-5.4-mini
```

If no dedicated classifier model is configured, the extension prompts you to choose one when auto mode is enabled in interactive mode.

## UI additions

- footer status for auto mode state
- recent denial history widget below the editor
- interactive override prompt when a denial happens

## Configuration

### Claude project allowlist interoperability

pi-auto-mode merges Claude Code tool allowlists from two places into its own fast-path allowlist:

Project-local files:

- `.claude/settings.user.json`
- `.claude/settings.json`

Global user files:

- `~/.claude/settings.user.json`
- `~/.claude/settings.json`

Supported fields:

- `permissions.allow`
- `permissions.allowedTools`
- `allow`
- `allowedTools`

Examples recognized:

```json
{
  "permissions": {
    "allow": ["Bash(*)", "Read(*)", "Edit(src/**)"]
  }
}
```

Those entries are normalized to tool names for pi's allowlist fast path, so `Bash(*)` becomes `bash`, `Read(*)` becomes `read`, etc.

It does not walk parent directories. It only reads the current project directory plus the global `~/.claude` directory.

You can inspect the merged result with:

```text
/auto-mode status
```

## Configuration

Create either of these in the target project:

- `.pi/auto-mode.json`
- `auto-mode.json`

Start from [`auto-mode.example.json`](./auto-mode.example.json).

Example:

```json
{
  "enabled": true,
  "classifierModel": "github-copilot/gpt-5.4-mini",
  "failOpen": true,
  "maxConsecutiveDenials": 3,
  "maxTotalDenials": 20,
  "maxTranscriptLines": 60,
  "reasoningEffort": "high",
  "allowlistedTools": ["read", "grep", "find", "ls"],
  "environment": [
    "**Trusted repo**: this repository and its configured remotes",
    "**Trusted internal domains**: api.mycorp.internal, registry.mycorp.internal"
  ],
  "allowRules": [],
  "denyRules": []
}
```

### Notes

- `classifierModel` is optional. If omitted, the extension uses the current active pi model.
- For a cheap GitHub Copilot-backed classifier, `github-copilot/gpt-5.4-mini` is a good default.
- The extension currently fails open by default, matching the reference repo's behavior when the classifier is unavailable.

## Files

- `package.json` — pi package manifest
- `extensions/auto-mode.ts` — the extension
- `auto-mode.example.json` — starter config

## Known gaps vs official Claude Code auto mode

This package mirrors the open-source reference architecture, not Anthropic's private implementation.

Current differences:

- no server-side prompt-injection probe
- no provider-side caching optimizations beyond what the selected model/provider already does
- JSON parsing is used for stage 2 instead of a dedicated classifier tool call
- policy is project-config based rather than Claude hook config based

## Development

This package is intentionally dependency-light and relies on pi's extension runtime.
