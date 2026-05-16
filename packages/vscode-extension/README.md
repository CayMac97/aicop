# AICop — AI Code Scanner

Detects security holes, AI-generated anti-patterns, and tech debt in JS/TS code — inline, as you work.

![AIScore status bar](https://aicop.net/assets/screenshot-statusbar.png)

---

## Features

- **38 rules** covering security, AI-smell, and tech-debt categories
- **Inline diagnostics** — squiggly lines and Problems panel entries
- **CodeLens annotations** — rule name and severity above each finding
- **AIScore™** — overall code quality score (0–100) in the status bar
- **Generate AI Fix Prompt** — one click to get a ready-to-paste prompt for Claude, Cursor, or ChatGPT
- **Scan on save / open** — automatic, zero-config analysis

---

## Commands

| Command | Description |
|---|---|
| `AICop: Scan Current File` | Run all rules on the active file |
| `AICop: Scan Entire Workspace` | Scan every JS/TS file in the workspace |
| `AICop: Clear All Diagnostics` | Remove all AICop markers |
| `AICop: Generate AI Fix Prompt` | Create a fix prompt for the current file's findings |

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `aicop.enabled` | `true` | Enable/disable AICop |
| `aicop.scanOnSave` | `true` | Scan automatically on file save |
| `aicop.scanOnOpen` | `true` | Scan automatically when a file is opened |
| `aicop.minSeverity` | `"warn"` | Minimum severity to display (`info` / `warn` / `error`) |
| `aicop.showAIScore` | `true` | Show AIScore™ in the status bar |
| `aicop.excludePatterns` | `["node_modules/**", "dist/**", "build/**"]` | Glob patterns to exclude |

---

## AIScore™

The status bar shows your current file or workspace score:

| Score | Color | Meaning |
|---|---|---|
| 90–100 | Default | Clean |
| 60–89 | Yellow | Needs attention |
| 0–59 | Red | Significant issues |

---

## Rules

### Security
`hardcoded-secrets` · `sql-injection` · `xss-vulnerabilities` · `command-injection` · `code-injection` · `path-traversal` · `open-redirect` · `cors-misconfiguration` · `weak-crypto` · `jwt-no-expiry` · `regex-dos` · `missing-rate-limit` · `csrf-missing`

### AI Smells
`inconsistent-error-handling` · `missing-null-checks` · `mixed-async-patterns` · `todo-stub-functions`

### Tech Debt
`cyclomatic-complexity` · `god-files` · `hardcoded-config` · `nesting-depth`

---

## Installation

Search for **AICop** in the VS Code Extensions panel, or install via:

```
ext install aicop.aicop
```

---

## License

MIT — [aicop.net](https://aicop.net)
