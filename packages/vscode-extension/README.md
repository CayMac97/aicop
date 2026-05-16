# VibeCop — AI Code Scanner

Detects security holes, AI-generated anti-patterns, and tech debt in JS/TS code — inline, as you work.

![VibeScore status bar](https://vibecop.net/assets/screenshot-statusbar.png)

---

## Features

- **38 rules** covering security, AI-smell, and tech-debt categories
- **Inline diagnostics** — squiggly lines and Problems panel entries
- **CodeLens annotations** — rule name and severity above each finding
- **VibeScore™** — overall code quality score (0–100) in the status bar
- **Generate AI Fix Prompt** — one click to get a ready-to-paste prompt for Claude, Cursor, or ChatGPT
- **Scan on save / open** — automatic, zero-config analysis

---

## Commands

| Command | Description |
|---|---|
| `VibeCop: Scan Current File` | Run all rules on the active file |
| `VibeCop: Scan Entire Workspace` | Scan every JS/TS file in the workspace |
| `VibeCop: Clear All Diagnostics` | Remove all VibeCop markers |
| `VibeCop: Generate AI Fix Prompt` | Create a fix prompt for the current file's findings |

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `vibecop.enabled` | `true` | Enable/disable VibeCop |
| `vibecop.scanOnSave` | `true` | Scan automatically on file save |
| `vibecop.scanOnOpen` | `true` | Scan automatically when a file is opened |
| `vibecop.minSeverity` | `"warn"` | Minimum severity to display (`info` / `warn` / `error`) |
| `vibecop.showVibeScore` | `true` | Show VibeScore™ in the status bar |
| `vibecop.excludePatterns` | `["node_modules/**", "dist/**", "build/**"]` | Glob patterns to exclude |

---

## VibeScore™

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

Search for **VibeCop** in the VS Code Extensions panel, or install via:

```
ext install vibecop.vibecop
```

---

## License

MIT — [vibecop.net](https://vibecop.net)
