# 🛡 AICop

**AI code quality & security scanner for TypeScript and JavaScript.**

AICop scans your codebase for security vulnerabilities, AI-generated code smells, and tech debt — in one command, with no configuration required.

```
npm install -g aicop
aicop scan ./src
```

---

## Features

- **29 detection rules** across 3 categories: Security, AI Smells, Tech Debt
- **AIScore™** — per-file AI confidence score (0–100)
- **Interactive grouped output** — expand Errors / Warnings / Info on demand
- **HTML reports** — beautiful visual reports with `--format html`
- **CI-ready** — exits with code 1 on errors, structured JSON output
- **Zero config** — works out of the box on any TypeScript or JavaScript project
- **Runs locally** — your code never leaves your machine

---

## Install

```bash
# Global install (recommended)
npm install -g aicop

# Or run without installing
npx aicop scan ./src

# pnpm
pnpm dlx aicop scan ./src
```

---

## Usage

```bash
# Scan current directory
aicop scan

# Scan a specific path
aicop scan ./src

# Only show errors (skip warnings and info)
aicop scan ./src --severity error

# Generate an HTML report
aicop scan ./src --format html

# Output JSON for programmatic use
aicop scan ./src --format json --output report.json

# Scan only files changed since main
aicop diff main

# Save current score as baseline (for tracking over time)
aicop baseline

# List all available rules
aicop rules

# Create a config file
aicop init
```

---

## Example output

```
✔ Scanned 47 files in 312ms

  ┌────────────────────────────────────────┐
  │  🔴 Errors:      3  (must fix)         │
  │  🟡 Warnings:   11  (should fix)       │
  │  🔵 Info:        5  (consider fixing)  │
  │  AIScore™: 67/100  — "AI-touched"   │
  └────────────────────────────────────────┘

  ● Errors       (3)  — press E to expand
  ● Warnings    (11)  — press W to expand
  ● Info         (5)  — press I to expand

  [E]rrors  [W]arnings  [I]nfo  [Q]uit  ›
```

---

## Rules

### Security (12 rules)

| Rule | Default |
|---|---|
| `security/hardcoded-secrets` | error |
| `security/sql-injection` | error |
| `security/xss-vulnerabilities` | error |
| `security/eval-usage` | error |
| `security/jwt-no-expiry` | error |
| `security/cors-misconfiguration` | error |
| `security/prototype-pollution` | error |
| `security/ssrf-risk` | error |
| `security/path-traversal` | error |
| `security/weak-crypto` | error |
| `security/missing-rate-limit` | warn |
| `security/regex-dos` | warn |

### AI Smells (11 rules)

| Rule | Default |
|---|---|
| `ai-smell/hallucinated-api-calls` | error |
| `ai-smell/dead-code-blocks` | warn |
| `ai-smell/todo-stub-functions` | warn |
| `ai-smell/copy-paste-patterns` | warn |
| `ai-smell/missing-null-checks` | warn |
| `ai-smell/mixed-async-patterns` | warn |
| `ai-smell/inconsistent-error-handling` | warn |
| `ai-smell/debug-leftovers` | info |
| `ai-smell/magic-numbers` | info |
| `ai-smell/generic-variable-names` | info |
| `ai-smell/ai-confidence-scorer` | info |

### Tech Debt (6 rules)

| Rule | Default |
|---|---|
| `tech-debt/cyclomatic-complexity` | warn |
| `tech-debt/function-length` | warn |
| `tech-debt/nesting-depth` | warn |
| `tech-debt/god-files` | warn |
| `tech-debt/hardcoded-config` | warn |
| `tech-debt/missing-types` | warn |

---

## Configuration

Run `aicop init` to create a `.aicoprc.json` in your project root:

```json
{
  "version": "1",
  "include": ["src/**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules/**", "dist/**"],
  "rules": {
    "security/hardcoded-secrets": "error",
    "ai-smell/magic-numbers": "off",
    "tech-debt/function-length": "warn"
  },
  "thresholds": {
    "maxErrors": 0,
    "maxWarnings": 20,
    "minAIScore": 50
  }
}
```

---

## CI / CD

```yaml
# .github/workflows/aicop.yml
- name: AICop scan
  uses: aicop/action@v1
  with:
    path: ./src
    severity: error
```

Or without the action:

```yaml
- name: AICop scan
  run: npx aicop scan ./src --ci --format json --output aicop-report.json
```

Exit code is `1` if any `error`-severity findings are found — automatically fails the build.

---

## AIScore™

Each file gets a score from 0–100 based on the weighted sum of AI smell signals:

| Score | Label |
|---|---|
| 0–20 | Clean |
| 21–40 | AI-assisted |
| 41–60 | AI-touched |
| 61–80 | Heavy AI smell |
| 81–100 | Needs rewrite |

---

## License

MIT © AICop
