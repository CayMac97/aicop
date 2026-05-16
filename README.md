# 🛡 VibeCop

**Your AI wrote bugs. VibeCop finds them.
npx vibecop scan .**  

Catch security vulnerabilities, AI code smells, and tech debt — before you ship to production.

```bash
npm install -g vibecop
vibecop scan ./src
```

> Works with any JS/TS project. No config required to get started.

## Table of Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [All Rules](#all-rules)
- [VibeScore](#vibescore)
- [Configuration](#configuration)
- [Test-File Behaviour](#test-file-behaviour)
- [GitHub Actions](#github-actions)
- [VS Code Extension](#vs-code-extension)
- [Baseline Tracking](#baseline-tracking)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

VibeCop parses every `.ts`, `.tsx`, `.js`, `.jsx` file into a full AST and runs **35 detection rules**:

| Category | Count | What it catches |
|---|---|---|
| 🔒 Security | 15 | Hardcoded secrets, SQL/command injection, XSS, eval, JWT no expiry, CORS misconfig, SSRF, path traversal, weak crypto, ReDoS, prototype pollution, missing rate limits, open redirect, insecure deserialisation, XXE injection |
| 🤖 AI Smells | 11 | Hallucinated APIs, dead code, TODO stubs, copy-paste patterns, debug leftovers, mixed async, missing null checks, generic variable names, magic numbers, inconsistent error handling, AI confidence score |
| 🧹 Tech Debt | 6 | Cyclomatic complexity, function length, nesting depth, god files, hardcoded config, missing types |

Every scanned file gets an **AI Confidence Score** and every scan produces an overall **VibeScore™** (0–100).

## Install

```bash
npm install -g vibecop      # global install
npx vibecop scan ./src      # one-off, no install needed
pnpm dlx vibecop scan ./src # pnpm
```

Requires **Node.js ≥ 18**.

---

## Usage

```bash
vibecop scan ./src                      # scan a directory
vibecop scan ./src --severity error     # errors only
vibecop scan ./src --format html        # HTML report
vibecop scan ./src --output report.html # save to file
vibecop diff main                       # only files changed since branch main
vibecop scan ./src --ci                 # CI mode (exits 1 on any error)
vibecop baseline save                   # save current score as baseline
vibecop rules                           # list all available rules
vibecop init                            # create .vibecoprc.json config
```

### CLI Options

| Flag | Default | Description |
|---|---|---|
| `--severity` | `info` | Minimum severity to report: `error`, `warn`, `info` |
| `--format` | `terminal` | Output format: `terminal`, `html`, `json` |
| `--output` | — | Write report to a file path |
| `--ci` | — | No colours, exits `1` on any `error` finding |
| `--rule` | — | Run only one specific rule ID |
| `--ignore` | — | Extra glob patterns to exclude |
| `--config` | — | Path to a custom config file |

---

## All Rules

### 🔒 Security Rules

| Rule ID | Severity | What it detects |
|---|---|---|
| `security/hardcoded-secrets` | error | Passwords, tokens, API keys embedded in code |
| `security/sql-injection` | error | String-concatenated SQL queries |
| `security/nosql-injection` | error | MongoDB queries built from unsanitised `req.body`, `req.query`, or `req.params` |
| `security/xss-vulnerabilities` | error | Unsanitised `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` |
| `security/eval-usage` | error | Direct `eval()` calls with non-literal arguments |
| `security/code-injection` | error | `vm.runInNewContext`, `vm.runInThisContext`, `math.eval` / `mathjs.evaluate` with dynamic input |
| `security/command-injection` | error | `exec`, `execSync`, `spawn` with string-concatenated arguments |
| `security/jwt-no-expiry` | error | JWTs signed without an `expiresIn` option |
| `security/cors-misconfiguration` | warn | CORS `origin: '*'` or `origin: true` on an authenticated route |
| `security/ssrf-risk` | warn | HTTP requests built from user-controlled URLs |
| `security/path-traversal` | error | `fs` calls with unsanitised user input in file paths |
| `security/weak-crypto` | warn | `MD5`, `SHA1`, `DES`, `RC4` algorithms |
| `security/regex-dos` | warn | Regex patterns vulnerable to catastrophic backtracking (ReDoS) |
| `security/prototype-pollution` | error | Unsafe `Object.assign(obj, userInput)`, `merge()` with untrusted data |
| `security/missing-rate-limit` | warn | Express auth routes (`/login`, `/register`, etc.) without rate-limit middleware |
| `security/open-redirect` | warn | `res.redirect()` with unvalidated user input |
| `security/insecure-deserialization` | error | `JSON.parse`, `eval`, `serialize-javascript` on untrusted input without validation |
| `security/xxe-injection` | error | XML parsers with external entity processing enabled |

### 🤖 AI Smell Rules

| Rule ID | Severity | What it detects |
|---|---|---|
| `ai-smell/hallucinated-api-calls` | error | Calls to npm packages that do not exist |
| `ai-smell/dead-code-blocks` | warn | Unreachable code after `return`/`throw`/`break` |
| `ai-smell/todo-stub-functions` | warn | Functions whose body is only a TODO comment or throws `"Not implemented"` |
| `ai-smell/copy-paste-patterns` | warn | Identical or near-identical code blocks (structural duplication) |
| `ai-smell/debug-leftovers` | warn | `console.log`, `debugger`, `console.debug` left in non-test code |
| `ai-smell/mixed-async-patterns` | warn | Mixing `async/await` and `.then()/.catch()` chains in the same function |
| `ai-smell/missing-null-checks` | warn | Dereferencing nullable values without a guard |
| `ai-smell/generic-variable-names` | info | Single-letter or overly generic names (`data`, `temp`, `obj`, `result`) |
| `ai-smell/magic-numbers` | info | Unexplained numeric literals (not `0`, `1`, `-1`, `100`) |
| `ai-smell/inconsistent-error-handling` | warn | Mixing `throw`, `return null`, `return { error }` patterns in the same file |
| `ai-smell/ai-confidence-scorer` | info | Per-file AI confidence score based on accumulated smell signals |

### 🧹 Tech Debt Rules

| Rule ID | Severity | What it detects |
|---|---|---|
| `tech-debt/cyclomatic-complexity` | warn | Functions with cyclomatic complexity > 10 |
| `tech-debt/function-length` | warn | Functions longer than 60 lines |
| `tech-debt/nesting-depth` | warn | Code nested deeper than 4 levels |
| `tech-debt/god-files` | warn | Files with more than 500 lines of code |
| `tech-debt/hardcoded-config` | info | Magic strings that look like environment config (URLs, ports, hostnames) |
| `tech-debt/missing-types` | info | TypeScript `any`, untyped function parameters or return values |

---

## VibeScore

The **VibeScore™** is a 0–100 number that summarises the overall AI-smell and security risk of your codebase.

| Score | Label | Meaning |
|---|---|---|
| 0–20 | 🟢 Clean | Very few issues |
| 21–50 | 🟡 AI-touched | Some smells, review recommended |
| 51–80 | 🟠 Heavy AI smell | Significant rework needed |
| 81–100 | 🔴 Needs rewrite | Major security or quality problems |

> VibeScore only considers `error` and `warn` findings. `info` findings don't affect it.

---

## Configuration

```bash
vibecop init   # creates .vibecoprc.json in the project root
```

```json
{
  "include": ["src/**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules", "dist", "build", "**/*.test.*"],
  "rules": {
    "security/hardcoded-secrets": "error",
    "ai-smell/magic-numbers": "off",
    "tech-debt/missing-types": "warn"
  },
  "thresholds": {
    "maxErrors": 0,
    "maxWarnings": 10,
    "minVibeScore": 60
  }
}
```

All rule severities can be set to `"error"`, `"warn"`, `"info"`, or `"off"`.

Files larger than **500 KB** are automatically skipped.  
Minified files (`*.min.js`, `*.min.css`), chunk files, and vendor directories are excluded by default.

---

## Test-File Behaviour

VibeCop applies relaxed rules to test files (paths containing `test/`, `tests/`, `spec/`, `__tests__/`, or filenames ending in `.test.ts`, `.spec.js`, etc.):

| Rule | Normal files | Test files |
|---|---|---|
| `security/hardcoded-secrets` | `ERROR` | `WARN` — *"hardcoded secret in test file — use environment variables even in tests"* |
| `security/missing-rate-limit` | checked | **skipped** entirely |

---

## GitHub Actions

```yaml
# .github/workflows/vibecop.yml
name: VibeCop

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: vibecop/action@v1
        with:
          path: ./src
          severity: warn
```

Or inline without the Action:

```yaml
- run: npx vibecop scan ./src --ci --severity warn
```

---

## VS Code Extension

The **VibeCop VS Code Extension** (`packages/vscode-extension`) adds real-time diagnostics directly in your editor:

- Underlines findings inline as you type
- Shows severity icons (🔴 error / ⚠️ warn / ℹ️ info) in the Problems panel
- Adds CodeLens above flagged functions with a quick-fix link
- Status bar indicator shows current file's VibeScore
- Commands: `VibeCop: Scan Current File`, `VibeCop: Scan Entire Workspace`, `VibeCop: Clear All Diagnostics`

Install locally:
```bash
npm run package:extension    # builds a .vsix file
code --install-extension vibecop-1.0.0.vsix
```

---

## Baseline Tracking

Track your codebase score over time:

```bash
vibecop baseline save         # saves current VibeScore as baseline
# ... fix things ...
vibecop scan ./src            # output shows delta vs baseline (↑ or ↓)
```

The baseline is stored in `.vibecopbaseline.json` (add this to git to share with your team).

---

## Project Structure

```
vibecop.net/
├── packages/
│   ├── cli/                   # Main CLI package (published to npm as "vibecop")
│   │   ├── src/
│   │   │   ├── scanner/       # AST walker + 35 detection rules
│   │   │   │   └── rules/
│   │   │   │       ├── security/    # 15 security rules
│   │   │   │       ├── ai-smells/   # 11 AI smell rules
│   │   │   │       └── tech-debt/   # 6 tech debt rules
│   │   │   ├── reporter/      # Terminal, HTML, and JSON reporters
│   │   │   ├── diff/          # Git diff integration
│   │   │   ├── fix-prompt/    # AI fix suggestion engine
│   │   │   └── config/        # Config loading and defaults
│   │   └── tests/             # Smoke tests + flagging fixtures
│   ├── vscode-extension/      # VS Code extension
│   └── website/               # vibecop.net landing page
└── action.yml                 # GitHub Action definition
```

---

## Contributing

1. Fork this repo
2. `npm install` at the root (uses npm workspaces)
3. `npm run build` to compile the CLI
4. `npm test` to run the 19 smoke tests
5. Add your rule in `packages/cli/src/scanner/rules/<category>/your-rule.ts`
6. Register it in `packages/cli/src/scanner/rules/index.ts`
7. Add a test fixture in `packages/cli/tests/fixtures/`
8. Open a PR

---

## License

MIT — free forever. Your code never leaves your machine.
