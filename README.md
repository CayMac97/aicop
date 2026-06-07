<img width="570" height="633" alt="image" src="https://github.com/user-attachments/assets/51c4cb3b-1c16-4db6-88a5-57580b626b85" />
# 🛡 AICop

**Your AI wrote bugs. AICop finds them.
npx aicop scan .**  

Catch security vulnerabilities, AI code smells, and tech debt — before you ship to production.

```bash
npm install -g aicop
aicop scan ./src
```

> Works with any JS/TS project. No config required to get started.

---

## 🆚 AICop vs. Vibecop

Mit Version 1.0.9 vollzieht AICop den Schritt von einem starren Scanner zu einem transparenten Analyse-Tool für KI-generierten JavaScript/TypeScript-Code. Während Konkurrenz-Tools wie *Vibecop* durch Python-Support und CI-native Features bei polyglotten Projekten punkten, fokussiert sich AICop auf tiefgreifende AST-Analysen (38+ Regeln), automatisierte Fix-Prompts und ein feingranulares Test-Environment-Handling. 

### Feature- & Genauigkeits-Vergleich

<div align="center">

| Metrik / Feature | aicop 1.0.8 (alt) | aicop 1.0.9 (aktuell) | vibecop 0.4.3 |
| :--- | :---: | :---: | :---: |
| **Aktive Regeln** | 38 | 38 | ~ 12 |
| **Testcode Findings (Accuracy)** | 4 | 4 | 3 |
| **Erkennung: Hardcoded Secrets** | 🟢 ✓ | 🟢 ✓ | 🟢 ✓ |
| **Erkennung: eval() usage** | 🟢 ✓ | 🟢 ✓ | 🟢 ✓ |
| **Erkennung: TODO-Stubs** | 🟢 ✓ (2x) | 🟢 ✓ (2x) | 🟡 ✓ (1x) |
| **Erkennung: SQL-Injection** | 🔴 ✗ | 🔴 ✗ | 🔴 ✗ |
| | | | |
| **Transparenz (`--explain`)** | 🔴 ✗ | 🟢 ✓ (Pattern + Confidence) | 🔴 ✗ |
| **Metrik-System** | 🟡 Aufgerundet (manipulierbar) | 🟢 Absolut (Math.floor, ehrlich) | 🔴 ✗ |
| **Test-File Handling** | 🔴 Blind ignoriert | 🟢 Konfigurierbare Overrides | 🔴 ✗ |
| **Benchmarking-Daten** | 🔴 Synthetisch | 🟢 Echter LLM-Output | - |
| | | | |
| **CLI Tools (Fix-Prompt, Badge)** | 🟢 ✓ | 🟢 ✓ (Verbessert) | 🔴 ✗ |
| **Diff Scanning / Baseline** | 🟢 ✓ | 🟢 ✓ | 🟡 Nur Diff |
| **CI/IDE Integration** | 🔴 ✗ | 🔴 ✗ | 🟢 SARIF & MCP Server |
| **Sprachen** | JS/TS | JS/TS | 🟢 JS/TS/Python |

</div>

### Architektonischer Radar-Vergleich

<div align="center">
  <svg width="400" height="400" viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg">
    <!-- Background Grid -->
    <polygon points="200,50 330,125 330,275 200,350 70,275 70,125" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1"/>
    <polygon points="200,80 304,140 304,260 200,320 96,260 96,140" fill="none" stroke="#cbd5e1" stroke-width="1" stroke-dasharray="4,4"/>
    <polygon points="200,110 278,155 278,245 200,290 122,245 122,155" fill="none" stroke="#cbd5e1" stroke-width="1" stroke-dasharray="4,4"/>
    <polygon points="200,140 252,170 252,230 200,260 148,230 148,170" fill="none" stroke="#cbd5e1" stroke-width="1" stroke-dasharray="4,4"/>
    <polygon points="200,170 226,185 226,215 200,230 174,215 174,185" fill="none" stroke="#cbd5e1" stroke-width="1" stroke-dasharray="4,4"/>
    
    <!-- Axes -->
    <line x1="200" y1="200" x2="200" y2="50" stroke="#94a3b8" stroke-width="1"/>
    <line x1="200" y1="200" x2="330" y2="125" stroke="#94a3b8" stroke-width="1"/>
    <line x1="200" y1="200" x2="330" y2="275" stroke="#94a3b8" stroke-width="1"/>
    <line x1="200" y1="200" x2="200" y2="350" stroke="#94a3b8" stroke-width="1"/>
    <line x1="200" y1="200" x2="70" y2="275" stroke="#94a3b8" stroke-width="1"/>
    <line x1="200" y1="200" x2="70" y2="125" stroke="#94a3b8" stroke-width="1"/>
    
    <!-- Axis Labels -->
    <text x="200" y="40" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="middle">Regel-Tiefe (AST)</text>
    <text x="345" y="125" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="start">Transparenz</text>
    <text x="345" y="280" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="start">Developer Exp.</text>
    <text x="200" y="370" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="middle">Sprach-Support</text>
    <text x="55" y="280" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="end">CI / IDE Integration</text>
    <text x="55" y="125" font-family="sans-serif" font-size="12" font-weight="bold" fill="#334155" text-anchor="end">Konfigurierbarkeit</text>

    <!-- Vibecop Data -->
    <polygon points="200,140 252,170 252,230 200,320 70,275 148,170" fill="rgba(234, 88, 12, 0.2)" stroke="#ea580c" stroke-width="2"/>
    <circle cx="200" cy="140" r="4" fill="#ea580c"/>
    <circle cx="252" cy="170" r="4" fill="#ea580c"/>
    <circle cx="252" cy="230" r="4" fill="#ea580c"/>
    <circle cx="200" cy="320" r="4" fill="#ea580c"/>
    <circle cx="70" cy="275" r="4" fill="#ea580c"/>
    <circle cx="148" cy="170" r="4" fill="#ea580c"/>

    <!-- AICop 1.0.9 Data -->
    <polygon points="200,50 330,125 330,275 200,260 122,245 96,140" fill="rgba(16, 185, 129, 0.4)" stroke="#10b981" stroke-width="2"/>
    <circle cx="200" cy="50" r="4" fill="#10b981"/>
    <circle cx="330" cy="125" r="4" fill="#10b981"/>
    <circle cx="330" cy="275" r="4" fill="#10b981"/>
    <circle cx="200" cy="260" r="4" fill="#10b981"/>
    <circle cx="122" cy="245" r="4" fill="#10b981"/>
    <circle cx="96" cy="140" r="4" fill="#10b981"/>

    <!-- Legend -->
    <rect x="250" y="350" width="12" height="12" fill="rgba(16, 185, 129, 0.4)" stroke="#10b981" stroke-width="2"/>
    <text x="270" y="361" font-family="sans-serif" font-size="12" fill="#334155">aicop 1.0.9</text>
    
    <rect x="250" y="370" width="12" height="12" fill="rgba(234, 88, 12, 0.2)" stroke="#ea580c" stroke-width="2"/>
    <text x="270" y="381" font-family="sans-serif" font-size="12" fill="#334155">vibecop 0.4.3</text>
  </svg>
</div>

### Wer sollte was nutzen?

* **Nutze AICop, wenn** du primär JavaScript/TypeScript verwendest, tiefe AST-Scans für AI-Smells brauchst und Code-Qualität durch den "AI Score" gamifizieren willst.
* **Nutze Vibecop, wenn** du polyglotte Projekte (Python/JS) hast und tiefe CI-Integration via SARIF oder MCP-Server benötigst.
* **Beide kombinieren?** Durchaus sinnvoll: AICop für tiefe Smell-Analysen lokal, Vibecop für CI/CD-Pipelines und Python-Repos.

---
## Table of Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [All Rules](#all-rules)
- [AIScore](#aiscore)
- [Configuration](#configuration)
- [Test-File Behaviour](#test-file-behaviour)
- [GitHub Actions](#github-actions)
- [VS Code Extension](#vs-code-extension)
- [Baseline Tracking](#baseline-tracking)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

AICop parses every `.ts`, `.tsx`, `.js`, `.jsx` file into a full AST and runs **35 detection rules**:

| Category | Count | What it catches |
|---|---|---|
| 🔒 Security | 15 | Hardcoded secrets, SQL/command injection, XSS, eval, JWT no expiry, CORS misconfig, SSRF, path traversal, weak crypto, ReDoS, prototype pollution, missing rate limits, open redirect, insecure deserialisation, XXE injection |
| 🤖 AI Smells | 11 | Hallucinated APIs, dead code, TODO stubs, copy-paste patterns, debug leftovers, mixed async, missing null checks, generic variable names, magic numbers, inconsistent error handling, AI confidence score |
| 🧹 Tech Debt | 6 | Cyclomatic complexity, function length, nesting depth, god files, hardcoded config, missing types |

Every scanned file gets an **AI Confidence Score** and every scan produces an overall **AIScore™** (0–100).

## Install

```bash
npm install -g aicop      # global install
npx aicop scan ./src      # one-off, no install needed
pnpm dlx aicop scan ./src # pnpm
```

Requires **Node.js ≥ 18**.

---

## Usage

```bash
aicop scan ./src                      # scan a directory
aicop scan ./src --severity error     # errors only
aicop scan ./src --format html        # HTML report
aicop scan ./src --output report.html # save to file
aicop diff main                       # only files changed since branch main
aicop scan ./src --ci                 # CI mode (exits 1 on any error)
aicop baseline save                   # save current score as baseline
aicop rules                           # list all available rules
aicop init                            # create .aicoprc.json config
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

## AIScore

The **AIScore™** is a 0–100 number that summarises the overall AI-smell and security risk of your codebase.

| Score | Label | Meaning |
|---|---|---|
| 0–20 | 🟢 Clean | Very few issues |
| 21–50 | 🟡 AI-touched | Some smells, review recommended |
| 51–80 | 🟠 Heavy AI smell | Significant rework needed |
| 81–100 | 🔴 Needs rewrite | Major security or quality problems |

> AIScore only considers `error` and `warn` findings. `info` findings don't affect it.

---

## Configuration

```bash
aicop init   # creates .aicoprc.json in the project root
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
    "minAIScore": 60
  }
}
```

All rule severities can be set to `"error"`, `"warn"`, `"info"`, or `"off"`.

Files larger than **500 KB** are automatically skipped.  
Minified files (`*.min.js`, `*.min.css`), chunk files, and vendor directories are excluded by default.

---

## Test-File Behaviour

AICop applies relaxed rules to test files (paths containing `test/`, `tests/`, `spec/`, `__tests__/`, or filenames ending in `.test.ts`, `.spec.js`, etc.):

| Rule | Normal files | Test files |
|---|---|---|
| `security/hardcoded-secrets` | `ERROR` | `WARN` — *"hardcoded secret in test file — use environment variables even in tests"* |
| `security/missing-rate-limit` | checked | **skipped** entirely |

---

## GitHub Actions

```yaml
# .github/workflows/aicop.yml
name: AICop

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: aicop/action@v1
        with:
          path: ./src
          severity: warn
```

Or inline without the Action:

```yaml
- run: npx aicop scan ./src --ci --severity warn
```

---

## VS Code Extension

The **AICop VS Code Extension** (`packages/vscode-extension`) adds real-time diagnostics directly in your editor:

- Underlines findings inline as you type
- Shows severity icons (🔴 error / ⚠️ warn / ℹ️ info) in the Problems panel
- Adds CodeLens above flagged functions with a quick-fix link
- Status bar indicator shows current file's AIScore
- Commands: `AICop: Scan Current File`, `AICop: Scan Entire Workspace`, `AICop: Clear All Diagnostics`

Install locally:
```bash
npm run package:extension    # builds a .vsix file
code --install-extension aicop-1.0.0.vsix
```

---

## Baseline Tracking

Track your codebase score over time:

```bash
aicop baseline save         # saves current AIScore as baseline
# ... fix things ...
aicop scan ./src            # output shows delta vs baseline (↑ or ↓)
```

The baseline is stored in `.aicop-baseline.json` (add this to git to share with your team).

---

## Project Structure

```
aicop.net/
├── packages/
│   ├── cli/                   # Main CLI package (published to npm as "aicop")
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
│   └── website/               # aicop.net landing page
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
 
 