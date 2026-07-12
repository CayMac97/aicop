markdown


<img width="639" height="314" alt="image" src="https://github.com/user-attachments/assets/d2e0448f-62ca-43dc-a3f5-988625b6bfac" />
# 🛡 AICop
**Your AI wrote bugs. AICop finds them.**  
Catch security vulnerabilities, AI code smells, and tech debt — before you ship to production.
```bash
npm install -g aicop
aicop scan ./src
Works with any JS/TS project. No config required to get started.

🆚 AICop vs. Vibecop
With version 1.2.0, AICop cements its position as a highly specialized, ultra-fast analysis tool for AI-generated JavaScript/TypeScript code. While Vibecop shines as a highly polished, polyglot production tool with Python support and deep CI/CD integrations, AICop focuses deeply on raw AST analysis in the JS/TS ecosystem (41+ rules), cross-file injections, high-performance monorepo scaling, and automated AI fix-prompts.

Feature & Accuracy Comparison
Metric / Feature	aicop 1.2.0 (current)	vibecop 0.4.3
Focus	JS/TS AST Deep-Scans, AI-Smells	Polyglot, CI-Pipeline, Production-Tooling
Active Rules (JS/TS)	41	~ 12
Detection: Hardcoded Secrets	🟢 ✓	🟢 ✓
Detection: eval() usage	🟢 ✓	🟢 ✓
Detection: TODO-Stubs	🟢 ✓ (2x)	🟡 ✓ (1x)
Detection: Cross-File SQL-Injection	🟢 ✓	🔴 ✗
Transparency (--explain)	🟢 ✓ (Pattern + Confidence)	🔴 ✗
Scoring System	🟢 Absolute (Math.floor, honest)	🔴 ✗
Test-File Handling	🟢 Configurable Overrides	🔴 ✗
Agent / MCP Integration	🟢 ✓	🟢 ✓
CLI Tools (Fix-Prompt, Baseline)	🟢 ✓	🔴 ✗
Languages	JS/TS	🟢 JS/TS/Python
Who should use what?
Use Vibecop if you need a production-ready, polyglot tool for broad projects with native CI pipeline integrations.
Use AICop if you want dedicated, incredibly deep focus on JS/TS security, cross-file injections, AI-specific code smells, and lightning-fast monorepo scans.
Combine both? Absolutely. Use AICop locally or via agents for deep architectural smell analysis, and Vibecop in your CI/CD pipeline for broad coverage.
🤖 Agent & IDE Integration (Claude Code, Cursor, etc.)
AICop is built to work seamlessly with autonomous coding agents and modern AI workflows.

Model Context Protocol (MCP) Server
AICop includes a built-in MCP server, allowing agents like Claude Code, Cursor, or Windsurf to directly query the scanner and fix issues on the fly.

bash


# Start the MCP server for your agent
aicop mcp
Once connected, your agent can autonomously invoke AICop to scan the workspace and fix issues before finishing its task.

Auto-Fix Prompts
If you don't use MCP, you can still let your AI fix the code automatically by generating an actionable prompt containing the exact AST violations:

bash


aicop fix-prompt ./src > fix-instructions.txt
Copy and paste fix-instructions.txt into ChatGPT or Claude. The AI will receive the exact context and rewrite the files to fix all security and smell issues perfectly.

⚡️ Massive Monorepo Support (New in v1.2.0)
As of version 1.2.0, AICop features an advanced on-demand AST parser with a per-worker LRU cache. It guarantees a flat O(1) memory footprint (~80 MB per worker thread) regardless of your project's size. It effortlessly distributes the workload across all available CPU cores, scanning thousands of files in mere seconds without Out-Of-Memory (OOM) crashes.

Table of Contents
What it does
Install
Usage
All Rules
AIScore
Configuration
Test-File Behaviour
GitHub Actions
VS Code Extension
Baseline Tracking
Contributing
License
What it does
AICop parses every .ts, .tsx, .js, .jsx file into a full AST and runs 41 detection rules:

Category	Count	What it catches
🔒 Security	23	Hardcoded secrets, SQL/command/prompt injection, XSS, eval, JWT no expiry, CORS misconfig, SSRF, path traversal, weak crypto, ReDoS, prototype pollution, missing rate limits, open redirect, insecure deserialisation, XXE injection, Next.js input validation, CSRF missing, insecure session, NoSQL injection
🤖 AI Smells	12	Hallucinated APIs, Next.js client/server confusion, dead code, TODO stubs, copy-paste patterns, debug leftovers, mixed async, missing null checks, generic variable names, magic numbers, inconsistent error handling, AI confidence score
🧹 Tech Debt	6	Cyclomatic complexity, function length, nesting depth, god files, hardcoded config, missing types
Every scanned file gets an AI Confidence Score and every scan produces an overall AIScore™ (0–100).

Install
bash


npm install -g aicop      # global install
npx aicop scan ./src      # one-off, no install needed
pnpm dlx aicop scan ./src # pnpm
Requires Node.js ≥ 20.

Usage
bash


aicop scan ./src                      # scan a directory
aicop scan ./src --severity error     # errors only
aicop scan ./src --format html        # HTML report
aicop scan ./src --output report.html # save to file
aicop diff main                       # only files changed since branch main
aicop scan ./src --ci                 # CI mode (exits 1 on any error)
aicop baseline save                   # save current score as baseline
aicop rules                           # list all available rules
aicop init                            # create .aicoprc.json config
CLI Options
Flag	Default	Description
--severity	info	Minimum severity to report: error, warn, info
--format	terminal	Output format: terminal, html, json
--output	—	Write report to a file path
--ci	—	No colours, exits 1 on any error finding
--rule	—	Run only one specific rule ID
--ignore	—	Extra glob patterns to exclude
--config	—	Path to a custom config file
All Rules
🔒 Security Rules
Rule ID	Severity	What it detects
security/hardcoded-secrets	error	Passwords, tokens, API keys embedded in code
security/sql-injection	error	String-concatenated SQL queries
security/nosql-injection	error	MongoDB queries built from unsanitised req.body, req.query, or req.params
security/xss-vulnerabilities	error	Unsanitised innerHTML, document.write, React dangerouslySetInnerHTML
security/eval-usage	error	Direct eval() calls with non-literal arguments
security/code-injection	error	vm.runInNewContext, vm.runInThisContext, math.eval / mathjs.evaluate with dynamic input
security/command-injection	error	exec, execSync, spawn with string-concatenated arguments
security/jwt-no-expiry	error	JWTs signed without an expiresIn option
security/cors-misconfiguration	warn	CORS origin: '*' or origin: true on an authenticated route
security/ssrf-risk	warn	HTTP requests built from user-controlled URLs
security/path-traversal	error	fs calls with unsanitised user input in file paths
security/weak-crypto	warn	MD5, SHA1, DES, RC4 algorithms
security/regex-dos	warn	Regex patterns vulnerable to catastrophic backtracking (ReDoS)
security/prototype-pollution	error	Unsafe Object.assign(obj, userInput), merge() with untrusted data
security/missing-rate-limit	warn	Express auth routes (/login, /register, etc.) without rate-limit middleware
security/open-redirect	warn	res.redirect() with unvalidated user input
security/insecure-deserialization	error	JSON.parse, eval, serialize-javascript on untrusted input without validation
security/xxe-injection	error	XML parsers with external entity processing enabled
security/prompt-injection	error	Detects unfiltered user input passed directly to AI SDKs
security/nextjs-missing-input-validation	warn	Server Actions and Route Handlers should validate input using a schema library (e.g. Zod)
🤖 AI Smell Rules
Rule ID	Severity	What it detects
ai-smell/hallucinated-api-calls	error	Calls to npm packages that do not exist
ai-smell/nextjs-client-server-confusion	warn	Detects client-side hooks or browser globals in Next.js files missing "use client"
ai-smell/dead-code-blocks	warn	Unreachable code after return/throw/break
ai-smell/todo-stub-functions	warn	Functions whose body is only a TODO comment or throws "Not implemented"
ai-smell/copy-paste-patterns	warn	Identical or near-identical code blocks (structural duplication)
ai-smell/debug-leftovers	warn	console.log, debugger, console.debug left in non-test code
ai-smell/mixed-async-patterns	warn	Mixing async/await and .then()/.catch() chains in the same function
ai-smell/missing-null-checks	warn	Dereferencing nullable values without a guard
ai-smell/generic-variable-names	info	Single-letter or overly generic names (data, temp, obj, result)
ai-smell/magic-numbers	info	Unexplained numeric literals (not 0, 1, -1, 100)
ai-smell/inconsistent-error-handling	warn	Mixing throw, return null, return { error } patterns in the same file
ai-smell/ai-confidence-scorer	info	Per-file AI confidence score based on accumulated smell signals
🧹 Tech Debt Rules
Rule ID	Severity	What it detects
tech-debt/cyclomatic-complexity	warn	Functions with cyclomatic complexity > 10
tech-debt/function-length	warn	Functions longer than 60 lines
tech-debt/nesting-depth	warn	Code nested deeper than 4 levels
tech-debt/god-files	warn	Files with more than 500 lines of code
tech-debt/hardcoded-config	info	Magic strings that look like environment config (URLs, ports, hostnames)
tech-debt/missing-types	info	TypeScript any, untyped function parameters or return values
AIScore
The AIScore™ is a 0–100 number that summarises the overall AI-smell and security risk of your codebase.

Score	Label	Meaning
0–20	🟢 Clean	Very few issues
21–50	🟡 AI-touched	Some smells, review recommended
51–80	🟠 Heavy AI smell	Significant rework needed
81–100	🔴 Needs rewrite	Major security or quality problems
AIScore only considers error and warn findings. info findings don't affect it.

Configuration
bash


aicop init   # creates .aicoprc.json in the project root
json


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
All rule severities can be set to "error", "warn", "info", or "off".

Files larger than 500 KB are automatically skipped.
Minified files (*.min.js, *.min.css), chunk files, and vendor directories are excluded by default.

Test-File Behaviour
AICop applies relaxed rules to test files (paths containing test/, tests/, spec/, __tests__/, or filenames ending in .test.ts, .spec.js, etc.):

Rule	Normal files	Test files
security/hardcoded-secrets	ERROR	WARN — "hardcoded secret in test file — use environment variables even in tests"
security/missing-rate-limit	checked	skipped entirely
GitHub Actions
yaml


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
Or inline without the Action:

yaml


- run: npx aicop scan ./src --ci --severity warn
VS Code Extension
The AICop VS Code Extension (packages/vscode-extension) adds real-time diagnostics directly in your editor:

Underlines findings inline as you type
Shows severity icons (🔴 error / ⚠️ warn / ℹ️ info) in the Problems panel
Adds CodeLens above flagged functions with a quick-fix link
Status bar indicator shows current file's AIScore
Commands: AICop: Scan Current File, AICop: Scan Entire Workspace, AICop: Clear All Diagnostics
Install locally:

bash


npm run package:extension    # builds a .vsix file
code --install-extension aicop-1.0.0.vsix
Baseline Tracking
Track your codebase score over time:

bash


aicop baseline save         # saves current AIScore as baseline
# ... fix things ...
aicop scan ./src            # output shows delta vs baseline (↑ or ↓)
The baseline is stored in .aicop-baseline.json (add this to git to share with your team).

Project Structure


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
Contributing
Fork this repo
npm install at the root (uses npm workspaces)
npm run build to compile the CLI
npm test to run the 19 smoke tests
Add your rule in packages/cli/src/scanner/rules/<category>/your-rule.ts
Register it in packages/cli/src/scanner/rules/index.ts
Add a test fixture in packages/cli/tests/fixtures/
Open a PR
License
MIT — free forever. Your code never leaves your machine.
