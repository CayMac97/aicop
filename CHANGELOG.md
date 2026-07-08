# Changelog

All notable changes to this project will be documented in this file.

## [1.1.2] - 2026-07-08

### Fixed (Top 10 OSS Benchmark)
- **`prototype-pollution`**: Fixed false positives on safe `for...in` loops. The rule now correctly requires the iterated object to be user-controlled via the TaintTracker before flagging.
- **`nextjs-client-server-confusion`**: Fixed massive false positives by restricting the rule to execute only in Next.js `app/` directories instead of all `.tsx`/`.jsx` files.
- **`regex-dos`**: Fixed false positives on standard string-matching regexes by removing the overly aggressive and faulty `OVERLAPPING_ALTERNATION` check. The rule now strictly enforces `NESTED_QUANTIFIER` patterns.
- **`insecure-deserialization`**: Removed `serialize-javascript` from the unsafe packages list, as it is a safe serializer for preventing XSS, not a vulnerable deserializer.
- **Test File Exclusion**: Fixed a bug in `scan-file.ts` where test files were not ignored due to a faulty `matchBase: true` configuration in `picomatch`.

### Known Limitations
- **Prototype Pollution Taint Propagation**: The TaintTracker currently has a gap where it does not propagate taint through a `NewExpression` (e.g. `new Wrapper(userInput)`). As `prototype-pollution` now relies strictly on the TaintTracker, it may miss edge cases where a tainted object was instantiated via a constructor before being merged. (Tracked for v1.1.3).
- **Regex-DoS Overlapping Alternation**: By removing the `OVERLAPPING_ALTERNATION` regex to fix false positives, AICop currently loses detection for catastrophic overlapping alternations like `(a|a)+`. Detecting this cleanly requires a true Regex-AST parser, which is planned for a future release.

## [1.0.11] - 2026-06-22
- **CSRF Protection Detection** (`security/csrf-missing`): Erkennt Express-Apps mit POST-Routes ohne CSRF-Schutz. Intelligente Ausnahmen für JWT-only APIs (stateless), Webhook-Routes und HTTP-Client-Calls.
- **Insecure Session Detection** (`security/insecure-session`): Prüft Session-Konfigurationen auf schwache Secrets (<20 Zeichen), httpOnly:false, secure:false und fehlende resave-Option. Unterstützt 7 Session-Packages (Express, Fastify, Koa).
- **JWT Unsafe Verify** (`security/jwt-unsafe-verify`): Erkennt `jwt.verify()`-Aufrufe deren Rückgabewert ignoriert wird. Nutzt Parent-Map-Tracking für präzise Erkennung. Callback-Style und try/catch-Pattern werden als sicher behandelt.
- **Phase-1 Cross-File Analysis**: Neuer Vorab-Scan aller Dateien baut globale Symboltabelle auf, bevor Regeln greifen. LRU-Cache (50 Einträge) für AST-Caching.

### Changed
- Gesamtregelanzahl von 38 auf 42 erhöht (23 Security, 13 AI-Smell, 6 Tech-Debt)

### Fixed
- `jwt-unsafe-verify`: try/catch-Pattern wird jetzt korrekt als sicher erkannt
- `prompt-injection`: Dead-Code in `isSanitizedContext()` entfernt

## [1.0.10] - 2026-06-07

### Added
- **Cross-Function Taint Tracking**: Engine now tracks variables and arguments across functions and up to 2-hops deep, vastly improving data flow analysis for injection vulnerabilities.
- **Auto-Fixing (`--fix` / `--dry-run`)**: AICop can now automatically fix certain code smells and tech debt issues in-place, rewriting code to eliminate vulnerabilities or messy code.
- **Parallel Scanning**: AST scanning is now multithreaded using Node.js `worker_threads`, significantly speeding up large codebases.
- **Next.js App Router Rules**: New rules added for Next.js security (`security/nextjs-missing-input-validation`) and common AI-induced bugs (`ai-smell/nextjs-client-server-confusion`).
- **Prompt Injection Rule**: Added new `security/prompt-injection` rule to detect when unfiltered user input reaches AI SDKs (OpenAI, Anthropic, LangChain), helping prevent attackers from overriding system prompts or extracting sensitive data.
- **Hallucinated APIs**: Expanded `ai-smells/hallucinated-api-calls` to detect AI-hallucinated syntax for Prisma, Next.js, Zod, Mongoose, Drizzle, and test frameworks.

### Fixed
- **eval() and spawn() Tracking**: `eval-usage` and `command-injection` rules updated to leverage the new cross-function taint tracker for complex argument tracking.
- **SQL-Injection Detection**: Rewrote `security/sql-injection` rule to accurately detect dynamic SQL string concatenations and template literals passed to database functions without relying solely on the taint tracker. Parameterized queries remain correctly unflagged.
- **Explainability**: The rule now provides `HIGH` confidence explanations when dynamic strings reach database query functions unparameterized.
- **NoSQL-Injection Variable Tracking**: Enhanced `security/nosql-injection` to properly track variables storing malicious queries before they hit the DB call. It now correctly detects inputs obfuscated through intermediate variables and explicitly warns with `HIGH` confidence when the `$where` operator is used.

## [1.0.9] - 2026-06-07

### Added
- `--explain` flag: View matched patterns and confidence levels for triggered rules to drastically improve transparency. Das `--explain`-Flag macht jeden Befund nachvollziehbar und reduziert den Erklärungsaufwand bei Code Reviews.
- Added 3 real-world LLM output files to the `tests/ai-benchmarks/` suite to ensure accurate evaluation of scanner performance.
- Badge Command: Updated `aicop badge` output to use standard shield.io Markdown formatting.

### Changed
- Refactored `scanner/index.ts` to use `picomatch` for configurable glob-based test file detection.
- Removed hardcoded early-returns in security rules (`hardcoded-secrets`, `eval-usage`, etc.), transferring responsibility to the global configuration layer. This prevents accidentally ignoring real vulnerabilities in `.spec` or `mock` files.
- Adjusted score calculation rounding logic to `Math.floor` so even minor warnings accurately reflect in the final score.
- Improved terminal reporter output formatting.

### Fixed
- Fixed critical security gap where security rules were completely disabled in test files.
- Adjusted detection sensitivity and `null-check` rules to increase True Positive Rate on generic AST nodes.
