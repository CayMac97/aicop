# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-06-07

### Fixed
- **SQL-Injection Detection**: Rewrote `security/sql-injection` rule to accurately detect dynamic SQL string concatenations and template literals passed to database functions without relying solely on the taint tracker. Parameterized queries remain correctly unflagged.
- **Explainability**: The rule now provides `HIGH` confidence explanations when dynamic strings reach database query functions unparameterized.

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
