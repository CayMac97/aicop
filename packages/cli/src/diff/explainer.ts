import { Finding } from '../scanner/rules/types.js';

export interface ExplainedFinding extends Finding {
  /** Human-readable explanation of why this finding was introduced or changed */
  diffContext: string;
}

const RULE_CONTEXTS: Record<string, string> = {
  'security/hardcoded-secrets': 'New secret or credential was introduced in this diff',
  'security/sql-injection': 'SQL query construction changed — review for injection risk',
  'security/xss-vulnerabilities': 'DOM manipulation added — check for unsanitized input',
  'security/eval-usage': 'Dynamic code execution introduced in this change',
  'security/weak-crypto': 'Cryptographic operation modified — verify algorithm strength',
  'security/jwt-no-expiry': 'JWT handling changed — ensure tokens have proper expiry',
  'security/missing-rate-limit': 'New auth or sensitive endpoint added without rate limiting',
  'security/path-traversal': 'File system access added — validate path inputs',
  'security/ssrf-risk': 'HTTP request with external URL added in this diff',
  'security/cors-misconfiguration': 'CORS policy changed — review origin and credential settings',
  'security/prototype-pollution': 'Object merging or assignment modified — check for pollution risk',
  'security/regex-dos': 'Regular expression modified — check for catastrophic backtracking',
  'ai-smell/dead-code-blocks': 'Unreachable code added — likely generated boilerplate',
  'ai-smell/inconsistent-error-handling': 'Error handling inconsistency introduced in this change',
  'ai-smell/todo-stub-functions': 'Unimplemented stub or TODO added — needs real implementation',
  'ai-smell/hallucinated-api-calls': 'Call to non-existent API method added — verify the API',
  'ai-smell/copy-paste-patterns': 'Duplicate code structure added — extract a shared function',
  'ai-smell/missing-null-checks': 'Unsafe property access added without null guard',
  'ai-smell/debug-leftovers': 'Debug code committed — remove before merging',
  'ai-smell/mixed-async-patterns': 'Mixed async patterns introduced — pick one style',
  'ai-smell/magic-numbers': 'Magic number added — extract to a named constant',
  'ai-smell/generic-variable-names': 'Generic variable name introduced — use a descriptive name',
  'tech-debt/cyclomatic-complexity': 'Function complexity increased — consider breaking it apart',
  'tech-debt/function-length': 'Long function added — split into smaller focused functions',
  'tech-debt/nesting-depth': 'Deep nesting added — extract inner logic to helper functions',
  'tech-debt/god-files': 'File grew significantly — consider splitting into modules',
  'tech-debt/hardcoded-config': 'Hardcoded configuration value added — use environment variables',
  'tech-debt/missing-types': 'TypeScript type annotation missing — add explicit types',
};

/**
 * Add diff context explanation to a list of findings.
 * Used by `vibescan diff` to explain why each finding is noteworthy in this changeset.
 */
export function explainFindings(findings: Finding[]): ExplainedFinding[] {
  return findings.map((f) => ({
    ...f,
    diffContext: RULE_CONTEXTS[f.ruleId] ?? 'New issue introduced in this diff',
  }));
}

/**
 * Format a concise diff report header for the changed files.
 */
export function buildDiffHeader(ref: string, changedFiles: string[]): string {
  const fileList = changedFiles.slice(0, 10).map((f) => `  • ${f}`).join('\n');
  const more = changedFiles.length > 10 ? `\n  ... and ${changedFiles.length - 10} more` : '';
  return `Scanning changes since ${ref}\n${fileList}${more}`;
}
