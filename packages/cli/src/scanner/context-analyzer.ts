import { Finding } from './rules/types.js';

const TODO_COMMENT_RE = /\/\/\s*(?:TODO|FIXME|HACK|XXX)\b/i;
const HARDCODED_EMAIL_RE = /["'][a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}["']/gi;
const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/;

export interface ContextPattern {
  re: RegExp;
  ruleId: string;
  severity: Finding['severity'];
  message: string;
  fix: string;
}

const CONTEXT_PATTERNS: ContextPattern[] = [
  {
    re: PRIVATE_KEY_RE,
    ruleId: 'security/hardcoded-secrets',
    severity: 'error',
    message: 'Private key material detected in source file',
    fix: 'Never store private keys in source files. Use environment variables or a key management service.',
  },
];

export function runContextAnalysis(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split('\n');

  for (const pattern of CONTEXT_PATTERNS) {
    lines.forEach((line, idx) => {
      if (pattern.re.test(line)) {
        findings.push({
          ruleId: pattern.ruleId,
          severity: pattern.severity,
          message: pattern.message,
          file: filePath,
          line: idx + 1,
          column: 0,
          snippet: line.trim(),
          fix: pattern.fix,
        });
      }
    });
  }

  return findings;
}

export function hasTodoComments(source: string): boolean {
  return TODO_COMMENT_RE.test(source);
}

export function extractTodoLines(source: string): Array<{ line: number; text: string }> {
  const results: Array<{ line: number; text: string }> = [];
  source.split('\n').forEach((line, idx) => {
    if (TODO_COMMENT_RE.test(line)) {
      results.push({ line: idx + 1, text: line.trim() });
    }
  });
  return results;
}

export function hasHardcodedEmails(source: string): boolean {
  const matches = source.match(HARDCODED_EMAIL_RE) ?? [];
  return matches.some((m) => !m.includes('example.') && !m.includes('@test.'));
}
