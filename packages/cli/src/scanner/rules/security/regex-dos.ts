import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier } from '../../../utils/ast-helpers.js';

const NESTED_QUANTIFIER = /(\([^)]*[+*][^)]*\)[+*]|\([^)]*\)[+*][+*])/;;
const OVERLAPPING_ALTERNATION = /\(([^|)]+\|[^)]+)\)[+*]/;

function analyzeRegexPattern(pattern: string): string | null {
  if (NESTED_QUANTIFIER.test(pattern)) {
    return 'Nested quantifiers detected — catastrophic backtracking possible (e.g., (a+)+)';
  }
  if (OVERLAPPING_ALTERNATION.test(pattern)) {
    return 'Overlapping alternation with quantifier — ReDoS risk (e.g., (a|aa)+)';
  }
  return null;
}

function checkRegexLiteral(node: TSESTree.Literal, source: string, filePath: string): Finding | null {
  if (!node.regex) return null;
  const issue = analyzeRegexPattern(node.regex.pattern);
  if (!issue) return null;
  return {
    ruleId: 'security/regex-dos',
    severity: 'warn',
    message: `catastrophic regex: ${issue}`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Rewrite the regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers if your engine supports them.',
  };
}

function checkNewRegExp(node: TSESTree.NewExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'RegExp') return null;
  const patternArg = node.arguments[0];
  if (!patternArg) return null;
  if (!isStringLiteral(patternArg as TSESTree.Expression)) {
    return {
      ruleId: 'security/regex-dos',
      severity: 'error',
      message: 'new RegExp() with non-static pattern — ReDoS risk',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Never use user-supplied strings as regex patterns. Validate input against a known safe pattern instead.',
    };
  }
  const pattern = String((patternArg as TSESTree.StringLiteral).value);
  const issue = analyzeRegexPattern(pattern);
  if (!issue) return null;
  return {
    ruleId: 'security/regex-dos',
    severity: 'warn',
    message: `catastrophic regex: ${issue}`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Rewrite to avoid nested quantifiers. Test with a tool like safe-regex or redos-checker.',
  };
}

const rule: Rule = {
  id: 'security/regex-dos',
  name: 'ReDoS (Regular Expression DoS)',
  category: 'security',
  severity: 'warn',
  description: 'Detects regular expressions vulnerable to catastrophic backtracking and dynamic regex construction',
  why: 'A carefully crafted input against a vulnerable regex can cause exponential time complexity, freezing your Node.js event loop for minutes or indefinitely (DoS).',
  fix: 'Avoid nested quantifiers and overlapping alternations. Use a static regex linter. Never compile user input as a regex.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      Literal(rawNode) {
        const finding = checkRegexLiteral(rawNode as TSESTree.Literal, source, filePath);
        if (finding) findings.push(finding);
      },
      NewExpression(rawNode) {
        const finding = checkNewRegExp(rawNode as TSESTree.NewExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
