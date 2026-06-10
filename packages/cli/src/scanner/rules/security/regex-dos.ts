import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, buildParentMap, isDynamicExpr } from '../../../utils/taint-tracker.js';

const NESTED_QUANTIFIER = /\([^)]*[+*?][^)]*\)[+*]/;
const OVERLAPPING_ALTERNATION = /\(([^|)]+\|[^)]+)\)[+*]/;

type RegexLiteral = TSESTree.Literal & {
  regex?: {
    pattern: string;
    flags: string;
  };
};

function analyzeRegexPattern(pattern: string): string | null {
  if (NESTED_QUANTIFIER.test(pattern)) {
    return 'Nested quantifiers detected — catastrophic backtracking possible (e.g., (a+)+)';
  }
  if (OVERLAPPING_ALTERNATION.test(pattern)) {
    return 'Overlapping alternation with quantifier — ReDoS risk (e.g., (a|aa)+)';
  }
  return null;
}

function checkRegexLiteral(node: RegexLiteral, source: string, filePath: string): Finding | null {
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

function checkRegExpConstruct(node: TSESTree.NewExpression | TSESTree.CallExpression, source: string, filePath: string, taintResult: any, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'RegExp') return null;
  const patternArg = node.arguments[0];
  if (!patternArg) return null;
  if (!isStringLiteral(patternArg as TSESTree.Expression)) {
    if (!isDynamicExpr(patternArg as TSESTree.Expression, taintResult, parentMap)) return null;
    return {
      ruleId: 'security/regex-dos',
      severity: 'error',
      message: 'RegExp() constructed with user-controlled input — direct ReDoS risk',
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
    const parentMap = buildParentMap(ast);
    const taintResult = buildContextualTaintMap(ast, filePath);

    walk(ast, {
      Literal(rawNode) {
        const finding = checkRegexLiteral(rawNode as RegexLiteral, source, filePath);
        if (finding) findings.push(finding);
      },
      NewExpression(rawNode) {
        const finding = checkRegExpConstruct(rawNode as TSESTree.NewExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
      CallExpression(rawNode) {
        const finding = checkRegExpConstruct(rawNode as TSESTree.CallExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
