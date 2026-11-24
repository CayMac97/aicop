import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, buildParentMap, isDynamicExpr, TaintResult } from '../../../utils/taint-tracker.js';

/**
 * Detects nested unbounded quantifiers such as (a+)+, (\w+\s?)* or (?:x*)+ .
 * A group is only dangerous if (1) it contains an unbounded quantifier and
 * (2) the group itself is quantified with an unbounded quantifier.
 * Plain capture groups like (.*)\.(.*) are NOT nested quantifiers.
 */
function hasNestedQuantifier(pattern: string): boolean {
  const stack: boolean[] = []; // per open group: contains an unbounded quantifier?
  let inClass = false;
  const isUnboundedAt = (i: number): boolean => {
    const c = pattern[i];
    if (c === '+' || c === '*') return true;
    if (c === '{') return /^\{\d+,\}/.test(pattern.slice(i));
    return false;
  };
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') { i++; continue; }
    if (inClass) { if (ch === ']') inClass = false; continue; }
    if (ch === '[') { inClass = true; continue; }
    if (ch === '(') { stack.push(false); continue; }
    if (ch === ')') {
      const innerHasQuantifier = stack.pop() ?? false;
      if (innerHasQuantifier && isUnboundedAt(i + 1)) return true;
      // quantifier inside propagates upward (e.g. ((a+)b)+)
      if (innerHasQuantifier && stack.length > 0) stack[stack.length - 1] = true;
      continue;
    }
    if (stack.length > 0 && isUnboundedAt(i)) stack[stack.length - 1] = true;
  }
  return false;
}

type RegexLiteral = TSESTree.Literal & {
  regex?: {
    pattern: string;
    flags: string;
  };
};

function analyzeRegexPattern(pattern: string): string | null {
  if (hasNestedQuantifier(pattern)) {
    return 'Nested quantifiers detected — catastrophic backtracking possible (e.g., (a+)+)';
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

function checkImplicitRegExp(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: any, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const methodName = me.property.name;
  if (methodName !== 'match' && methodName !== 'search' && methodName !== 'matchAll') return null;
  
  const patternArg = node.arguments[0];
  if (!patternArg) return null;
  if (isStringLiteral(patternArg as TSESTree.Expression)) return null;
  
  if (isDynamicExpr(patternArg as TSESTree.Expression, taintResult, parentMap)) {
    return {
      ruleId: 'security/regex-dos',
      severity: 'error',
      message: `String.${methodName}() called with user-controlled input — implicit RegExp creation risk`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Never use user-supplied strings directly in match/search/matchAll, as they are converted to RegExp. Escape the input or use indexOf/includes.',
    };
  }
  return null;
}

function hasLengthCheck(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'LogicalExpression' ||
      current.type === 'SwitchStatement'
    ) {
      let conditionNode: TSESTree.Node | undefined;
      if (current.type === 'IfStatement') conditionNode = current.test;
      else if (current.type === 'ConditionalExpression') conditionNode = current.test;
      else if (current.type === 'LogicalExpression') conditionNode = current.left;
      
      let hasLengthGuard = false;
      if (conditionNode) {
        walk(conditionNode, {
          MemberExpression(rawNode) {
            const me = rawNode as TSESTree.MemberExpression;
            if (isIdentifier(me.property) && me.property.name === 'length') {
              hasLengthGuard = true;
            }
          }
        });
      }
      if (hasLengthGuard) return true;
    }
    current = parentMap.get(current);
  }
  return false;
}

function checkRegexExecution(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = me.property.name;
  
  if (method === 'test' || method === 'exec') {
    const inputArg = node.arguments[0];
    if (inputArg && isDynamicExpr(inputArg as TSESTree.Expression, taintResult, parentMap)) {
      if (!hasLengthCheck(node, parentMap)) {
        return {
          ruleId: 'security/regex-dos',
          severity: 'warn',
          message: `Unbounded user input passed to RegExp.${method}() — ReDoS risk`,
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: 'Limit the length of user input before running regexes to prevent ReDoS attacks: if (input.length > 200) throw new Error("Too long");',
        };
      }
    }
  } else if (method === 'match' || method === 'search' || method === 'matchAll' || method === 'replace' || method === 'replaceAll') {
    const obj = me.object;
    if (isDynamicExpr(obj as TSESTree.Expression, taintResult, parentMap)) {
      const regexArg = node.arguments[0];
      if (regexArg && (regexArg.type === 'Literal' && 'regex' in regexArg || regexArg.type === 'Identifier')) {
         if (!hasLengthCheck(node, parentMap)) {
           return {
            ruleId: 'security/regex-dos',
            severity: 'warn',
            message: `Unbounded user input passed to String.${method}() with a regex — ReDoS risk`,
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: 'Limit the length of user input before running regexes to prevent ReDoS attacks.',
          };
         }
      }
    }
  }
  return null;
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
        
        const implicitFinding = checkImplicitRegExp(rawNode as TSESTree.CallExpression, source, filePath, taintResult, parentMap);
        if (implicitFinding) findings.push(implicitFinding);

        const execFinding = checkRegexExecution(rawNode as TSESTree.CallExpression, source, filePath, taintResult, parentMap);
        if (execFinding) findings.push(execFinding);
      },
    });

    return findings;
  },
};

export default rule;
