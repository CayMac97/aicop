import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const EXEC_FUNCTIONS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
const USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers']);

function isUserInput(node: TSESTree.Node): boolean {
  if (isMemberExpression(node)) {
    const me = node as TSESTree.MemberExpression;
    if (isMemberExpression(me.object)) {
      const parent = me.object as TSESTree.MemberExpression;
      if (isIdentifier(parent.object) && (parent.object as TSESTree.Identifier).name === 'req') {
        if (isIdentifier(parent.property) && USER_INPUT_PROPS.has((parent.property as TSESTree.Identifier).name)) {
          return true;
        }
      }
    }
    if (isIdentifier(me.object) && isIdentifier(me.property)) {
      const prop = (me.property as TSESTree.Identifier).name;
      if (USER_INPUT_PROPS.has(prop)) return true;
    }
  }
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInput(e));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInput(be.left) || isUserInput(be.right);
  }
  return false;
}

function argContainsUserInput(arg: TSESTree.Node): boolean {
  if (isStringLiteral(arg)) return false;
  return isUserInput(arg);
}

function checkExecCall(node: TSESTree.CallExpression, source: string, filePath: string, childProcessUsed: boolean): Finding | null {
  if (!childProcessUsed) return null;

  let funcName: string | null = null;

  if (isIdentifier(node.callee)) {
    const name = (node.callee as TSESTree.Identifier).name;
    if (EXEC_FUNCTIONS.has(name)) funcName = name;
  } else if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (isIdentifier(me.property) && EXEC_FUNCTIONS.has((me.property as TSESTree.Identifier).name)) {
      funcName = (me.property as TSESTree.Identifier).name;
    }
  }

  if (!funcName) return null;

  const firstArg = node.arguments[0];
  if (!firstArg) return null;
  if (!argContainsUserInput(firstArg)) return null;

  return {
    ruleId: 'security/command-injection',
    severity: 'error',
    message: `command injection risk — user input in ${funcName}() call`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate and whitelist input before passing to exec()',
  };
}

function sourceUsesChildProcess(source: string): boolean {
  return source.includes('child_process');
}

const rule: Rule = {
  id: 'security/command-injection',
  name: 'Command Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects child_process functions called with user-controlled input',
  why: 'Passing unsanitized user input to exec(), spawn(), or similar functions allows attackers to run arbitrary system commands.',
  fix: 'Validate and whitelist all input before passing to child_process functions. Avoid constructing shell commands from user data.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const childProcessUsed = sourceUsesChildProcess(source);
    if (!childProcessUsed) return findings;

    walk(ast, {
      CallExpression(rawNode) {
        const f = checkExecCall(rawNode as TSESTree.CallExpression, source, filePath, childProcessUsed);
        if (f) findings.push(f);
      },
    });

    return findings;
  },
};

export default rule;
