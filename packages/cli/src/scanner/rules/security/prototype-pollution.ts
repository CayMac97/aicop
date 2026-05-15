import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

const MERGE_FUNCTIONS = new Set(['merge', 'deepMerge', 'assign', 'extend', 'defaults', 'defaultsDeep']);
const USER_INPUT_PROPS = new Set(['params', 'body', 'query', 'headers']);

function isReqBody(node: TSESTree.Node): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (!isIdentifier(me.object)) return false;
  const obj = (me.object as TSESTree.Identifier).name;
  return (obj === 'req' || obj === 'request') &&
    isIdentifier(me.property) &&
    USER_INPUT_PROPS.has((me.property as TSESTree.Identifier).name);
}

function isUserInputArg(node: TSESTree.Node): boolean {
  if (isReqBody(node)) return true;
  if (node.type === 'SpreadElement') {
    return isReqBody((node as TSESTree.SpreadElement).argument);
  }
  return false;
}

function checkObjectAssign(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'Object') return null;
  if ((me.property as TSESTree.Identifier).name !== 'assign') return null;
  if (!node.arguments.some((arg) => isUserInputArg(arg))) return null;
  return {
    ruleId: 'security/prototype-pollution',
    severity: 'error',
    message: 'Object.assign() with user input — prototype pollution risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate and sanitize input before merging. Use a safe-assign utility or explicitly pick known properties.',
  };
}

function checkMergeFunctionCall(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  let funcName = '';
  if (isIdentifier(node.callee)) {
    funcName = (node.callee as TSESTree.Identifier).name;
  } else if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (isIdentifier(me.property)) funcName = (me.property as TSESTree.Identifier).name;
  }
  if (!MERGE_FUNCTIONS.has(funcName)) return null;
  if (!node.arguments.some((arg) => isUserInputArg(arg))) return null;
  return {
    ruleId: 'security/prototype-pollution',
    severity: 'error',
    message: `${funcName}() with user input — prototype pollution risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Sanitize deeply nested objects before merging, or use Object.create(null) targets. Validate all keys.',
  };
}

function checkDynamicPropertyAssign(node: TSESTree.AssignmentExpression, source: string, filePath: string): Finding | null {
  if (node.left.type !== 'MemberExpression') return null;
  const me = node.left as TSESTree.MemberExpression;
  if (!me.computed) return null;
  if (!isReqBody(me.property)) return null;
  return {
    ruleId: 'security/prototype-pollution',
    severity: 'error',
    message: 'dynamic property assignment with user-controlled key',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate keys against an allowlist before dynamic assignment. Check for "__proto__", "constructor", "prototype".',
  };
}

const rule: Rule = {
  id: 'security/prototype-pollution',
  name: 'Prototype Pollution',
  category: 'security',
  severity: 'error',
  description: 'Detects Object.assign, merge functions, and dynamic property assignments with user-controlled input',
  why: 'Prototype pollution lets attackers modify Object.prototype, affecting all objects in your app. This can lead to privilege escalation, DoS, or remote code execution.',
  fix: 'Validate all keys against an allowlist, freeze Object.prototype, or use Object.create(null) for dict-like objects.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const assignF = checkObjectAssign(node, source, filePath);
        if (assignF) { findings.push(assignF); return; }
        const mergeF = checkMergeFunctionCall(node, source, filePath);
        if (mergeF) findings.push(mergeF);
      },
      AssignmentExpression(rawNode) {
        const finding = checkDynamicPropertyAssign(rawNode as TSESTree.AssignmentExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
