import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

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

function isUserInputArg(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isReqBody(node)) return true;
  if (isIdentifier(node) && isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (node.type === 'SpreadElement') {
    return isReqBody((node as TSESTree.SpreadElement).argument);
  }
  return false;
}

function collectLocalObjectVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init || node.init.type !== 'ObjectExpression') return;
      if (node.id.type !== 'Identifier') return;
      vars.add((node.id as TSESTree.Identifier).name);
    },
  });
  return vars;
}

function checkForInLoop(node: TSESTree.ForInStatement, source: string, filePath: string, localObjectVars: Set<string>): Finding | null {
  if (node.right.type === 'Identifier' && localObjectVars.has((node.right as TSESTree.Identifier).name)) return null;
  const body = node.body;
  const stmts = body.type === 'BlockStatement'
    ? (body as TSESTree.BlockStatement).body
    : [body];
  const hasProtoGuard = stmts.some((s) => {
    const src = extractSnippet(source, getLine(s as TSESTree.Node));
    return src.includes('hasOwnProperty') || src.includes('__proto__') || src.includes('Object.prototype');
  });
  if (hasProtoGuard) return null;
  const hasObjKeyAssign = stmts.some((s) => {
    if (s.type !== 'ExpressionStatement') return false;
    const expr = (s as TSESTree.ExpressionStatement).expression;
    if (expr.type !== 'AssignmentExpression') return false;
    const assign = expr as TSESTree.AssignmentExpression;
    if (assign.left.type !== 'MemberExpression') return false;
    return (assign.left as TSESTree.MemberExpression).computed;
  });
  if (!hasObjKeyAssign) return null;
  return {
    ruleId: 'security/prototype-pollution',
    severity: 'error',
    message: 'for...in loop assigns obj[key] without hasOwnProperty check — prototype pollution risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Add guard: if (!Object.prototype.hasOwnProperty.call(src, key)) continue; — or use Object.entries() instead of for...in.',
  };
}

function checkObjectAssign(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>, parent: TSESTree.Node | null): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'Object') return null;
  if ((me.property as TSESTree.Identifier).name !== 'assign') return null;
  if (!node.arguments.some((arg) => isUserInputArg(arg, taintResult, parentMap))) return null;
  // Result discarded (ExpressionStatement) with fresh {} target — no object is mutated
  if (
    parent?.type === 'ExpressionStatement' &&
    node.arguments[0]?.type === 'ObjectExpression' &&
    (node.arguments[0] as TSESTree.ObjectExpression).properties.length === 0
  ) return null;
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

function checkMergeFunctionCall(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  let funcName = '';
  if (isIdentifier(node.callee)) {
    funcName = (node.callee as TSESTree.Identifier).name;
  } else if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (isIdentifier(me.property)) funcName = (me.property as TSESTree.Identifier).name;
  }
  if (!MERGE_FUNCTIONS.has(funcName)) return null;
  if (!node.arguments.some((arg) => isUserInputArg(arg, taintResult, parentMap))) return null;
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

function checkDynamicPropertyAssign(node: TSESTree.AssignmentExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (node.left.type !== 'MemberExpression') return null;
  const me = node.left as TSESTree.MemberExpression;
  if (!me.computed) return null;
  if (!isUserInputArg(me.property, taintResult, parentMap)) return null;
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
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);
    const localObjectVars = collectLocalObjectVars(ast);

    walk(ast, {
      CallExpression(rawNode, parent) {
        const node = rawNode as TSESTree.CallExpression;
        const assignF = checkObjectAssign(node, source, filePath, taintResult, parentMap, parent);
        if (assignF) { findings.push(assignF); return; }
        // Object.assign is handled exclusively by checkObjectAssign (including its suppression)
        if (isMemberExpression(node.callee)) {
          const me = node.callee as TSESTree.MemberExpression;
          if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'Object' &&
              isIdentifier(me.property) && (me.property as TSESTree.Identifier).name === 'assign') return;
        }
        const mergeF = checkMergeFunctionCall(node, source, filePath, taintResult, parentMap);
        if (mergeF) findings.push(mergeF);
      },
      AssignmentExpression(rawNode) {
        const finding = checkDynamicPropertyAssign(rawNode as TSESTree.AssignmentExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
      ForInStatement(rawNode) {
        const finding = checkForInLoop(rawNode as TSESTree.ForInStatement, source, filePath, localObjectVars);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
