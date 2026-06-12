import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const EXEC_FUNCTIONS = new Set(['exec', 'spawn', 'execSync', 'spawnSync', 'execFile', 'execFileSync', 'sync']);
const USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers']);

function isReqPropUserInput(node: TSESTree.MemberExpression): boolean {
  if (!isMemberExpression(node.object)) return false;
  const parent = node.object as TSESTree.MemberExpression;
  return isIdentifier(parent.object)
    && (parent.object as TSESTree.Identifier).name === 'req'
    && isIdentifier(parent.property)
    && USER_INPUT_PROPS.has((parent.property as TSESTree.Identifier).name);
}

function isUserInput(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (isMemberExpression(node)) {
    const me = node as TSESTree.MemberExpression;
    if (isReqPropUserInput(me)) return true;
  }
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInput(e, taintResult, parentMap));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInput(be.left, taintResult, parentMap) || isUserInput(be.right, taintResult, parentMap);
  }
  return false;
}

function argContainsUserInput(arg: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isStringLiteral(arg)) return false;
  return isUserInput(arg, taintResult, parentMap);
}

function hasVarAllowlistCheck(node: TSESTree.Node, varName: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      let usesVarName = false;
      let usesValidationMethod = false;
      walk(current, {
        Identifier(rawNode) {
          if ((rawNode as TSESTree.Identifier).name === varName) usesVarName = true;
          const name = (rawNode as TSESTree.Identifier).name;
          if (name === 'includes' || name === 'indexOf' || name === 'has') usesValidationMethod = true;
        },
        UnaryExpression(rawNode) {
          const uNode = rawNode as TSESTree.UnaryExpression;
          if (uNode.operator === 'typeof') {
            if (isIdentifier(uNode.argument) && uNode.argument.name === varName) {
              usesVarName = true;
              usesValidationMethod = true;
            }
          }
        }
      });
      if (usesVarName && usesValidationMethod) {
        hasGuard = true;
        break;
      }
    }
    current = parentMap.get(current);
  }
  return hasGuard;
}

function checkExecCall(node: TSESTree.CallExpression, source: string, filePath: string, childProcessUsed: boolean, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
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
  const secondArg = node.arguments[1];
  
  if (!firstArg) return null;
  
  let isVulnerable = false;
  if (argContainsUserInput(firstArg, taintResult, parentMap)) {
    isVulnerable = true;
    
    // Suppress when all tainted template expressions are validated via allowlist
    if (firstArg.type === 'TemplateLiteral') {
      const tl = firstArg as TSESTree.TemplateLiteral;
      const taintedExprs = tl.expressions.filter((e) => isUserInput(e, taintResult, parentMap));
      if (
        taintedExprs.length > 0 &&
        taintedExprs.every((e) =>
          isIdentifier(e) && hasVarAllowlistCheck(node, (e as TSESTree.Identifier).name, parentMap),
        )
      ) {
        isVulnerable = false;
      }
    }
  }
  
  // Also check array elements in second argument (for spawn)
  if (!isVulnerable && secondArg && secondArg.type === 'ArrayExpression') {
    const hasTaintedElem = (secondArg as TSESTree.ArrayExpression).elements.some(elem => 
      elem && argContainsUserInput(elem, taintResult, parentMap)
    );
    if (hasTaintedElem) {
       isVulnerable = true;
    }
  }

  if (!isVulnerable) return null;

  return {
    ruleId: 'security/command-injection',
    severity: 'error',
    message: `command injection risk — user input in ${funcName}() call`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate and whitelist input before passing to child_process functions',
  };
}

function hasChildProcessImport(ast: ParsedAST): boolean {
  let uses = false;
  walk(ast, {
    ImportDeclaration(node) {
      const src = String((node as TSESTree.ImportDeclaration).source.value);
      if (src === 'child_process' || src === 'node:child_process' || src === 'cross-spawn' || src === 'shelljs') {
        uses = true;
      }
    },
    CallExpression(node) {
      const call = node as TSESTree.CallExpression;
      if (isIdentifier(call.callee) && call.callee.name === 'require' && call.arguments[0] && isStringLiteral(call.arguments[0])) {
        const val = (call.arguments[0] as TSESTree.StringLiteral).value;
        if (val === 'child_process' || val === 'node:child_process' || val === 'cross-spawn' || val === 'shelljs') uses = true;
      }
    }
  });
  return uses;
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
    const childProcessUsed = hasChildProcessImport(ast);

    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    if (childProcessUsed) {
      walk(ast, {
        CallExpression(rawNode) {
          const f = checkExecCall(rawNode as TSESTree.CallExpression, source, filePath, childProcessUsed, taintResult, parentMap);
          if (f) findings.push(f);
        },
      });
    }

    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();

    for (const crossCall of crossFileCalls) {
      walk(crossCall.externalNode, {
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          const extParentMap = buildParentMap(crossCall.externalNode);
          const f = checkExecCall(node, source, crossCall.externalFilePath, true, crossTaintResult, extParentMap);
          if (f) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/command-injection',
              severity: 'error',
              message: 'Cross-file command injection risk — user input flows into imported child_process function',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: 'Validate and whitelist input before passing to child_process functions',
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
