import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult, isDirectUserInputExpr, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const VM_METHODS = new Set(['runInNewContext', 'runInThisContext']);
const MATH_EVAL_METHODS = new Set(['eval', 'evaluate']);
const MATH_OBJ_NAMES = new Set(['mathjs', 'math', 'Math']);

function argIsTainted(arg: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isStringLiteral(arg)) return false;
  if (arg.type === 'Literal') return false;
  return isNodeContextuallyTainted(arg, taintResult, parentMap) || isDirectUserInputExpr(arg);
}

function checkVmRun(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'vm') return null;
  if (!VM_METHODS.has((me.property as TSESTree.Identifier).name)) return null;
  const arg = node.arguments[0];
  if (!arg || !argIsTainted(arg, taintResult, parentMap)) return null;
  return {
    ruleId: 'security/code-injection',
    severity: 'error',
    message: `code injection risk — user input passed to vm.${(me.property as TSESTree.Identifier).name}()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate all input before executing in vm context. Prefer a sandboxing library with strict resource limits.',
  };
}

function hasAllowlistCheck(node: TSESTree.Node, varName: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
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

function checkMathEval(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const obj = (me.object as TSESTree.Identifier).name;
  const method = (me.property as TSESTree.Identifier).name;
  if (!MATH_OBJ_NAMES.has(obj)) return null;
  if (!MATH_EVAL_METHODS.has(method)) return null;
  if (obj === 'Math') return null;
  const arg = node.arguments[0];
  if (!arg || !argIsTainted(arg, taintResult, parentMap)) return null;
  if (isIdentifier(arg)) {
    if (hasAllowlistCheck(node, (arg as TSESTree.Identifier).name, parentMap)) return null;
  }
  return {
    ruleId: 'security/code-injection',
    severity: 'error',
    message: `code injection risk — user input passed to ${obj}.${method}()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: obj + '.' + method + '() can execute arbitrary code. Validate and sanitize all input first.',
  };
}

const rule: Rule = {
  id: 'security/code-injection',
  name: 'Code Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects vm.runInNewContext(), vm.runInThisContext(), and math.eval() called with dynamic input',
  why: 'Passing user-controlled data to code execution functions allows attackers to run arbitrary JavaScript on the server.',
  fix: 'Never pass user input to eval or eval-equivalent functions.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const vmF = checkVmRun(node, source, filePath, taintResult, parentMap);
        if (vmF) { findings.push(vmF); return; }
        const mathF = checkMathEval(node, source, filePath, taintResult, parentMap);
        if (mathF) findings.push(mathF);
      },
    });

    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();

    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode);
      walk(crossCall.externalNode, {
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          
          let finding: Finding | null = null;
          let msgType = '';
          const vmF = checkVmRun(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
          if (vmF) { finding = vmF; msgType = 'vm run'; }
          else {
            const mathF = checkMathEval(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
            if (mathF) { finding = mathF; msgType = 'math.eval'; }
          }
          
          if (finding) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/code-injection',
              severity: 'error',
              message: `Cross-file code injection risk — user input flows into ${msgType}() in imported function`,
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: finding.fix,
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
