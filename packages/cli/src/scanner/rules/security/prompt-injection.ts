import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';

const AI_SDK_KEYWORDS = ['openai', 'anthropic', 'langchain'];
const TARGET_PROPS = new Set(['content', 'prompt', 'input', 'message', 'messages', 'text']);
const SANITIZER_PATTERN = /sanitize|validate|clean|filter|escape|purify/i;

function hasAiSdkImport(ast: ParsedAST): boolean {
  let hasImport = false;
  walk(ast, {
    ImportDeclaration(rawNode) {
      const node = rawNode as TSESTree.ImportDeclaration;
      const src = String(node.source.value);
      if (AI_SDK_KEYWORDS.some(k => src.includes(k))) hasImport = true;
    },
    CallExpression(rawNode) {
      const node = rawNode as TSESTree.CallExpression;
      if (isIdentifier(node.callee) && node.callee.name === 'require' && node.arguments.length > 0) {
        const arg = node.arguments[0];
        if (arg.type === 'Literal' && typeof arg.value === 'string') {
          const src = arg.value;
          if (AI_SDK_KEYWORDS.some(k => src.includes(k))) hasImport = true;
        }
      }
    }
  });
  return hasImport;
}

function isAiMethodCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const prop = node.callee.property;
  if (!isIdentifier(prop)) return false;
  const name = prop.name;
  return name === 'create' || name === 'invoke' || name === 'generate' || name === 'call';
}

function isDirectUserInput(node: TSESTree.Node): boolean {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return isDirectUserInput((node as TSESTree.TSAsExpression).expression);
  }
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  let root = me.object;
  while (isMemberExpression(root)) {
    root = root.object;
  }
  return isIdentifier(root) && root.name === 'req';
}

function isTainted(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isDirectUserInput(node)) return true;
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some(e => isTainted(e, taintResult, parentMap));
  }
  if (node.type === 'BinaryExpression' && (node as TSESTree.BinaryExpression).operator === '+') {
    const be = node as TSESTree.BinaryExpression;
    return isTainted(be.left, taintResult, parentMap) || isTainted(be.right, taintResult, parentMap);
  }
  return false;
}

function containsTaintedTargetProp(obj: TSESTree.ObjectExpression, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property') continue;
    const keyName = isIdentifier(prop.key) ? prop.key.name : 
                   (prop.key.type === 'Literal' ? String(prop.key.value) : null);
    
    if (keyName && TARGET_PROPS.has(keyName)) {
      if (isTainted(prop.value, taintResult, parentMap)) return true;
      if (prop.value.type === 'ArrayExpression') {
         const arr = prop.value as TSESTree.ArrayExpression;
         if (arr.elements.some(el => el && (isTainted(el, taintResult, parentMap) || (el.type === 'ObjectExpression' && containsTaintedTargetProp(el, taintResult, parentMap))))) {
           return true;
         }
      }
      if (prop.value.type === 'ObjectExpression' && containsTaintedTargetProp(prop.value as TSESTree.ObjectExpression, taintResult, parentMap)) {
        return true;
      }
    } else {
      // Deep check other properties just in case
      if (prop.value.type === 'ArrayExpression') {
        const arr = prop.value as TSESTree.ArrayExpression;
        if (arr.elements.some(el => el && (isTainted(el, taintResult, parentMap) || (el.type === 'ObjectExpression' && containsTaintedTargetProp(el, taintResult, parentMap))))) {
          return true;
        }
      }
      if (prop.value.type === 'ObjectExpression' && containsTaintedTargetProp(prop.value as TSESTree.ObjectExpression, taintResult, parentMap)) {
        return true;
      }
    }
  }
  return false;
}

function buildParentMap(ast: ParsedAST): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) {
      if (parent) map.set(node, parent);
    },
  });
  return map;
}

function isSanitizedContext(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  // Removing upward traversal. A call to an LLM is NOT safe just because its output is sanitized.
  // Input sanitization is handled by removing the sanitized variables from taintResult.
  return false;
}

const rule: Rule = {
  id: 'security/prompt-injection',
  name: 'Prompt Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects unfiltered user input passed directly to AI SDKs',
  why: 'Passing unfiltered user input directly into LLM prompts allows attackers to override instructions, inject malicious context, or exfiltrate sensitive data (Prompt Injection).',
  fix: 'Validate and sanitize user input before passing to AI. Consider an allowlist for allowed prompt structures.',
  
  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    if (!hasAiSdkImport(ast)) return [];
    
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    // Remove sanitized variables from tainted set
    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (isIdentifier(node.callee) && SANITIZER_PATTERN.test(node.callee.name)) {
          // If sanitize(req.body.msg) is assigned to a var, the var is safe.
          // Wait, buildTaintMap might have tainted it because it's a direct user input.
          // So we untaint the variable it is assigned to.
          const parent = parentMap.get(node);
          if (parent?.type === 'VariableDeclarator') {
            const decl = parent as TSESTree.VariableDeclarator;
            if (isIdentifier(decl.id)) taintResult.globalTaints.delete(decl.id.name);
          }
        }
      }
    });

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (!isAiMethodCall(node)) return;
        
        // Ensure not in try/catch or wrapper
        if (isSanitizedContext(node, parentMap)) return;
        
        let isVuln = false;
        for (const arg of node.arguments) {
          if (arg.type === 'ObjectExpression' && containsTaintedTargetProp(arg, taintResult, parentMap)) {
            isVuln = true;
          } else if (isTainted(arg, taintResult, parentMap)) {
            // e.g. chain.invoke(req.body) directly
            isVuln = true;
          }
        }

        if (isVuln) {
          findings.push({
            ruleId: 'security/prompt-injection',
            severity: 'error',
            message: 'Unfiltered user input passed directly to AI SDK — prompt injection risk',
            explain: 'User-controlled content reaches AI model without sanitization — attacker can override system prompt or extract sensitive data',
            confidence: 'HIGH',
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: rule.fix,
          });
        }
      }
    });

    const { getCrossFileTaints } = require('../../../utils/taint-tracker.js');
    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();

    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode as any);
      walk(crossCall.externalNode, {
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          if (!isAiMethodCall(node)) return;
          
          if (isSanitizedContext(node, extParentMap)) return;

          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          let isVuln = false;
          for (const arg of node.arguments) {
            const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
            if (arg.type === 'ObjectExpression' && containsTaintedTargetProp(arg, crossTaintResult, extParentMap)) {
              isVuln = true;
            } else if (isTainted(arg, crossTaintResult, extParentMap)) {
              isVuln = true;
            }
          }

          if (isVuln) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/prompt-injection',
              severity: 'error',
              message: 'Cross-file Prompt Injection: Unfiltered user input flows into AI SDK in imported function',
              explain: 'User input flows into an imported function that executes an AI prompt',
              confidence: 'HIGH',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: rule.fix,
            });
          }
        }
      });
    }

    return findings;
  }
};

export default rule;
