import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildTaintMap, isTaintedNode } from '../../../utils/taint-tracker.js';

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

function isTainted(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isDirectUserInput(node)) return true;
  if (isTaintedNode(node, tainted)) return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some(e => isTainted(e, tainted));
  }
  if (node.type === 'BinaryExpression' && (node as TSESTree.BinaryExpression).operator === '+') {
    const be = node as TSESTree.BinaryExpression;
    return isTainted(be.left, tainted) || isTainted(be.right, tainted);
  }
  return false;
}

function containsTaintedTargetProp(obj: TSESTree.ObjectExpression, tainted: Set<string>): boolean {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property') continue;
    const keyName = isIdentifier(prop.key) ? prop.key.name : 
                   (prop.key.type === 'Literal' ? String(prop.key.value) : null);
    
    if (keyName && TARGET_PROPS.has(keyName)) {
      if (isTainted(prop.value, tainted)) return true;
      if (prop.value.type === 'ArrayExpression') {
         const arr = prop.value as TSESTree.ArrayExpression;
         if (arr.elements.some(el => el && el.type === 'ObjectExpression' && containsTaintedTargetProp(el, tainted))) {
           return true;
         }
      }
      if (prop.value.type === 'ObjectExpression' && containsTaintedTargetProp(prop.value as TSESTree.ObjectExpression, tainted)) {
        return true;
      }
    } else {
      // Deep check other properties just in case
      if (prop.value.type === 'ArrayExpression') {
        const arr = prop.value as TSESTree.ArrayExpression;
        if (arr.elements.some(el => el && el.type === 'ObjectExpression' && containsTaintedTargetProp(el, tainted))) {
          return true;
        }
      }
      if (prop.value.type === 'ObjectExpression' && containsTaintedTargetProp(prop.value as TSESTree.ObjectExpression, tainted)) {
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
  let curr: TSESTree.Node | undefined = node;
  while (curr) {
    if (curr.type === 'CallExpression') {
      const call = curr as TSESTree.CallExpression;
      if (isIdentifier(call.callee) && SANITIZER_PATTERN.test(call.callee.name)) {
        return true;
      }
      if (isMemberExpression(call.callee) && isIdentifier(call.callee.property) && SANITIZER_PATTERN.test(call.callee.property.name)) {
        return true;
      }
    }
    if (curr.type === 'TryStatement') {
      return true; // We assume a try/catch implies some validation as per requirements
    }
    curr = parentMap.get(curr);
  }
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
    const tainted = buildTaintMap(ast);
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
            if (isIdentifier(decl.id)) tainted.delete(decl.id.name);
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
          if (arg.type === 'ObjectExpression' && containsTaintedTargetProp(arg, tainted)) {
            isVuln = true;
          } else if (isTainted(arg, tainted)) {
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

    return findings;
  }
};

export default rule;
