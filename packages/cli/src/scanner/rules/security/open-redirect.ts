import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const USER_INPUT_PROPS = new Set(['query', 'body', 'params', 'headers']);

// aicop-ignore tech-debt/cyclomatic-complexity
function isUserInput(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
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

function isStaticUrl(node: TSESTree.Node): boolean {
  if (isStringLiteral(node)) return true;
  if (node.type === 'Literal') return true;
  return false;
}

function isStatusCode(node: TSESTree.Node): boolean {
  if (node.type !== 'Literal') return false;
  return typeof (node as TSESTree.Literal).value === 'number';
}

const REDIRECT_VALIDATION_FN_RE = /(?:is)?(?:allowed|valid|safe|permit|whitelist|sanitize|check|verify|trusted)/i;

function hasRedirectValidation(node: TSESTree.Node, varName: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    let guardNode: TSESTree.Node | null = null;
    if (current.type === 'IfStatement' || current.type === 'ConditionalExpression') {
      guardNode = (current as any).test;
    } else if (current.type === 'SwitchStatement') {
      guardNode = (current as any).discriminant;
    } else if (current.type === 'LogicalExpression') {
      guardNode = (current as any).left;
    }

    if (guardNode) {
      walk(guardNode, {
        CallExpression(rawNode) {
          const cNode = rawNode as TSESTree.CallExpression;
          if (isMemberExpression(cNode.callee)) {
            const prop = cNode.callee.property;
            if (isIdentifier(prop)) {
              if (prop.name === 'includes' || prop.name === 'has') hasGuard = true;
              if (prop.name === 'startsWith') {
                if (isIdentifier(cNode.callee.object) && cNode.callee.object.name === varName) hasGuard = true;
              }
            }
          } else if (isIdentifier(cNode.callee)) {
            const name = cNode.callee.name;
            if (REDIRECT_VALIDATION_FN_RE.test(name)) hasGuard = true;
          }
        }
      });
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }
  return hasGuard;
}

function checkResRedirect(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const objName = (me.object as TSESTree.Identifier).name;
  if (objName !== 'res' && objName !== 'reply') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'redirect' && method !== 'location') return null;

  const args = node.arguments;
  if (args.length === 0) return null;

  const urlArg = args.length >= 2 && isStatusCode(args[0]) ? args[1] : args[0];

  if (isStaticUrl(urlArg)) return null;
  if (urlArg.type === 'TemplateLiteral') {
    const tl = urlArg as TSESTree.TemplateLiteral;
    const firstRaw = tl.quasis[0]?.value.raw ?? '';
    // If it starts with / but not //, it's safe ONLY IF the first quasi guarantees it won't become //
    // e.g., `/${userInput}` -> if userInput is `/evil`, it becomes `//evil`.
    // It's safe if it starts with a safe path like `/api/` or `/?` or `/#`.
    // Just checking `startsWith('/')` is not enough. We check if the static part is strictly longer than `/`
    // or if the first quasi is long enough to prevent `//` at the start.
    if (firstRaw.startsWith('/') && !firstRaw.startsWith('//')) {
      if (firstRaw.length > 1 && firstRaw[1] !== '/') return null;
      if (firstRaw === '/' && tl.expressions.length === 0) return null;
      // If firstRaw === '/' and there's an expression immediately after, it's unsafe!
    }
  }
  if (!isUserInput(urlArg, taintResult, parentMap)) return null;
  if (isIdentifier(urlArg)) {
    const varName = (urlArg as TSESTree.Identifier).name;
    if (hasRedirectValidation(node, varName, parentMap)) return null;
  }

  return {
    ruleId: 'security/open-redirect',
    severity: 'error',
    message: `open redirect — user-controlled URL in res.${method}()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate redirect destination against an allowlist of known-safe paths.',
  };
}

const rule: Rule = {
  id: 'security/open-redirect',
  name: 'Open Redirect',
  category: 'security',
  severity: 'error',
  description: 'Detects res.redirect() calls with user-controlled URL from req.query, req.body, or req.params',
  why: 'Open redirects allow attackers to craft links that appear to go to a trusted site but redirect to a malicious one, enabling phishing attacks.',
  fix: 'Validate all redirect URLs against an allowlist. Never use raw req.query or req.body values as redirect destinations.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const f = checkResRedirect(rawNode as TSESTree.CallExpression, source, filePath, taintResult, parentMap);
        if (f) findings.push(f);
      },
    });

    return findings;
  },
};

export default rule;
