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

function hasRedirectValidation(source: string, varName: string, line: number): boolean {
  const priorLines = source.split('\n').slice(Math.max(0, line - 15), line).join('\n');
  // Allowlist check: ALLOWED.includes(varName) or ALLOWED.has(varName)
  if (priorLines.includes(`.includes(${varName}`) || priorLines.includes(`.has(${varName}`)) return true;
  // Path-only validation: both startsWith('/') AND startsWith('//') present = protocol-relative handled
  if (
    (priorLines.includes(`${varName}.startsWith('/')`) || priorLines.includes(`${varName}.startsWith("/")`)) &&
    (priorLines.includes(`${varName}.startsWith('//')`) || priorLines.includes(`${varName}.startsWith("//")`))
  ) return true;
  // Custom validation function: isAllowedUrl(varName), validateRedirect(varName), etc.
  const customValidationRe = new RegExp(`${REDIRECT_VALIDATION_FN_RE.source}[\\w]*\\(${varName}\\)`, 'i');
  if (customValidationRe.test(priorLines)) return true;
  return false;
}

function checkResRedirect(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'res') return null;
  if ((me.property as TSESTree.Identifier).name !== 'redirect') return null;

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
    if (hasRedirectValidation(source, varName, getLine(node))) return null;
  }

  return {
    ruleId: 'security/open-redirect',
    severity: 'error',
    message: 'open redirect — user-controlled URL in res.redirect()',
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
