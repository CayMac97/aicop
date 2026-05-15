import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const USER_INPUT_PROPS = new Set(['query', 'body', 'params', 'headers']);

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

function isStaticUrl(node: TSESTree.Node): boolean {
  if (isStringLiteral(node)) return true;
  if (node.type === 'Literal') return true;
  return false;
}

function isStatusCode(node: TSESTree.Node): boolean {
  if (node.type !== 'Literal') return false;
  return typeof (node as TSESTree.Literal).value === 'number';
}

function checkResRedirect(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'res') return null;
  if ((me.property as TSESTree.Identifier).name !== 'redirect') return null;

  const args = node.arguments;
  if (args.length === 0) return null;

  let urlArg: TSESTree.Node;
  if (args.length >= 2 && isStatusCode(args[0])) {
    urlArg = args[1];
  } else {
    urlArg = args[0];
  }

  if (isStaticUrl(urlArg)) return null;
  if (!isUserInput(urlArg)) return null;

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

    walk(ast, {
      CallExpression(rawNode) {
        const f = checkResRedirect(rawNode as TSESTree.CallExpression, source, filePath);
        if (f) findings.push(f);
      },
    });

    return findings;
  },
};

export default rule;
