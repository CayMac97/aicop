import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

const HTTP_CLIENTS = new Set(['fetch', 'axios', 'got', 'request', 'superagent', 'undici']);
const AXIOS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request']);
const USER_INPUT_PROPS = new Set(['params', 'body', 'query', 'headers']);

function isUserControlledArg(node: TSESTree.Node): boolean {
  if (node.type === 'TemplateLiteral') {
    const tl = node as TSESTree.TemplateLiteral;
    return tl.expressions.some((e) => isUserControlledArg(e));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    return isUserControlledArg(be.left) || isUserControlledArg(be.right);
  }
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (isMemberExpression(me.object)) {
    const parent = me.object as TSESTree.MemberExpression;
    if (isIdentifier(parent.object) && (parent.object as TSESTree.Identifier).name === 'req') {
      if (isIdentifier(parent.property) && USER_INPUT_PROPS.has((parent.property as TSESTree.Identifier).name)) {
        return true;
      }
    }
  }
  return false;
}

function isFetchCall(node: TSESTree.CallExpression): boolean {
  return isIdentifier(node.callee) && (node.callee as TSESTree.Identifier).name === 'fetch';
}

function isHttpClientMethodCall(node: TSESTree.CallExpression): string | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object)) return null;
  const obj = (me.object as TSESTree.Identifier).name;
  if (!HTTP_CLIENTS.has(obj) && obj !== 'http' && obj !== 'https') return null;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  const isValid = obj === 'axios' ? AXIOS_METHODS.has(method) : method === 'get' || method === 'request';
  return isValid ? `${obj}.${method}` : null;
}

function checkHttpCall(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  let clientName = '';
  if (isFetchCall(node)) {
    clientName = 'fetch';
  } else {
    const methodName = isHttpClientMethodCall(node);
    if (!methodName) return null;
    clientName = methodName;
  }
  const urlArg = node.arguments[0];
  if (!urlArg || !isUserControlledArg(urlArg)) return null;
  return {
    ruleId: 'security/ssrf-risk',
    severity: 'error',
    message: `${clientName}() called with a URL derived from user input — SSRF risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate URLs against an allowlist before making requests. Never pass user-supplied URLs directly to HTTP clients.',
  };
}

const rule: Rule = {
  id: 'security/ssrf-risk',
  name: 'SSRF Risk',
  category: 'security',
  severity: 'error',
  description: 'Detects HTTP requests where the URL is constructed from user-controlled input (Server-Side Request Forgery)',
  why: 'SSRF allows attackers to make your server send requests to internal services (AWS metadata, localhost, internal APIs), leaking credentials and bypassing network controls.',
  fix: 'Validate and allowlist URLs before making requests. Use URL parsing to check protocol and hostname against a safe list.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const finding = checkHttpCall(rawNode as TSESTree.CallExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
