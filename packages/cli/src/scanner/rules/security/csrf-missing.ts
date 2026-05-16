import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isStringLiteral, isMemberExpression } from '../../../utils/ast-helpers.js';

const CSRF_PACKAGES = new Set(['csurf', 'csrf-csrf', 'lusca']);
const SESSION_PACKAGES = new Set(['express-session', 'cookie-session']);
const EXPRESS_PACKAGES = new Set(['express', 'express-router']);
const HTTP_CLIENT_OBJECTS = new Set(['axios', 'got', 'request', 'supertest', 'http', 'https', 'fetch']);

function getRequireArg(node: TSESTree.CallExpression): string | null {
  if (!isIdentifier(node.callee) || node.callee.name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  return String((arg as TSESTree.StringLiteral).value);
}

function isHttpClientCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  // Direct: axios.post(), http.request(), etc.
  if (isIdentifier(me.object)) {
    return HTTP_CLIENT_OBJECTS.has((me.object as TSESTree.Identifier).name.toLowerCase());
  }
  // Chained: supertest(app).post(), got(url).post()
  if (me.object.type === 'CallExpression') {
    const innerCallee = (me.object as TSESTree.CallExpression).callee;
    if (isIdentifier(innerCallee)) {
      return HTTP_CLIENT_OBJECTS.has((innerCallee as TSESTree.Identifier).name.toLowerCase());
    }
  }
  return false;
}

function isExpressPostRoute(node: TSESTree.CallExpression): boolean {
  if (isHttpClientCall(node)) return false;
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  return isIdentifier(me.property) && (me.property as TSESTree.Identifier).name === 'post';
}

const rule: Rule = {
  id: 'security/csrf-missing',
  name: 'CSRF Protection Missing',
  category: 'security',
  severity: 'warn',
  description: 'Detects Express apps with POST routes or session middleware but no CSRF protection',
  why: 'Without CSRF protection, state-changing requests can be forged by malicious third-party sites, leading to unauthorized actions on behalf of authenticated users.',
  fix: 'Use csurf or csrf-csrf middleware on all state-changing routes',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    let hasCsrf = false;
    let hasExpressImport = false;
    let hasSession = false;
    let firstPostRouteNode: TSESTree.CallExpression | null = null;
    let firstSessionNode: TSESTree.CallExpression | null = null;

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const pkg = getRequireArg(node);
        if (pkg) {
          if (CSRF_PACKAGES.has(pkg)) hasCsrf = true;
          if (SESSION_PACKAGES.has(pkg) && !firstSessionNode) firstSessionNode = node;
          if (EXPRESS_PACKAGES.has(pkg)) hasExpressImport = true;
          return;
        }
        if (isExpressPostRoute(node) && !firstPostRouteNode) firstPostRouteNode = node;
      },
      ImportDeclaration(rawNode) {
        const decl = rawNode as TSESTree.ImportDeclaration;
        const src = String(decl.source.value);
        if (CSRF_PACKAGES.has(src)) hasCsrf = true;
        if (SESSION_PACKAGES.has(src)) hasSession = true;
        if (EXPRESS_PACKAGES.has(src)) hasExpressImport = true;
      },
    });

    if (hasCsrf) return findings;
    // Only flag files that are actually Express servers (import express) or use session middleware
    if (!hasExpressImport && !hasSession) return findings;

    const triggerNode = firstPostRouteNode ?? firstSessionNode;
    if (!triggerNode) return findings;

    findings.push({
      ruleId: 'security/csrf-missing',
      severity: 'warn',
      message: 'POST routes without CSRF protection — state-changing requests are forgeable',
      file: filePath,
      line: getLine(triggerNode),
      column: getColumn(triggerNode),
      snippet: extractSnippet(source, getLine(triggerNode)),
      fix: 'Use csurf or csrf-csrf middleware on all state-changing routes',
    });

    return findings;
  },
};

export default rule;
