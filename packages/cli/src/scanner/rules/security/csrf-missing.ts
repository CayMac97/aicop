import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isStringLiteral, isMemberExpression } from '../../../utils/ast-helpers.js';

const CSRF_PACKAGES = new Set(['csurf', 'csrf-csrf', 'lusca']);
const SESSION_PACKAGES = new Set(['express-session', 'cookie-session']);
const EXPRESS_PACKAGES = new Set(['express', 'express-router']);
const JWT_PACKAGES = new Set(['express-jwt', 'passport-jwt', 'jsonwebtoken', 'jose', 'koa-jwt', 'fastify-jwt', '@auth/express']);
const HTTP_CLIENT_OBJECTS = new Set(['axios', 'got', 'request', 'supertest', 'http', 'https', 'fetch']);
const CSRF_IDENTIFIER_RE = /^(?:csrf|csrfProtection|csrfMiddleware|csrfToken|doubleCsrf|csurfProtection|lusca)/i;

function getRequireArg(node: TSESTree.CallExpression): string | null {
  if (!isIdentifier(node.callee) || (node.callee as TSESTree.Identifier).name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  return String((arg as TSESTree.StringLiteral).value);
}

function isHttpClientCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (isIdentifier(me.object)) {
    return HTTP_CLIENT_OBJECTS.has((me.object as TSESTree.Identifier).name.toLowerCase());
  }
  if (me.object.type === 'CallExpression') {
    const innerCallee = (me.object as TSESTree.CallExpression).callee;
    if (isIdentifier(innerCallee)) {
      return HTTP_CLIENT_OBJECTS.has((innerCallee as TSESTree.Identifier).name.toLowerCase());
    }
  }
  return false;
}

const WEBHOOK_PATH_RE = /\/webhook(?:s)?(?:\/|$)/i;

function isWebhookRoute(node: TSESTree.CallExpression): boolean {
  const firstArg = node.arguments[0];
  if (!firstArg || !isStringLiteral(firstArg as TSESTree.Expression)) return false;
  return WEBHOOK_PATH_RE.test(String((firstArg as TSESTree.StringLiteral).value));
}

function isExpressPostRoute(node: TSESTree.CallExpression): boolean {
  if (isHttpClientCall(node)) return false;
  if (isWebhookRoute(node)) return false;
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  return isIdentifier(me.property) && (me.property as TSESTree.Identifier).name === 'post';
}

function isCsrfArg(arg: TSESTree.Node): boolean {
  if (isIdentifier(arg)) return CSRF_IDENTIFIER_RE.test((arg as TSESTree.Identifier).name);
  if (arg.type === 'CallExpression') {
    const ce = arg as TSESTree.CallExpression;
    if (isIdentifier(ce.callee)) return CSRF_IDENTIFIER_RE.test((ce.callee as TSESTree.Identifier).name);
    if (isMemberExpression(ce.callee)) {
      const me = ce.callee as TSESTree.MemberExpression;
      if (isIdentifier(me.property)) return CSRF_IDENTIFIER_RE.test((me.property as TSESTree.Identifier).name);
    }
  }
  if (arg.type === 'ArrayExpression') {
    return (arg as TSESTree.ArrayExpression).elements.some((e) => e && isCsrfArg(e));
  }
  return false;
}

function routeHasCsrfMiddleware(node: TSESTree.CallExpression): boolean {
  return node.arguments.slice(1).some((arg) => isCsrfArg(arg));
}

function isGlobalUseWithCsrf(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || (me.property as TSESTree.Identifier).name !== 'use') return false;
  return node.arguments.some((arg) => isCsrfArg(arg));
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

    let hasExpressImport = false;
    let hasSession = false;
    let hasJwt = false;
    let hasGlobalCsrf = false;
    const unprotectedPostRoutes: TSESTree.CallExpression[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const pkg = getRequireArg(node);
        if (pkg) {
          if (CSRF_PACKAGES.has(pkg)) return; // import alone doesn't protect; we track usage
          if (SESSION_PACKAGES.has(pkg)) hasSession = true;
          if (EXPRESS_PACKAGES.has(pkg)) hasExpressImport = true;
          if (JWT_PACKAGES.has(pkg)) hasJwt = true;
          return;
        }
        if (isGlobalUseWithCsrf(node)) { hasGlobalCsrf = true; return; }
        if (isExpressPostRoute(node) && !routeHasCsrfMiddleware(node)) {
          unprotectedPostRoutes.push(node);
        }
      },
      ImportDeclaration(rawNode) {
        const decl = rawNode as TSESTree.ImportDeclaration;
        const src = String(decl.source.value);
        if (SESSION_PACKAGES.has(src)) hasSession = true;
        if (EXPRESS_PACKAGES.has(src)) hasExpressImport = true;
        if (JWT_PACKAGES.has(src)) hasJwt = true;
        // CSRF package import alone doesn't guarantee protection — track usage above
      },
    });

    if (hasGlobalCsrf) return findings;
    if (!hasExpressImport && !hasSession) return findings;
    // JWT/stateless APIs don't use cookies so CSRF doesn't apply
    if (hasJwt && !hasSession) return findings;
    if (unprotectedPostRoutes.length === 0) return findings;

    for (const triggerNode of unprotectedPostRoutes) {
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
    }

    return findings;
  },
};

export default rule;
