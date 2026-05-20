import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

const AUTH_ROUTE_PATTERNS = [
  /\/login/i, /\/signin/i, /\/register/i, /\/signup/i,
  /\/forgot[-_]?password/i, /\/reset[-_]?password/i, /\/auth/i,
];
const RATE_LIMIT_IDENTIFIERS = /rateLimit|rateLimiter|limitRate|throttle|slowDown|expressRateLimit/i;
const HTTP_METHODS = new Set(['post', 'put', 'patch', 'delete']);

function isAuthRoute(pathValue: string): boolean {
  return AUTH_ROUTE_PATTERNS.some((p) => p.test(pathValue));
}

function isRouteDefinition(node: TSESTree.CallExpression): string | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name.toLowerCase();
  if (!HTTP_METHODS.has(method)) return null;
  const pathArg = node.arguments[0];
  if (!pathArg || !isStringLiteral(pathArg as TSESTree.Expression)) return null;
  return String((pathArg as TSESTree.StringLiteral).value);
}

function collectRateLimitVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init || node.init.type !== 'CallExpression') return;
      const call = node.init as TSESTree.CallExpression;
      if (!isIdentifier(call.callee)) return;
      if (!RATE_LIMIT_IDENTIFIERS.test((call.callee as TSESTree.Identifier).name)) return;
      if (node.id.type !== 'Identifier') return;
      vars.add((node.id as TSESTree.Identifier).name);
    },
  });
  return vars;
}

function middlewareIncludesRateLimit(
  args: Array<TSESTree.Expression | TSESTree.SpreadElement>,
  rateLimitVars: Set<string>,
): boolean {
  for (const arg of args) {
    if (arg.type === 'CallExpression') {
      const ce = arg as TSESTree.CallExpression;
      if (isIdentifier(ce.callee)) {
        if (RATE_LIMIT_IDENTIFIERS.test((ce.callee as TSESTree.Identifier).name)) return true;
      }
    }
    if (isIdentifier(arg)) {
      const name = (arg as TSESTree.Identifier).name;
      if (RATE_LIMIT_IDENTIFIERS.test(name) || rateLimitVars.has(name)) return true;
    }
  }
  return false;
}

const rule: Rule = {
  id: 'security/missing-rate-limit',
  name: 'Missing Rate Limit',
  category: 'security',
  severity: 'warn',
  description: 'Detects authentication endpoints that are not protected by rate limiting middleware',
  why: 'Without rate limiting, auth endpoints are vulnerable to brute-force and credential-stuffing attacks. An attacker can try thousands of passwords per second.',
  fix: 'Add express-rate-limit before your auth routes: app.use("/login", rateLimit({ windowMs: 15*60*1000, max: 10 }), loginHandler)',
  fixCode: `// npm install express-rate-limit
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // max 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again in 15 minutes' }
});

// Apply to auth routes:
app.post('/login', authLimiter, async (req, res) => { ... });
app.post('/register', authLimiter, async (req, res) => { ... });
app.post('/forgot-password', authLimiter, async (req, res) => { ... });`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    if (/[/\\](?:test|tests|spec|__tests__)[/\\]|\.(?:test|spec|cy)\.[jt]sx?$/i.test(filePath)) return findings;

    const rateLimitVars = collectRateLimitVars(ast);
    const seenEndpoints = new Set<string>();

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const routePath = isRouteDefinition(node);
        if (!routePath) return;
        if (!isAuthRoute(routePath)) return;
        if (middlewareIncludesRateLimit(node.arguments, rateLimitVars)) return;
        if (seenEndpoints.has(routePath)) return;
        seenEndpoints.add(routePath);
        findings.push({
          ruleId: 'security/missing-rate-limit',
          severity: 'warn',
          message: `Auth endpoint "${routePath}" has no rate limiting middleware`,
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: 'Install express-rate-limit and add: const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 })',
        });
      },
    });

    return findings;
  },
};

export default rule;
