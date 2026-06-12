import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

const AUTH_ROUTE_PATTERNS = [
  /\/login/i, /\/signin/i, /\/register/i, /\/signup/i,
  /\/forgot[-_]?password/i, /\/reset[-_]?password/i, /\/auth/i,
];
const RATE_LIMIT_IDENTIFIERS = /rateLimit|rateLimiter|limitRate|throttle|slowDown|expressRateLimit|limiter|brute/i;
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
  args: Array<TSESTree.Expression | TSESTree.SpreadElement | TSESTree.Node>,
  rateLimitVars: Set<string>,
): boolean {
  for (const arg of args) {
    if (arg.type === 'ArrayExpression') {
      if (middlewareIncludesRateLimit((arg as TSESTree.ArrayExpression).elements.filter(Boolean) as TSESTree.Expression[], rateLimitVars)) return true;
    }
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
    const rateLimitVars = collectRateLimitVars(ast);
    const seenEndpoints = new Set<string>();
    
    let hasGlobalRateLimit = false;

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (isMemberExpression(node.callee)) {
          const me = node.callee as TSESTree.MemberExpression;
          if (isIdentifier(me.property) && (me.property as TSESTree.Identifier).name === 'use') {
            if (middlewareIncludesRateLimit(node.arguments, rateLimitVars)) {
              const firstArg = node.arguments[0];
              let isGlobal = true;
              if (firstArg && isStringLiteral(firstArg as TSESTree.Expression)) {
                const prefix = String((firstArg as TSESTree.StringLiteral).value);
                if (prefix !== '/' && prefix !== '*' && !isAuthRoute(prefix)) {
                  isGlobal = false;
                }
              }
              if (isGlobal) {
                hasGlobalRateLimit = true;
              }
            }
          }
        }
        
        const routePath = isRouteDefinition(node);
        if (routePath && isAuthRoute(routePath) && !middlewareIncludesRateLimit(node.arguments, rateLimitVars) && !seenEndpoints.has(routePath)) {
          seenEndpoints.add(routePath);
          (node as any)._missingRateLimitPath = routePath;
        }

        const hapiFinding = checkHapiRoute(node, source, filePath);
        if (hapiFinding) {
          // Delay finding pushing to end just in case there's a global rate limit we detect later.
          // For simplicity we'll just push it to a separate array or attach it.
          (node as any)._missingHapiRateLimitFinding = hapiFinding;
        }
      },
    });

    if (hasGlobalRateLimit) return findings;

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if ((node as any)._missingRateLimitPath) {
          findings.push({
            ruleId: 'security/missing-rate-limit',
            severity: 'warn',
            message: `Auth endpoint "${(node as any)._missingRateLimitPath}" has no rate limiting middleware`,
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: 'Install express-rate-limit and add: const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 })',
          });
        }
        if ((node as any)._missingHapiRateLimitFinding) {
          findings.push((node as any)._missingHapiRateLimitFinding);
        }
      }
    });

    return findings;
  },
};

function checkHapiRoute(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if (me.property.name !== 'route') return null;
  
  const arg = node.arguments[0];
  if (!arg || arg.type !== 'ObjectExpression') return null;
  
  let pathStr: string | null = null;
  let methodStr: string | null = null;
  let hasRateLimitPlugin = false;
  
  for (const prop of arg.properties) {
    if (prop.type !== 'Property') continue;
    if (isIdentifier(prop.key)) {
      if (prop.key.name === 'path' && isStringLiteral(prop.value as TSESTree.Expression)) {
        pathStr = String((prop.value as TSESTree.StringLiteral).value);
      } else if (prop.key.name === 'method' && isStringLiteral(prop.value as TSESTree.Expression)) {
        methodStr = String((prop.value as TSESTree.StringLiteral).value).toLowerCase();
      } else if ((prop.key.name === 'config' || prop.key.name === 'options') && prop.value.type === 'ObjectExpression') {
        for (const configProp of prop.value.properties) {
          if (configProp.type !== 'Property') continue;
          if (isIdentifier(configProp.key) && configProp.key.name === 'plugins' && configProp.value.type === 'ObjectExpression') {
             for (const pluginProp of configProp.value.properties) {
               if (pluginProp.type !== 'Property') continue;
               let pluginName = '';
               if (isIdentifier(pluginProp.key)) pluginName = pluginProp.key.name;
               else if (pluginProp.key.type === 'Literal') pluginName = String(pluginProp.key.value);
               
               if (RATE_LIMIT_IDENTIFIERS.test(pluginName)) {
                 hasRateLimitPlugin = true;
               }
             }
          }
        }
      }
    }
  }
  
  if (pathStr && methodStr && HTTP_METHODS.has(methodStr) && isAuthRoute(pathStr) && !hasRateLimitPlugin) {
    return {
      ruleId: 'security/missing-rate-limit',
      severity: 'warn',
      message: `Hapi auth endpoint "${pathStr}" has no rate limiting plugin configured`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: "Add 'hapi-rate-limit' or similar to the route's options.plugins configuration",
    };
  }
  
  return null;
}

export default rule;
