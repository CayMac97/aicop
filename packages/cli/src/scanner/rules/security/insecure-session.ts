import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isStringLiteral, isCallExpression } from '../../../utils/ast-helpers.js';

const SESSION_PACKAGES = new Set(['express-session', 'cookie-session', '@fastify/secure-session', '@fastify/session', 'fastify-session', 'koa-session', 'koa-generic-session']);

function getRequireArg(node: TSESTree.CallExpression): string | null {
  if (!isIdentifier(node.callee) || node.callee.name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  return String((arg as TSESTree.StringLiteral).value);
}

function findProp(obj: TSESTree.ObjectExpression, key: string): TSESTree.Property | null {
  for (const p of obj.properties) {
    if (p.type !== 'Property') continue;
    const prop = p as TSESTree.Property;
    if (isIdentifier(prop.key) && (prop.key as TSESTree.Identifier).name === key) return prop;
    if (isStringLiteral(prop.key as TSESTree.Expression) && (prop.key as TSESTree.StringLiteral).value === key) return prop;
  }
  return null;
}

function checkSessionOptions(node: TSESTree.CallExpression, source: string, filePath: string, pkgName?: string): Finding[] {
  const findings: Finding[] = [];
  const optArg = node.arguments[0];
  if (!optArg || optArg.type !== 'ObjectExpression') return findings;
  const opts = optArg as TSESTree.ObjectExpression;

  const secretProp = findProp(opts, 'secret');
  if (secretProp) {
    const checkString = (node: TSESTree.Node) => {
      if (isStringLiteral(node as TSESTree.Expression)) {
        const val = String((node as TSESTree.StringLiteral).value);
        if (val.length < 20) {
          findings.push({
            ruleId: 'security/insecure-session',
            severity: 'warn',
            message: 'weak session secret — use a long random string from process.env',
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: 'Set secret from process.env: session({ secret: process.env.SESSION_SECRET })',
          });
        }
      }
    };
    if (secretProp.value.type === 'ArrayExpression') {
      for (const el of (secretProp.value as TSESTree.ArrayExpression).elements) {
        if (el) checkString(el);
      }
    } else {
      checkString(secretProp.value);
    }
  }

  const cookieProp = findProp(opts, 'cookie');
  const hasSpread = opts.properties.some((p) => p.type === 'SpreadElement');
  
  const isTopLevelCookieOpts = pkgName === 'cookie-session' || pkgName === 'koa-session' || pkgName === 'koa-generic-session';
  const cookieObj = isTopLevelCookieOpts ? opts : (cookieProp && cookieProp.value.type === 'ObjectExpression' ? cookieProp.value as TSESTree.ObjectExpression : null);

  if (cookieObj) {
    const httpOnlyProp = findProp(cookieObj, 'httpOnly');
    if (httpOnlyProp && httpOnlyProp.value.type === 'Literal') {
      const val = (httpOnlyProp.value as TSESTree.Literal).value;
      if (val === false) {
        findings.push({
          ruleId: 'security/insecure-session',
          severity: 'warn',
          message: 'session cookie httpOnly:false — accessible via JavaScript',
          file: filePath,
          line: getLine(httpOnlyProp),
          column: getColumn(httpOnlyProp),
          snippet: extractSnippet(source, getLine(httpOnlyProp)),
          fix: 'Remove httpOnly:false or set it to true to prevent JS access to the session cookie',
        });
      }
    }

    const secureProp = findProp(cookieObj, 'secure');
    if (secureProp) {
      if (secureProp.value.type === 'Literal') {
        const val = (secureProp.value as TSESTree.Literal).value;
        if (val === false) {
          findings.push({
            ruleId: 'security/insecure-session',
            severity: 'warn',
            message: 'session cookie secure:false — transmitted over HTTP',
            file: filePath,
            line: getLine(secureProp),
            column: getColumn(secureProp),
            snippet: extractSnippet(source, getLine(secureProp)),
            fix: 'Set secure:true in production — use: secure: process.env.NODE_ENV === "production"',
          });
        }
      }
    } else if (!hasSpread) {
      const lineNode = isTopLevelCookieOpts ? opts : cookieProp!;
      findings.push({
        ruleId: 'security/insecure-session',
        severity: 'warn',
        message: 'session cookie secure option missing — defaults to false (transmitted over HTTP)',
        file: filePath,
        line: getLine(lineNode),
        column: getColumn(lineNode),
        snippet: extractSnippet(source, getLine(lineNode)),
        fix: isTopLevelCookieOpts ? 'Set secure:true in production' : 'Set secure:true in production — use: cookie: { secure: process.env.NODE_ENV === "production" }',
      });
    }
  } else if (!hasSpread) {
    findings.push({
      ruleId: 'security/insecure-session',
      severity: 'warn',
      message: 'session cookie options missing — secure defaults to false',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Add cookie options and set secure:true in production',
    });
  }

  if (!isTopLevelCookieOpts) {
    const resaveProp = findProp(opts, 'resave');
    if (!resaveProp && !hasSpread) {
      findings.push({
        ruleId: 'security/insecure-session',
        severity: 'warn',
        message: 'session missing resave option — set resave:false to prevent unnecessary session saves',
        file: filePath,
        line: getLine(node),
        column: getColumn(node),
        snippet: extractSnippet(source, getLine(node)),
        fix: 'Add resave:false and saveUninitialized:false to session options',
      });
    }
  }

  return findings;
}

const rule: Rule = {
  id: 'security/insecure-session',
  name: 'Insecure Session Configuration',
  category: 'security',
  severity: 'warn',
  description: 'Detects insecure express-session configurations including weak secrets and unsafe cookie options',
  why: 'Weak session secrets allow session forgery. httpOnly:false exposes cookies to XSS. secure:false transmits session cookies over HTTP, enabling interception.',
  fix: 'Use a strong random secret from process.env, set httpOnly:true and secure:true on cookies',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const sessionVars = new Map<string, string>();

    walk(ast, {
      VariableDeclarator(rawNode) {
        const decl = rawNode as TSESTree.VariableDeclarator;
        if (!decl.init || !isCallExpression(decl.init)) return;
        const pkg = getRequireArg(decl.init as TSESTree.CallExpression);
        if (pkg && SESSION_PACKAGES.has(pkg) && isIdentifier(decl.id)) {
          sessionVars.set((decl.id as TSESTree.Identifier).name, pkg);
        }
      },
      ImportDeclaration(rawNode) {
        const decl = rawNode as TSESTree.ImportDeclaration;
        const pkg = String(decl.source.value);
        if (!SESSION_PACKAGES.has(pkg)) return;
        for (const spec of decl.specifiers) {
          if (spec.type === 'ImportDefaultSpecifier') {
            sessionVars.set(spec.local.name, pkg);
          }
        }
      },
    });

    if (sessionVars.size === 0) return findings;

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (isIdentifier(node.callee) && sessionVars.has(node.callee.name)) {
          findings.push(...checkSessionOptions(node, source, filePath, sessionVars.get(node.callee.name)));
        } else if (
          node.callee.type === 'MemberExpression' &&
          isIdentifier(node.callee.property) &&
          node.callee.property.name === 'register' &&
          node.arguments.length >= 2
        ) {
          const firstArg = node.arguments[0];
          let pkgName: string | undefined;
          if (isIdentifier(firstArg) && sessionVars.has(firstArg.name)) {
            pkgName = sessionVars.get(firstArg.name);
          } else if (firstArg.type === 'CallExpression') {
            const reqArg = getRequireArg(firstArg as TSESTree.CallExpression);
            if (reqArg && SESSION_PACKAGES.has(reqArg)) pkgName = reqArg;
          }
          if (pkgName && node.arguments[1].type === 'ObjectExpression') {
             const dummyNode = {
               ...node,
               arguments: [node.arguments[1]]
             } as TSESTree.CallExpression;
             findings.push(...checkSessionOptions(dummyNode, source, filePath, pkgName));
          }
        }
      },
    });

    return findings;
  },
};

export default rule;
