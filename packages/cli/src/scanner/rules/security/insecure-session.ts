import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isStringLiteral, isCallExpression } from '../../../utils/ast-helpers.js';

const SESSION_PACKAGES = new Set(['express-session', 'cookie-session']);

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

function checkSessionOptions(node: TSESTree.CallExpression, source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const optArg = node.arguments[0];
  if (!optArg || optArg.type !== 'ObjectExpression') return findings;
  const opts = optArg as TSESTree.ObjectExpression;

  const secretProp = findProp(opts, 'secret');
  if (secretProp && isStringLiteral(secretProp.value as TSESTree.Expression)) {
    const val = String((secretProp.value as TSESTree.StringLiteral).value);
    if (val.length < 20) {
      findings.push({
        ruleId: 'security/insecure-session',
        severity: 'warn',
        message: 'weak session secret — use a long random string from process.env',
        file: filePath,
        line: getLine(secretProp),
        column: getColumn(secretProp),
        snippet: extractSnippet(source, getLine(secretProp)),
        fix: 'Set secret from process.env: session({ secret: process.env.SESSION_SECRET })',
      });
    }
  }

  const cookieProp = findProp(opts, 'cookie');
  if (cookieProp && cookieProp.value.type === 'ObjectExpression') {
    const cookieObj = cookieProp.value as TSESTree.ObjectExpression;

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
    if (secureProp && secureProp.value.type === 'Literal') {
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
  }

  const resaveProp = findProp(opts, 'resave');
  if (!resaveProp) {
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

  return findings;
}

const rule: Rule = {
  id: 'security/insecure-session',
  name: 'Insecure Session Configuration',
  category: 'security',
  severity: 'error',
  description: 'Detects insecure express-session configurations including weak secrets and unsafe cookie options',
  why: 'Weak session secrets allow session forgery. httpOnly:false exposes cookies to XSS. secure:false transmits session cookies over HTTP, enabling interception.',
  fix: 'Use a strong random secret from process.env, set httpOnly:true and secure:true on cookies',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const sessionVarNames = new Set<string>();

    walk(ast, {
      VariableDeclarator(rawNode) {
        const decl = rawNode as TSESTree.VariableDeclarator;
        if (!decl.init || !isCallExpression(decl.init)) return;
        const pkg = getRequireArg(decl.init as TSESTree.CallExpression);
        if (pkg && SESSION_PACKAGES.has(pkg) && isIdentifier(decl.id)) {
          sessionVarNames.add((decl.id as TSESTree.Identifier).name);
        }
      },
      ImportDeclaration(rawNode) {
        const decl = rawNode as TSESTree.ImportDeclaration;
        if (!SESSION_PACKAGES.has(String(decl.source.value))) return;
        for (const spec of decl.specifiers) {
          if (spec.type === 'ImportDefaultSpecifier') {
            sessionVarNames.add(spec.local.name);
          }
        }
      },
    });

    if (sessionVarNames.size === 0) return findings;

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (!isIdentifier(node.callee)) return;
        if (!sessionVarNames.has((node.callee as TSESTree.Identifier).name)) return;
        findings.push(...checkSessionOptions(node, source, filePath));
      },
    });

    return findings;
  },
};

export default rule;
