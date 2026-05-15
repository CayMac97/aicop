import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const UNSAFE_DESER_PACKAGES = new Set(['node-serialize', 'serialize-javascript']);

function isStaticArg(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

function checkUnserialize(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  let name: string | null = null;

  if (isIdentifier(node.callee)) {
    const n = (node.callee as TSESTree.Identifier).name;
    if (n === 'unserialize') name = 'unserialize';
  } else if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (isIdentifier(me.property) && (me.property as TSESTree.Identifier).name === 'unserialize') {
      const obj = isIdentifier(me.object) ? (me.object as TSESTree.Identifier).name : '?';
      name = `${obj}.unserialize`;
    }
  }

  if (!name) return null;

  const arg = node.arguments[0];
  if (!arg || isStaticArg(arg)) return null;

  return {
    ruleId: 'security/insecure-deserialization',
    severity: 'error',
    message: `${name}() allows RCE with crafted payloads`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use JSON.parse() instead — never deserialize untrusted data',
  };
}

function checkUnsafePackageRequire(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  const pkg = String((arg as TSESTree.StringLiteral).value);
  if (!UNSAFE_DESER_PACKAGES.has(pkg)) return null;
  return {
    ruleId: 'security/insecure-deserialization',
    severity: 'warn',
    message: `"${pkg}" can deserialize executable code — RCE risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Replace with JSON.parse() for data, or use a safe serialization format',
  };
}

const rule: Rule = {
  id: 'security/insecure-deserialization',
  name: 'Insecure Deserialization',
  category: 'security',
  severity: 'error',
  description: 'Detects use of node-serialize and similar packages that can execute code during deserialization',
  why: 'The node-serialize package deserializes JavaScript functions. A crafted payload can trigger arbitrary code execution (RCE) on the server.',
  fix: 'Use JSON.parse() for data exchange. Never deserialize untrusted user input with node-serialize or similar packages.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const deser = checkUnserialize(node, source, filePath);
        if (deser) { findings.push(deser); return; }
        const pkg = checkUnsafePackageRequire(node, source, filePath);
        if (pkg) findings.push(pkg);
      },
    });

    return findings;
  },
};

export default rule;
