import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const UNSAFE_DESER_PACKAGES = new Set(['node-serialize', 'serialize-javascript', 'js-yaml']);

function isStaticArg(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

function checkUnserialize(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  let name: string | null = null;
  let isYamlLoad = false;

  if (isIdentifier(node.callee)) {
    const n = (node.callee as TSESTree.Identifier).name;
    if (n === 'unserialize') name = 'unserialize';
  } else if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (isIdentifier(me.property)) {
      if ((me.property as TSESTree.Identifier).name === 'unserialize') {
        const obj = isIdentifier(me.object) ? (me.object as TSESTree.Identifier).name : '?';
        name = `${obj}.unserialize`;
      } else if ((me.property as TSESTree.Identifier).name === 'load') {
        if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'yaml') {
          name = 'yaml.load';
          isYamlLoad = true;
        }
      }
    }
  }

  if (!name) return null;

  const arg = node.arguments[0];
  if (!arg || isStaticArg(arg)) return null;

  if (isYamlLoad) {
    return {
      ruleId: 'security/insecure-deserialization',
      severity: 'error',
      message: `${name}() allows RCE with crafted payloads in older js-yaml versions`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Use yaml.safeLoad() instead — never deserialize untrusted data with yaml.load()',
    };
  }

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

function checkBsonDeserialize(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || me.property.name !== 'deserialize') return null;
  if (isIdentifier(me.object) && me.object.name !== 'BSON') return null; // usually BSON.deserialize
  
  const optsArg = node.arguments[1];
  if (!optsArg || optsArg.type !== 'ObjectExpression') return null;
  
  let hasEvalFunctions = false;
  for (const prop of optsArg.properties) {
    if (prop.type === 'Property' && isIdentifier(prop.key) && prop.key.name === 'evalFunctions') {
      if (prop.value.type === 'Literal' && prop.value.value === true) {
        hasEvalFunctions = true;
      }
    }
  }
  
  if (hasEvalFunctions) {
    return {
      ruleId: 'security/insecure-deserialization',
      severity: 'error',
      message: 'BSON.deserialize() with evalFunctions: true allows RCE',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Disable evalFunctions or ensure input is strictly trusted. Executing functions from BSON is highly dangerous.',
    };
  }
  return null;
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
      ImportDeclaration(rawNode) {
        const node = rawNode as TSESTree.ImportDeclaration;
        if (!isStringLiteral(node.source)) return;
        const pkg = String((node.source as TSESTree.StringLiteral).value);
        if (UNSAFE_DESER_PACKAGES.has(pkg)) {
          findings.push({
            ruleId: 'security/insecure-deserialization',
            severity: 'warn',
            message: `"${pkg}" can deserialize executable code — RCE risk`,
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: 'Replace with JSON.parse() for data, or use a safe serialization format',
          });
        }
      },
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const finding1 = checkUnserialize(node, source, filePath);
        if (finding1) { findings.push(finding1); return; }
        const findingBson = checkBsonDeserialize(node, source, filePath);
        if (findingBson) { findings.push(findingBson); return; }
        const finding2 = checkUnsafePackageRequire(node, source, filePath);
        if (finding2) findings.push(finding2);
      },
    });

    return findings;
  },
};

export default rule;
