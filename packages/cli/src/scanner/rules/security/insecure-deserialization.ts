import { TSESTree } from '@typescript-eslint/typescript-estree';
import fs from 'node:fs';
import path from 'node:path';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';
import { collectModuleBindings, isBoundModuleCall, ModuleBindings } from '../../../utils/module-bindings.js';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const UNSAFE_DESER_PACKAGES = new Set(['node-serialize', 'js-yaml']);


const YAML_LOAD_EXPORTS = new Set(['load', 'loadAll']);
const SAFE_YAML_SCHEMAS = new Set(['JSON_SCHEMA', 'CORE_SCHEMA', 'FAILSAFE_SCHEMA']);
const SAFE_YAML_EXPORTS = new Set(['safeLoad', 'safeLoadAll', 'safeDump', 'dump']);
const yamlSafeCache = new Map<string, boolean>();

/**
 * js-yaml >= 4 makes load() safe by default (no !!js/function), so yaml.load() is only a
 * risk on js-yaml <= 3. We look at the nearest package.json that declares js-yaml.
 * Unknown version => false (keep reporting).
 */
function isModernJsYaml(filePath: string): boolean {
  let dir = path.dirname(path.resolve(filePath));
  const visited: string[] = [];
  let result = false;
  for (let i = 0; i < 12; i++) {
    const cached = yamlSafeCache.get(dir);
    if (cached !== undefined) { result = cached; break; }
    visited.push(dir);
    const pkgPath = path.join(dir, 'package.json');
    let found = false;
    try {
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, Record<string, string> | undefined>;
        const spec = pkg.dependencies?.['js-yaml'] ?? pkg.devDependencies?.['js-yaml'];
        if (typeof spec === 'string') {
          const m = /(\d+)/.exec(spec);
          result = m ? Number(m[1]) >= 4 : false;
          found = true;
        }
      }
    } catch { /* unreadable package.json => unknown */ }
    if (found) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  for (const d of visited) yamlSafeCache.set(d, result);
  return result;
}

function isStaticArg(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

/** load(x, { schema: JSON_SCHEMA | CORE_SCHEMA | FAILSAFE_SCHEMA }) restricts js-yaml to plain data types */
function hasSafeYamlSchema(node: TSESTree.CallExpression): boolean {
  const opts = node.arguments[1];
  if (!opts || opts.type !== 'ObjectExpression') return false;
  return opts.properties.some((p) => {
    if (p.type !== 'Property' || !isIdentifier(p.key) || p.key.name !== 'schema') return false;
    const v = p.value;
    if (isIdentifier(v)) return SAFE_YAML_SCHEMAS.has(v.name);
    return isMemberExpression(v) && isIdentifier(v.property) && SAFE_YAML_SCHEMAS.has(v.property.name);
  });
}

function checkUnserialize(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>, yamlBindings: ModuleBindings): Finding | null {
  let name: string | null = null;
  let isYamlLoad = false;

  // js-yaml bound under any local name: jsYaml.load(...), const { load } = require('js-yaml'), ...
  if (isBoundModuleCall(node.callee, yamlBindings, YAML_LOAD_EXPORTS)) {
    name = isMemberExpression(node.callee) && isIdentifier(node.callee.object) ? `${node.callee.object.name}.load` : 'load';
    isYamlLoad = true;
  }

  if (isYamlLoad) {
    // handled above
  } else if (isIdentifier(node.callee)) {
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
    if (isModernJsYaml(filePath)) return null;
    if (hasSafeYamlSchema(node)) return null;
    const userControlled = isNodeContextuallyTainted(arg, taintResult, parentMap);
    return {
      ruleId: 'security/insecure-deserialization',
      severity: userControlled ? 'error' : 'warn',
      fixedSeverity: true,
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
  if (pkg === 'js-yaml' && isModernJsYaml(filePath)) return null;
  return {
    ruleId: 'security/insecure-deserialization',
    severity: 'info',
    fixedSeverity: true,
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
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);
    const yamlBindings = collectModuleBindings(ast, new Set(['js-yaml']));

    walk(ast, {
      ImportDeclaration(rawNode) {
        const node = rawNode as TSESTree.ImportDeclaration;
        if (!isStringLiteral(node.source)) return;
        const pkg = String((node.source as TSESTree.StringLiteral).value);
        if (UNSAFE_DESER_PACKAGES.has(pkg)) {
          if (pkg === 'js-yaml') {
            if (isModernJsYaml(filePath)) return;
            // importing only the safe API (safeLoad/dump ...) is not a risk
            const specs = node.specifiers;
            const onlySafe = specs.length > 0 && specs.every(
              (sp) => sp.type === 'ImportSpecifier' && SAFE_YAML_EXPORTS.has((sp.imported as TSESTree.Identifier).name),
            );
            if (onlySafe) return;
          }
          findings.push({
            ruleId: 'security/insecure-deserialization',
            severity: 'info', // dependency note; concrete load()/unserialize() calls are checked separately
            fixedSeverity: true,
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
        const finding1 = checkUnserialize(node, source, filePath, taintResult, parentMap, yamlBindings);
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
