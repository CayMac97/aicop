import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildExtendedTaintMap } from '../../../utils/taint-tracker.js';

const MONGO_QUERY_METHODS = new Set([
  'find',
  'findOne',
  'findOneAndUpdate',
  'findOneAndDelete',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'count',
  'countDocuments',
  'aggregate',
]);

const REQ_INPUT_SOURCES = new Set(['body', 'query', 'params']);

function isReqSource(node: TSESTree.Node): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  return (
    isIdentifier(me.object) &&
    me.object.name === 'req' &&
    isIdentifier(me.property) &&
    REQ_INPUT_SOURCES.has(me.property.name)
  );
}

function isReqInput(node: TSESTree.Node): boolean {
  if (isReqSource(node)) return true;
  if (!isMemberExpression(node)) return false;
  return isReqSource((node as TSESTree.MemberExpression).object);
}

function isSequelizeCall(node: TSESTree.CallExpression): boolean {
  const firstArg = node.arguments[0];
  if (!firstArg || firstArg.type !== 'ObjectExpression') return false;
  return firstArg.properties.some((p) => {
    if (p.type !== 'Property') return false;
    const prop = p as TSESTree.Property;
    return isIdentifier(prop.key) && prop.key.name === 'where';
  });
}

function buildVarMap(ast: ParsedAST): Map<string, TSESTree.Node> {
  const map = new Map<string, TSESTree.Node>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (node.id.type === 'Identifier' && node.init) {
        map.set(node.id.name, node.init);
      }
    }
  });
  return map;
}

function checkNodeForNoSQLInjection(
  node: TSESTree.Node,
  tainted: Set<string>,
  varMap: Map<string, TSESTree.Node>,
  visited = new Set<string>()
): { isVuln: boolean; hasWhere: boolean } {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return checkNodeForNoSQLInjection((node as TSESTree.TSAsExpression).expression, tainted, varMap, visited);
  }

  if (isReqInput(node)) return { isVuln: true, hasWhere: false };
  if (isIdentifier(node)) {
    const name = node.name;
    if (tainted.has(name)) return { isVuln: true, hasWhere: false };
    if (visited.has(name)) return { isVuln: false, hasWhere: false };
    visited.add(name);
    const init = varMap.get(name);
    if (init) return checkNodeForNoSQLInjection(init, tainted, varMap, visited);
    return { isVuln: false, hasWhere: false };
  }
  
  if (node.type === 'ObjectExpression') {
    let isVuln = false;
    let hasWhere = false;
    for (const p of node.properties) {
      if (p.type === 'Property') {
        const keyName = isIdentifier(p.key) ? p.key.name : (p.key.type === 'Literal' ? String(p.key.value) : '');
        const res = checkNodeForNoSQLInjection(p.value, tainted, varMap, visited);
        if (res.isVuln) {
          isVuln = true;
          if (keyName === '$where' || res.hasWhere) hasWhere = true;
        }
      }
    }
    return { isVuln, hasWhere };
  }
  
  if (node.type === 'ArrayExpression') {
    let isVuln = false;
    let hasWhere = false;
    for (const e of node.elements) {
      if (e) {
        const res = checkNodeForNoSQLInjection(e, tainted, varMap, visited);
        if (res.isVuln) {
          isVuln = true;
          if (res.hasWhere) hasWhere = true;
        }
      }
    }
    return { isVuln, hasWhere };
  }
  
  return { isVuln: false, hasWhere: false };
}

function hasTaintedVarNames(source: string, tainted: Set<string>, line: number): string[] {
  const priorLines = source.split('\n').slice(Math.max(0, line - 20), line);
  return Array.from(tainted).filter((name) =>
    priorLines.some((l) => l.includes(name)),
  );
}

function hasTypeOrPatternValidation(source: string, varNames: string[], line: number): boolean {
  const priorLines = source.split('\n').slice(Math.max(0, line - 20), line).join('\n');
  if (varNames.some((n) => priorLines.includes(`typeof ${n}`))) return true;
  if (varNames.some((n) => priorLines.includes(`.test(${n})`))) return true;
  const hasValidateFn =
    /\b(?:validate|sanitize|check|clean)[A-Za-z]*\s*\(/.test(priorLines) &&
    varNames.some((n) => priorLines.includes(n));
  const hasErrorCheck = /if\s*\(\s*errors\b/.test(priorLines);
  if (hasValidateFn) {
    if (/\b(?:sanitize|clean)\b/.test(priorLines)) return true;
    if (hasErrorCheck) return true;
  }
  return false;
}

const rule: Rule = {
  id: 'security/nosql-injection',
  name: 'NoSQL Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects MongoDB queries built with direct user input from req.body, req.query, or req.params',
  why: "MongoDB operators like {$gt:''} or {$where:'...'} in user input can bypass authentication and expose all documents",
  fix: "Sanitize input with mongo-sanitize or express-mongo-sanitize, or validate input type before using in queries",

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const tainted = buildExtendedTaintMap(ast);
    const varMap = buildVarMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const callee = node.callee;
        if (!isMemberExpression(callee)) return;
        if (!isIdentifier(callee.property)) return;
        const methodName = callee.property.name;
        if (!MONGO_QUERY_METHODS.has(methodName)) return;
        if (isSequelizeCall(node)) return;

        for (const arg of node.arguments) {
          const res = checkNodeForNoSQLInjection(arg, tainted, varMap);
          if (res.isVuln) {
            const taintedNamesHere = hasTaintedVarNames(source, tainted, getLine(node));
            if (hasTypeOrPatternValidation(source, taintedNamesHere, getLine(node))) break;
            
            let explain = 'MongoDB query built with direct user input — attacker can manipulate query logic';
            if (res.hasWhere) {
              explain += ' (CRITICAL: $where operator allows arbitrary code execution)';
            }

            findings.push({
              ruleId: 'security/nosql-injection',
              severity: 'error',
              message: 'NoSQL injection — user input used directly in MongoDB query',
              explain,
              confidence: 'HIGH',
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: rule.fix,
            });
            break;
          }
        }
      },
    });

    return findings;
  },
};

export default rule;
