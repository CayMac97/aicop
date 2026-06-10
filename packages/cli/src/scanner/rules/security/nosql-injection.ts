import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { crossFileCache } from '../../cross-file/cross-file-resolver.js';
import { readFileContent } from '../../../utils/file-utils.js';

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

function buildParentMap(ast: TSESTree.Node): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) {
      if (parent) map.set(node, parent);
    },
  });
  return map;
}

function getVarInitInScope(name: string, startNode: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): TSESTree.Node | null {
  let current: TSESTree.Node | undefined = startNode;
  while (current) {
    if (current.type === 'BlockStatement' || current.type === 'Program') {
      const body = (current as any).body;
      if (Array.isArray(body)) {
        for (const stmt of body) {
          if (stmt.type === 'VariableDeclaration') {
            for (const decl of stmt.declarations) {
              if (decl.id.type === 'Identifier' && decl.id.name === name) {
                return decl.init;
              }
            }
          }
        }
      }
    }
    current = parentMap.get(current);
  }
  return null;
}

function checkNodeForNoSQLInjection(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>,
  visited = new Set<string>()
): { isVuln: boolean; hasWhere: boolean } {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return checkNodeForNoSQLInjection((node as TSESTree.TSAsExpression).expression, taintResult, parentMap, visited);
  }

  if (isReqInput(node)) return { isVuln: true, hasWhere: false };
  if (isIdentifier(node)) {
    if (isNodeContextuallyTainted(node, taintResult, parentMap)) return { isVuln: true, hasWhere: false };
    const name = node.name;
    if (visited.has(name)) return { isVuln: false, hasWhere: false };
    visited.add(name);
    const init = getVarInitInScope(name, node, parentMap);
    if (init) return checkNodeForNoSQLInjection(init, taintResult, parentMap, visited);
    return { isVuln: false, hasWhere: false };
  }
  
  if (node.type === 'ObjectExpression') {
    let isVuln = false;
    let hasWhere = false;
    for (const p of node.properties) {
      if (p.type === 'Property') {
        const keyName = isIdentifier(p.key) ? p.key.name : (p.key.type === 'Literal' ? String(p.key.value) : '');
        const res = checkNodeForNoSQLInjection(p.value, taintResult, parentMap, visited);
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
        const res = checkNodeForNoSQLInjection(e, taintResult, parentMap, visited);
        if (res.isVuln) {
          isVuln = true;
          if (res.hasWhere) hasWhere = true;
        }
      }
    }
    return { isVuln, hasWhere };
  }
  
  if (node.type === 'CallExpression') {
    if (isNodeContextuallyTainted(node, taintResult, parentMap)) {
      return { isVuln: true, hasWhere: false };
    }
    const call = node as TSESTree.CallExpression;
    for (const arg of call.arguments) {
      const res = checkNodeForNoSQLInjection(arg, taintResult, parentMap, visited);
      if (res.isVuln) return res;
    }
  }
  
  return { isVuln: false, hasWhere: false };
}

function hasTaintedVarNames(source: string, taintResult: TaintResult, line: number): string[] {
  const priorLines = source.split('\n').slice(Math.max(0, line - 20), line);
  const allTaintedNames = new Set(taintResult.globalTaints);
  for (const lt of taintResult.localTaints.values()) {
    lt.forEach(name => allTaintedNames.add(name));
  }
  return Array.from(allTaintedNames).filter((name) =>
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
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

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
          const res = checkNodeForNoSQLInjection(arg, taintResult, parentMap);
          if (res.isVuln) {
            const taintedNamesHere = hasTaintedVarNames(source, taintResult, getLine(node));
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

    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();
    
    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode);
      walk(crossCall.externalNode, {
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          const callee = node.callee;
          if (!isMemberExpression(callee)) return;
          if (!isIdentifier(callee.property)) return;
          const methodName = callee.property.name;
          if (!MONGO_QUERY_METHODS.has(methodName)) return;
          if (isSequelizeCall(node)) return;

          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;

          let isVulnerable = false;
          for (const arg of node.arguments) {
            const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
            const res = checkNodeForNoSQLInjection(arg, crossTaintResult, extParentMap);
            if (res.isVuln) {
              const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
              const sourceLine = getLine(sourceNode);
              const taintedNamesHere = hasTaintedVarNames(source, taintResult, sourceLine);
              if (!hasTypeOrPatternValidation(source, taintedNamesHere, sourceLine)) {
                isVulnerable = true;
                break;
              }
            }
          }
          
          if (isVulnerable) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/nosql-injection',
              severity: 'error',
              message: 'Cross-file NoSQL injection — user input flows into MongoDB query in imported function',
              explain: 'User input flows into an imported function that executes a NoSQL query',
              confidence: 'HIGH',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: 'Sanitize input with mongo-sanitize or express-mongo-sanitize, or validate input type before using in queries',
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
