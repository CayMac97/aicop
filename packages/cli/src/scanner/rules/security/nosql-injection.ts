import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildTaintMap } from '../../../utils/taint-tracker.js';

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
]);

const REQ_INPUT_SOURCES = new Set(['body', 'query', 'params']);

function isReqSource(node: TSESTree.Node): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  return (
    isIdentifier(me.object) &&
    (me.object as TSESTree.Identifier).name === 'req' &&
    isIdentifier(me.property) &&
    REQ_INPUT_SOURCES.has((me.property as TSESTree.Identifier).name)
  );
}

function isReqInput(node: TSESTree.Node): boolean {
  if (isReqSource(node)) return true;
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  return isReqSource(me.object);
}

function isSequelizeCall(node: TSESTree.CallExpression): boolean {
  const firstArg = node.arguments[0];
  if (!firstArg || firstArg.type !== 'ObjectExpression') return false;
  return (firstArg as TSESTree.ObjectExpression).properties.some((p) => {
    if (p.type !== 'Property') return false;
    const prop = p as TSESTree.Property;
    return isIdentifier(prop.key) && (prop.key as TSESTree.Identifier).name === 'where';
  });
}

function containsRawReqInput(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isReqInput(node)) return true;
  if (isIdentifier(node) && tainted.has((node as TSESTree.Identifier).name)) return true;
  if (node.type === 'CallExpression') return false;
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(
      (p) => p.type === 'Property' && containsRawReqInput((p as TSESTree.Property).value, tainted),
    );
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(
      (e) => e !== null && containsRawReqInput(e as TSESTree.Node, tainted),
    );
  }
  return false;
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
  // validate/sanitize/check function call with error check in the same context
  const hasValidateFn =
    /\b(?:validate|sanitize|check|clean)[A-Za-z]*\s*\(/.test(priorLines) &&
    varNames.some((n) => priorLines.includes(n));
  const hasErrorCheck = /if\s*\(\s*errors\b/.test(priorLines);
  if (hasValidateFn && hasErrorCheck) return true;
  return false;
}

const rule: Rule = {
  id: 'security/nosql-injection',
  name: 'NoSQL Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects MongoDB queries built with direct user input from req.body, req.query, or req.params',
  why: "MongoDB operators like {$gt:''} or {$where:'...'} in user input can bypass authentication and expose all documents",
  fix: "Sanitize input with mongo-sanitize or express-mongo-sanitize, or validate input type before using in queries: if (typeof req.body.username !== 'string') return res.status(400)",

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const tainted = buildTaintMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const { callee } = node;
        if (!isMemberExpression(callee)) return;
        const method = callee as TSESTree.MemberExpression;
        if (!isIdentifier(method.property)) return;
        const methodName = (method.property as TSESTree.Identifier).name;
        if (!MONGO_QUERY_METHODS.has(methodName)) return;
        if (isSequelizeCall(node)) return;

        for (const arg of node.arguments) {
          if (containsRawReqInput(arg as TSESTree.Node, tainted)) {
            const taintedNamesHere = hasTaintedVarNames(source, tainted, getLine(node));
            if (hasTypeOrPatternValidation(source, taintedNamesHere, getLine(node))) break;
            findings.push({
              ruleId: 'security/nosql-injection',
              severity: 'error',
              message: 'NoSQL injection — user input used directly in MongoDB query',
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: "Sanitize input with mongo-sanitize or express-mongo-sanitize, or validate input type before using in queries: if (typeof req.body.username !== 'string') return res.status(400)",
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
