import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

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

function containsRawReqInput(node: TSESTree.Node): boolean {
  if (isReqInput(node)) return true;
  if (node.type === 'CallExpression') return false;
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(
      (p) => p.type === 'Property' && containsRawReqInput((p as TSESTree.Property).value),
    );
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(
      (e) => e !== null && containsRawReqInput(e as TSESTree.Node),
    );
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
  fix: "Sanitize input with mongo-sanitize or express-mongo-sanitize, or validate input type before using in queries: if (typeof req.body.username !== 'string') return res.status(400)",

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

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
          if (containsRawReqInput(arg as TSESTree.Node)) {
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
