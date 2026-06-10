import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const HTTP_CLIENTS = new Set(['fetch', 'axios', 'got', 'request', 'superagent', 'undici', 'needle']);
const AXIOS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request']);
const USER_INPUT_PROPS = new Set(['params', 'body', 'query', 'headers']);

function isUserControlledArg(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (node.type === 'TemplateLiteral') {
    const tl = node as TSESTree.TemplateLiteral;
    return tl.expressions.some((e) => isUserControlledArg(e, taintResult, parentMap));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    return isUserControlledArg(be.left, taintResult, parentMap) || isUserControlledArg(be.right, taintResult, parentMap);
  }
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (isMemberExpression(me.object)) {
    const parent = me.object as TSESTree.MemberExpression;
    if (isIdentifier(parent.object) && (parent.object as TSESTree.Identifier).name === 'req') {
      if (isIdentifier(parent.property) && USER_INPUT_PROPS.has((parent.property as TSESTree.Identifier).name)) {
        return true;
      }
    }
  }
  return false;
}

const DIRECT_HTTP_CLIENTS = new Set(['got', 'request', 'needle', 'nodeFetch', 'superagent', 'axios']);

function isDirectHttpClientCall(node: TSESTree.CallExpression): string | null {
  if (!isIdentifier(node.callee)) return null;
  const name = (node.callee as TSESTree.Identifier).name;
  if (name === 'fetch' || DIRECT_HTTP_CLIENTS.has(name)) return name;
  return null;
}

function isHttpClientMethodCall(node: TSESTree.CallExpression): string | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object)) return null;
  const obj = (me.object as TSESTree.Identifier).name;
  if (!HTTP_CLIENTS.has(obj) && obj !== 'http' && obj !== 'https') return null;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  const isValid = obj === 'axios' ? AXIOS_METHODS.has(method) : method === 'get' || method === 'request';
  return isValid ? `${obj}.${method}` : null;
}

function hasUrlAllowlistValidation(node: TSESTree.Node, varName: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      walk(current, {
        NewExpression(rawNode) {
          const nNode = rawNode as TSESTree.NewExpression;
          if (isIdentifier(nNode.callee) && nNode.callee.name === 'URL') {
            if (nNode.arguments[0] && isIdentifier(nNode.arguments[0]) && nNode.arguments[0].name === varName) {
              hasGuard = true;
            }
          }
        },
        CallExpression(rawNode) {
          const cNode = rawNode as TSESTree.CallExpression;
          if (isMemberExpression(cNode.callee)) {
            const prop = cNode.callee.property;
            if (isIdentifier(prop)) {
              if (prop.name === 'test' || prop.name === 'includes' || prop.name === 'has') hasGuard = true;
              if (prop.name === 'startsWith') {
                if (isIdentifier(cNode.callee.object) && cNode.callee.object.name === varName) hasGuard = true;
              }
            }
          }
        }
      });
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }
  return hasGuard;
}

function checkHttpCall(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  let clientName = '';
  const directName = isDirectHttpClientCall(node);
  if (directName) {
    clientName = directName;
  } else {
    const methodName = isHttpClientMethodCall(node);
    if (!methodName) return null;
    clientName = methodName;
  }
  const urlArg = node.arguments[0];
  if (!urlArg || !isUserControlledArg(urlArg, taintResult, parentMap)) return null;
  if (isIdentifier(urlArg)) {
    const varName = (urlArg as TSESTree.Identifier).name;
    if (hasUrlAllowlistValidation(node, varName, parentMap)) return null;
  } else if (urlArg.type === 'NewExpression') {
    const newExpr = urlArg as TSESTree.NewExpression;
    if (isIdentifier(newExpr.callee) && newExpr.callee.name === 'URL') {
      return null;
    }
  }
  return {
    ruleId: 'security/ssrf-risk',
    severity: 'error',
    message: `${clientName}() called with a URL derived from user input — SSRF risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate URLs against an allowlist before making requests. Never pass user-supplied URLs directly to HTTP clients.',
  };
}

const rule: Rule = {
  id: 'security/ssrf-risk',
  name: 'SSRF Risk',
  category: 'security',
  severity: 'error',
  description: 'Detects HTTP requests where the URL is constructed from user-controlled input (Server-Side Request Forgery)',
  why: 'SSRF allows attackers to make your server send requests to internal services (AWS metadata, localhost, internal APIs), leaking credentials and bypassing network controls.',
  fix: 'Validate and allowlist URLs before making requests. Use URL parsing to check protocol and hostname against a safe list.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const finding = checkHttpCall(rawNode as TSESTree.CallExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
    });

    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();

    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode);
      walk(crossCall.externalNode, {
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          const finding = checkHttpCall(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
          if (finding) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/ssrf-risk',
              severity: 'error',
              message: 'Cross-file SSRF Risk: User input flows into HTTP client in imported function',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: 'Validate URLs against an allowlist before making requests. Never pass user-supplied URLs directly to HTTP clients.',
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
