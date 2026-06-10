import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const FS_DANGER_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'appendFile', 'appendFileSync', 'unlink', 'unlinkSync',
  'rmdir', 'rmdirSync', 'stat', 'statSync', 'access', 'accessSync',
  'open', 'openSync', 'createReadStream', 'createWriteStream',
]);
const USER_INPUT_PROPS = new Set(['params', 'body', 'query', 'headers', 'cookies']);

function isDirectUserInput(node: TSESTree.Node): boolean {
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

function isUserInputExpr(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (isDirectUserInput(node)) return true;
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInputExpr(be.left, taintResult, parentMap) || isUserInputExpr(be.right, taintResult, parentMap);
  }
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInputExpr(e, taintResult, parentMap));
  }
  return false;
}

function checkFsCall(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const objName = (me.object as TSESTree.Identifier).name;
  if (objName !== 'fs' && objName !== 'fse') return null;
  const methodName = (me.property as TSESTree.Identifier).name;
  if (!FS_DANGER_METHODS.has(methodName)) return null;
  const pathArg = node.arguments[0];
  if (!pathArg) return null;
  if (isStringLiteral(pathArg as TSESTree.Expression)) return null;
  if (!isUserInputExpr(pathArg, taintResult, parentMap)) return null;
  return {
    ruleId: 'security/path-traversal',
    severity: 'error',
    message: `fs.${methodName}() with user-controlled path — traversal risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate: const safe = path.resolve(base, input); if (!safe.startsWith(base)) throw new Error("Invalid path")',
  };
}

function linesAfter(source: string, line: number, count: number): string {
  const all = source.split('\n');
  return all.slice(line, line + count).join('\n');  // line is 1-indexed; slice at index `line` = next line
}

function checkPathJoin(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'path') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'join' && method !== 'resolve') return null;
  const hasUserInput = node.arguments.some((arg) => isUserInputExpr(arg, taintResult, parentMap));
  if (!hasUserInput) return null;
  const contextAfter = linesAfter(source, getLine(node), 6);
  if (contextAfter.includes('.startsWith(')) return null;
  return {
    ruleId: 'security/path-traversal',
    severity: 'error',
    message: `path.${method}() with unvalidated user input`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate: const full = path.resolve(base, input); if (!full.startsWith(base)) throw new Error("Invalid path")',
  };
}

function isPathLikeString(node: TSESTree.Node): boolean {
  if (!isStringLiteral(node)) return false;
  const val = String((node as TSESTree.StringLiteral).value);
  return val.startsWith('/') || val.startsWith('./') || val.startsWith('../');
}

function isDirnameOrRelPath(node: TSESTree.Node): boolean {
  if (isIdentifier(node) && (node as TSESTree.Identifier).name === '__dirname') return true;
  return isPathLikeString(node);
}

function checkPathConcatBinary(node: TSESTree.BinaryExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (node.operator !== '+') return null;

  const left = node.left;
  const right = node.right;
  const leftHasUser = isUserInputExpr(left, taintResult, parentMap);
  const rightHasUser = isUserInputExpr(right, taintResult, parentMap);

  if (!leftHasUser && !rightHasUser) return null;

  const isSuspiciousString = (n: TSESTree.Node) => {
    if (!isStringLiteral(n)) return false;
    const val = String((n as TSESTree.StringLiteral).value);
    return val.includes('/') || val.includes('\\') || val.includes('dir') || val.includes('path') || val.includes('file');
  };

  if (!isSuspiciousString(left) && !isSuspiciousString(right)) return null;

  return {
    ruleId: 'security/path-traversal',
    severity: 'error',
    message: 'path string built with user input — traversal risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Resolve and validate path stays within base directory before any file operation',
  };
}

const rule: Rule = {
  id: 'security/path-traversal',
  name: 'Path Traversal',
  category: 'security',
  severity: 'error',
  description: 'Detects file system operations with user-controlled paths that could allow directory traversal',
  why: 'Path traversal (../../../etc/passwd) lets attackers read or write arbitrary files on your server, leading to credential theft or remote code execution.',
  fix: 'Always resolve paths and verify they stay within the intended base directory before performing file operations.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const fsF = checkFsCall(node, source, filePath, taintResult, parentMap);
        if (fsF) { findings.push(fsF); return; }
        const pathF = checkPathJoin(node, source, filePath, taintResult, parentMap);
        if (pathF) {
          const afterLines = linesAfter(source, pathF.line, 6);
          const hasSendFile = afterLines.includes('.sendFile(') || afterLines.includes('.download(');
          const hasSafeStringUse = !hasSendFile && (afterLines.includes('res.send(') || afterLines.includes('res.json('));
          if (!hasSafeStringUse) findings.push(pathF);
        }
      },
      BinaryExpression(rawNode) {
        const finding = checkPathConcatBinary(rawNode as TSESTree.BinaryExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (node.operator === '+=') {
          // Bug AP fix: check += operations
          if (isUserInputExpr(node.right, taintResult, parentMap)) {
            // Simplified check: if right is tainted, and we're appending it to something, flag it as risk
            findings.push({
              ruleId: 'security/path-traversal',
              severity: 'error',
              message: 'path string built with user input (+=) — traversal risk',
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: 'Resolve and validate path stays within base directory before any file operation',
            });
          }
        }
      }
    });

    const { getCrossFileTaints } = require('../../../utils/taint-tracker.js');
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
          const fsF = checkFsCall(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
          if (fsF) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/path-traversal',
              severity: 'error',
              message: 'Cross-file path traversal: user input flows into imported fs function',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: fsF.fix,
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
