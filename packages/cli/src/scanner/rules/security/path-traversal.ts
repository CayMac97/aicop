import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const FS_DANGER_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'appendFile', 'appendFileSync', 'unlink', 'unlinkSync',
  'rmdir', 'rmdirSync', 'stat', 'statSync', 'access', 'accessSync',
  'open', 'openSync', 'createReadStream', 'createWriteStream',
  'copyFile', 'copyFileSync', 'rename', 'renameSync',
  'mkdir', 'mkdirSync', 'readdir', 'readdirSync'
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
  if (node.type === 'CallExpression') {
    const ce = node as TSESTree.CallExpression;
    if (isMemberExpression(ce.callee) && isIdentifier(ce.callee.property)) {
      if (ce.callee.property.name === 'join' && ce.callee.object.type === 'ArrayExpression') {
        return ce.callee.object.elements.some((e) => e && isUserInputExpr(e, taintResult, parentMap));
      }
      if (isIdentifier(ce.callee.object) && (ce.callee.object.name === 'path' || ce.callee.object.name === 'node:path')) {
        if (ce.callee.property.name === 'join' || ce.callee.property.name === 'resolve' || ce.callee.property.name === 'normalize') {
          return ce.arguments.some(arg => isUserInputExpr(arg, taintResult, parentMap));
        }
      }
    }
  }
  return false;
}

function isSuspiciousString(n: TSESTree.Node): boolean {
  if (!isStringLiteral(n)) return false;
  const val = String((n as TSESTree.StringLiteral).value);
  if (val.includes('<') && val.includes('>')) return false; // Likely HTML (XSS payload), not a file path
  return val.includes('/') || val.includes('\\') || val.includes('dir') || val.includes('path') || val.includes('file');
}


/**
 * Early-exit containment guard that precedes the sink in the same function:
 *   const p = path.resolve(base, input);
 *   if (!p.startsWith(base)) return res.status(403).end();   // <- guard
 *   fs.readFile(p, ...)
 */
function hasEarlyExitStartsWithGuard(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  const containsStartsWith = (n: TSESTree.Node): boolean => {
    let found = false;
    walk(n, {
      CallExpression(c) {
        const call = c as TSESTree.CallExpression;
        if (isMemberExpression(call.callee) && isIdentifier(call.callee.property) && call.callee.property.name === 'startsWith') found = true;
      },
    });
    return found;
  };
  const exitsEarly = (n: TSESTree.Node): boolean => {
    let exits = false;
    walk(n, {
      ReturnStatement() { exits = true; },
      ThrowStatement() { exits = true; },
    });
    return exits;
  };
  let child: TSESTree.Node = node;
  let cur: TSESTree.Node | undefined = parentMap.get(node);
  while (cur) {
    if (cur.type === 'BlockStatement' || cur.type === 'Program') {
      const body = cur.body as TSESTree.Node[];
      const idx = body.indexOf(child);
      for (let i = 0; i < idx; i++) {
        const stmt = body[i];
        if (stmt.type === 'IfStatement' && containsStartsWith(stmt.test) && exitsEarly(stmt.consequent)) return true;
      }
    }
    if (cur.type === 'FunctionDeclaration' || cur.type === 'FunctionExpression' || cur.type === 'ArrowFunctionExpression') break;
    child = cur;
    cur = parentMap.get(cur);
  }
  return false;
}


/**
 * Containment guard that FOLLOWS the path construction in the same block:
 *   const p = path.resolve(base, input);              // <- the flagged call
 *   if (!p.startsWith(base)) return res.sendStatus(403);   // <- later guard
 */
function hasLaterContainmentGuard(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  const containsStartsWith = (n: TSESTree.Node): boolean => {
    let found = false;
    walk(n, {
      CallExpression(c) {
        const call = c as TSESTree.CallExpression;
        if (isMemberExpression(call.callee) && isIdentifier(call.callee.property) && call.callee.property.name === 'startsWith') found = true;
      },
    });
    return found;
  };
  const exitsEarly = (n: TSESTree.Node): boolean => {
    let exits = false;
    walk(n, {
      ReturnStatement() { exits = true; },
      ThrowStatement() { exits = true; },
    });
    return exits;
  };
  let child: TSESTree.Node = node;
  let cur: TSESTree.Node | undefined = parentMap.get(node);
  while (cur) {
    if (cur.type === 'BlockStatement' || cur.type === 'Program') {
      const body = cur.body as TSESTree.Node[];
      const idx = body.indexOf(child);
      if (idx >= 0) {
        for (let i = idx + 1; i < body.length; i++) {
          const stmt = body[i];
          if (stmt.type === 'IfStatement' && containsStartsWith(stmt.test) && exitsEarly(stmt.consequent)) return true;
        }
      }
    }
    if (cur.type === 'FunctionDeclaration' || cur.type === 'FunctionExpression' || cur.type === 'ArrowFunctionExpression') break;
    child = cur;
    cur = parentMap.get(cur);
  }
  return false;
}

function checkFsCall(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  let objName = '';
  let methodName = '';
  if (isIdentifier(me.object) && isIdentifier(me.property)) {
    objName = me.object.name;
    methodName = me.property.name;
  } else if (isMemberExpression(me.object) && isIdentifier(me.object.object) && isIdentifier(me.object.property) && isIdentifier(me.property)) {
    if (me.object.object.name === 'fs' && me.object.property.name === 'promises') {
      objName = 'fs';
      methodName = me.property.name;
    }
  }
  if (objName !== 'fs' && objName !== 'fse') return null;
  if (!FS_DANGER_METHODS.has(methodName)) return null;
  const pathArg = node.arguments[0];
  if (!pathArg) return null;
  if (isStringLiteral(pathArg as TSESTree.Expression)) return null;
  const isUserInput = isUserInputExpr(pathArg, taintResult, parentMap);
  if (!isUserInput) return null;
  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      let conditionNode: TSESTree.Node | undefined;
      if (current.type === 'IfStatement') conditionNode = current.test;
      else if (current.type === 'ConditionalExpression') conditionNode = current.test;
      else if (current.type === 'LogicalExpression') conditionNode = current.left;
      
      if (conditionNode) {
        walk(conditionNode, {
          CallExpression(cNode) {
            const call = cNode as TSESTree.CallExpression;
            if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)) {
              if (call.callee.property.name === 'startsWith') {
                hasGuard = true;
              }
            }
          }
        });
      }
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }

  if (hasGuard || hasEarlyExitStartsWithGuard(node, parentMap)) return null;

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

function checkSendFile(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const objName = (me.object as TSESTree.Identifier).name;
  if (objName !== 'res' && objName !== 'reply') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'sendFile' && method !== 'download') return null;

  const arg = node.arguments[0];
  if (!arg || !isUserInputExpr(arg, taintResult, parentMap)) return null;

  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      // res.sendFile isn't guarded simply by being in an if statement.
      // Need real path validation.
      let conditionNode: TSESTree.Node | undefined;
      if (current.type === 'IfStatement') conditionNode = current.test;
      else if (current.type === 'ConditionalExpression') conditionNode = current.test;
      else if (current.type === 'LogicalExpression') conditionNode = current.left;

      if (conditionNode) {
        walk(conditionNode, {
          CallExpression(cNode) {
            const call = cNode as TSESTree.CallExpression;
            if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)) {
              if (call.callee.property.name === 'startsWith' || call.callee.property.name === 'resolve') {
                hasGuard = true;
              }
            }
          }
        });
      }
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }

  if (hasGuard || hasEarlyExitStartsWithGuard(node, parentMap)) return null;

  return {
    ruleId: 'security/path-traversal',
    severity: 'error',
    message: `res.${method}() with user-controlled path — traversal / arbitrary file read risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate paths before sending files, or use the `root` option in res.sendFile() to restrict directory access.',
  };
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

  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      let conditionNode: TSESTree.Node | undefined;
      if (current.type === 'IfStatement') conditionNode = current.test;
      else if (current.type === 'ConditionalExpression') conditionNode = current.test;
      else if (current.type === 'LogicalExpression') conditionNode = current.left;
      
      if (conditionNode) {
        walk(conditionNode, {
          CallExpression(cNode) {
            const call = cNode as TSESTree.CallExpression;
            if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)) {
              if (call.callee.property.name === 'startsWith') {
                hasGuard = true;
              }
            }
          }
        });
      }
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }

  if (hasGuard || hasEarlyExitStartsWithGuard(node, parentMap)) return null;

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





function checkPathConcatBinary(node: TSESTree.BinaryExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (node.operator !== '+') return null;

  const left = node.left;
  const right = node.right;
  const leftHasUser = isUserInputExpr(left, taintResult, parentMap);
  const rightHasUser = isUserInputExpr(right, taintResult, parentMap);

  if (!leftHasUser && !rightHasUser) return null;

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
        
        const sendF = checkSendFile(node, source, filePath, taintResult, parentMap);
        if (sendF) { findings.push(sendF); return; }

        const pathF = checkPathJoin(node, source, filePath, taintResult, parentMap);
        if (pathF) {
          // Verify if it's used immediately in a safe way without guards
          let current: TSESTree.Node | undefined = node;
          let isSafe = false;
          while (current) {
            const parent = parentMap.get(current);
            if (parent && parent.type === 'CallExpression') {
              const call = parent as TSESTree.CallExpression;
              if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)) {
                const name = call.callee.property.name;
                if (name === 'send' || name === 'json') {
                  isSafe = true;
                  break;
                }
              }
            }
            if (parent && (parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression' || parent.type === 'BlockStatement')) break;
            current = parent;
          }
          if (!isSafe && !hasLaterContainmentGuard(node, parentMap)) findings.push(pathF);
        }
      },
      BinaryExpression(rawNode) {
        const finding = checkPathConcatBinary(rawNode as TSESTree.BinaryExpression, source, filePath, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (node.operator === '+=') {
          if (isUserInputExpr(node.right, taintResult, parentMap)) {
            // Check if left side is suspicious string or left side's initialization is suspicious
            let leftSuspicious = false;
            if (node.left.type === 'Identifier') {
              const varName = (node.left as TSESTree.Identifier).name;
              if (varName.includes('dir') || varName.includes('path') || varName.includes('file')) leftSuspicious = true;
            }
            if (isSuspiciousString(node.left)) leftSuspicious = true;
            if (leftSuspicious) {
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
      }
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
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map(), sanitizedExpressions: new Set<string>() };
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
