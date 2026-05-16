import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

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

function isUserInputExpr(node: TSESTree.Node): boolean {
  if (isDirectUserInput(node)) return true;
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInputExpr(be.left) || isUserInputExpr(be.right);
  }
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInputExpr(e));
  }
  return false;
}

function checkFsCall(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
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
  if (!isUserInputExpr(pathArg)) return null;
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

function checkPathJoin(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'path') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'join' && method !== 'resolve') return null;
  const hasUserInput = node.arguments.some((arg) => isUserInputExpr(arg));
  if (!hasUserInput) return null;
  const contextAfter = extractSnippet(source, getLine(node) + 1, 2);
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

function checkPathConcatBinary(node: TSESTree.BinaryExpression, source: string, filePath: string): Finding | null {
  if (node.operator !== '+') return null;

  const left = node.left;
  const right = node.right;
  const leftHasUser = isUserInputExpr(left);
  const rightHasUser = isUserInputExpr(right);

  if (!leftHasUser && !rightHasUser) return null;

  if (leftHasUser && !isPathLikeString(right)) return null;
  if (!leftHasUser && !isDirnameOrRelPath(left)) return null;

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

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const fsF = checkFsCall(node, source, filePath);
        if (fsF) { findings.push(fsF); return; }
        const pathF = checkPathJoin(node, source, filePath);
        if (pathF) findings.push(pathF);
      },
      BinaryExpression(rawNode) {
        const finding = checkPathConcatBinary(rawNode as TSESTree.BinaryExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
