import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const GENERIC_NAMES = new Set(['temp', 'tmp', 'val', 'obj', 'arr', 'stuff', 'thing', 'data2', 'result2', 'foo', 'bar', 'baz', 'qux']);

const ALLOWED_NAMES = new Set([
  'i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'e', 'a', 'b', 'c', 'd', 'p', 'q', 'r', 's', 't', 'v', '_',
  'id', 'fn', 'cb', 'ok', 'ms', 'px', 'db',
]);

const MIN_GENERIC_COUNT = 3;
const MIN_FUNCTION_LINES = 15;

interface FuncRange {
  start: number;
  end: number;
}

function getFuncRanges(ast: ParsedAST): FuncRange[] {
  const ranges: FuncRange[] = [];
  walk(ast, {
    enter(node) {
      const type = node.type;
      if (
        (type === 'FunctionDeclaration' || type === 'FunctionExpression' || type === 'ArrowFunctionExpression') &&
        node.loc
      ) {
        ranges.push({ start: node.loc.start.line, end: node.loc.end.line });
      }
    },
  });
  return ranges;
}

function findInnermostFunc(line: number, ranges: FuncRange[]): FuncRange | null {
  let best: FuncRange | null = null;
  for (const r of ranges) {
    if (r.start <= line && line <= r.end) {
      if (!best || (r.end - r.start) < (best.end - best.start)) {
        best = r;
      }
    }
  }
  return best;
}

function isForLoopVar(parent: TSESTree.Node | null): boolean {
  if (!parent) return false;
  return (
    parent.type === 'ForStatement' ||
    parent.type === 'ForInStatement' ||
    parent.type === 'ForOfStatement'
  );
}

function isCallbackParam(parent: TSESTree.Node | null): boolean {
  if (!parent) return false;
  return (
    parent.type === 'CatchClause' ||
    parent.type === 'CallExpression' ||
    parent.type === 'ArrowFunctionExpression'
  );
}

function shouldFlagName(name: string, parent: TSESTree.Node | null, isParam: boolean): boolean {
  if (ALLOWED_NAMES.has(name)) return false;
  if (name.startsWith('_')) return false;
  if (isForLoopVar(parent)) return false;
  if (isParam && isCallbackParam(parent)) return false;
  return GENERIC_NAMES.has(name.toLowerCase());
}

function isVariableDeclarator(parent: TSESTree.Node | null): boolean {
  return parent?.type === 'VariableDeclarator';
}

function isParameterContext(parent: TSESTree.Node | null): boolean {
  return (
    parent?.type === 'FunctionDeclaration' ||
    parent?.type === 'FunctionExpression' ||
    parent?.type === 'ArrowFunctionExpression'
  );
}

const rule: Rule = {
  id: 'ai-smell/generic-variable-names',
  name: 'Generic Variable Names',
  category: 'ai-smell',
  severity: 'info',
  description: 'Detects functions with 3+ generic variable names in a 15+ line function — reduces false positives from small helpers',
  why: 'AI models tend to use generic variable names when they don\'t have context for a better name. Code reads like a rough draft rather than intentional design.',
  fix: 'Name variables after what they represent: "userData" not "data", "parsedResponse" not "result", "authToken" not "temp".',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const funcRanges = getFuncRanges(ast);
    const candidates: Array<{ funcKey: string; finding: Finding }> = [];

    walk(ast, {
      Identifier(rawNode, parent) {
        const node = rawNode as TSESTree.Identifier;
        const isParam = isParameterContext(parent);
        if (!isVariableDeclarator(parent) && !isParam) return;
        if (!shouldFlagName(node.name, parent, isParam)) return;

        const line = getLine(node);
        const enclosingFunc = findInnermostFunc(line, funcRanges);
        if (!enclosingFunc) return; // module-level generic names are fine

        const funcSpan = enclosingFunc.end - enclosingFunc.start + 1;
        if (funcSpan < MIN_FUNCTION_LINES) return; // too short to care

        const funcKey = `${enclosingFunc.start}:${enclosingFunc.end}`;
        candidates.push({
          funcKey,
          finding: {
            ruleId: 'ai-smell/generic-variable-names',
            severity: 'info',
            message: `Generic variable name "${node.name}" — use a name that describes the value's purpose`,
            file: filePath,
            line,
            column: getColumn(node),
            snippet: extractSnippet(source, line),
            fix: `Rename "${node.name}" to something descriptive: what does this variable actually represent?`,
          },
        });
      },
    });

    // Only emit findings if the function has >= MIN_GENERIC_COUNT generic names
    const groups = new Map<string, Finding[]>();
    for (const { funcKey, finding } of candidates) {
      const list = groups.get(funcKey) ?? [];
      list.push(finding);
      groups.set(funcKey, list);
    }

    const findings: Finding[] = [];
    for (const [, list] of groups) {
      if (list.length >= MIN_GENERIC_COUNT) {
        findings.push(...list);
      }
    }
    return findings;
  },
};

export default rule;
