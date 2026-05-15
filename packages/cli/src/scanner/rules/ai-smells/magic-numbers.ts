import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const ALLOWED_NUMBERS = new Set([
  0, 1, -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 16, 20, 24, 25, 30, 32, 36, 40, 50, 60, 64, 90, 100, 120, 128, 256, 512, 1000, 1024,
  3600, 86400, 604800, 10000,
  200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 308, 400, 401, 403, 404, 405, 408, 409, 410, 422, 429, 500, 501, 502, 503, 504,
  21, 22, 25, 53, 80, 443, 3000, 3306, 4000, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 27017,
  128, 192, 256, 512, 2048, 4096,
]);

const SKIP_PARENT_TYPES = new Set([
  'VariableDeclarator',    // const TIMEOUT = 3000 — this IS the definition
  'Property',              // { code: 200 } — object literal
  'ExportNamedDeclaration',
  'ArrayExpression',
  'ReturnStatement',       // return 200 in switch/express handlers
  'SwitchCase',            // case 404:
  'ConditionalExpression', // status === 200 ? ...
  'AssignmentExpression',  // this.code = 200
]);

const WELL_KNOWN_NUMBER_CONTEXTS = new Set(['setTimeout', 'setInterval', 'setImmediate', 'slice', 'splice', 'indexOf']);

const MILLISECOND_MULTIPLES_DESCRIPTION: Record<number, string> = {
  1000: '1 second in ms',
  60000: '1 minute in ms',
  3600000: '1 hour in ms',
  86400000: '1 day in ms',
  604800000: '1 week in ms',
};

function shouldFlagNumber(value: number, parent: TSESTree.Node | null): boolean {
  if (ALLOWED_NUMBERS.has(value)) return false;
  if (!parent) return false;
  if (SKIP_PARENT_TYPES.has(parent.type)) return false;
  if (parent.type === 'AssignmentPattern') return false;
  if (parent.type === 'CallExpression') {
    const ce = parent as TSESTree.CallExpression;
    if (ce.callee.type === 'Identifier' && WELL_KNOWN_NUMBER_CONTEXTS.has((ce.callee as TSESTree.Identifier).name)) return false;
  }
  return true;
}

function lineHasComment(source: string, lineNumber: number): boolean {
  const line = source.split('\n')[lineNumber - 1] ?? '';
  return line.includes('//');
}

function getNumberHint(value: number): string {
  const desc = MILLISECOND_MULTIPLES_DESCRIPTION[value];
  if (desc) return ` (this looks like ${desc})`;
  if (value > 999 && value % 1000 === 0) return ' (looks like a millisecond value)';
  return '';
}

const rule: Rule = {
  id: 'ai-smell/magic-numbers',
  name: 'Magic Numbers',
  category: 'ai-smell',
  severity: 'info',
  description: 'Detects numeric literals used directly in logic that should be named constants',
  why: 'Magic numbers obscure intent. What does "86400000" mean? A named constant MILLISECONDS_PER_DAY is instantly understandable. AI models love hardcoding numbers.',
  fix: 'Extract magic numbers into named constants at the top of the file or in a constants module.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      Literal(rawNode, parent) {
        const node = rawNode as TSESTree.Literal;
        if (typeof node.value !== 'number') return;
        const value = node.value;
        if (!shouldFlagNumber(value, parent)) return;
        const lineNum = getLine(node);
        if (lineHasComment(source, lineNum)) return;
        const hint = getNumberHint(value);
        const severity = Math.abs(value) > 10000 ? 'warn' : 'info';
        findings.push({
          ruleId: 'ai-smell/magic-numbers',
          severity,
          message: `Magic number ${String(value)} used directly in logic${hint}`,
          file: filePath,
          line: lineNum,
          column: getColumn(node),
          snippet: extractSnippet(source, lineNum),
          fix: `Extract to a named constant: const DESCRIPTIVE_NAME = ${String(value)}`,
        });
      },
    });

    return findings;
  },
};

export default rule;
