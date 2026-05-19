import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier } from '../../../utils/ast-helpers.js';
import { isTypeScriptFile } from '../../../utils/file-utils.js';

function hasTypeAnnotation(param: TSESTree.Parameter): boolean {
  const p = param as TSESTree.Parameter & { typeAnnotation?: unknown };
  return p.typeAnnotation != null;
}

function checkFunctionParams(
  node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
  parentNode: TSESTree.Node | null,
  source: string,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];
  if (
    parentNode?.type === 'CallExpression' ||
    parentNode?.type === 'NewExpression' ||
    parentNode?.type === 'Property' ||
    parentNode?.type === 'JSXExpressionContainer'
  ) return findings;
  for (const param of node.params) {
    if (param.type === 'RestElement') continue;
    if (param.type === 'AssignmentPattern') continue; // default params may omit types
    if (param.type === 'TSParameterProperty') continue;
    if (!hasTypeAnnotation(param)) {
      const paramName = isIdentifier(param) ? (param as TSESTree.Identifier).name : '(destructured)';
      findings.push({
        ruleId: 'tech-debt/missing-types',
        severity: 'warn',
        message: `Parameter "${paramName}" is missing a type annotation`,
        file: filePath,
        line: getLine(param),
        column: getColumn(param),
        snippet: extractSnippet(source, getLine(param)),
        fix: `Add type: function foo(${paramName}: YourType)`,
      });
    }
  }
  return findings;
}

function checkTsIgnore(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split('\n');
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('// @ts-ignore') || trimmed.startsWith('// @ts-expect-error')) {
      const directive = trimmed.startsWith('// @ts-ignore') ? '@ts-ignore' : '@ts-expect-error';
      findings.push({
        ruleId: 'tech-debt/missing-types',
        severity: 'warn',
        message: `${directive} directive suppresses type errors — fix the underlying issue instead`,
        file: filePath,
        line: idx + 1,
        column: 0,
        snippet: trimmed,
        fix: 'Fix the type error properly rather than suppressing it. Use type assertions or proper interfaces.',
      });
    }
  });
  return findings;
}

function checkAsAnyAssertions(node: TSESTree.TSTypeAssertion | TSESTree.TSAsExpression, source: string, filePath: string): Finding | null {
  const typeRef = node.typeAnnotation;
  if (!typeRef || typeRef.type !== 'TSAnyKeyword') return null;
  return {
    ruleId: 'tech-debt/missing-types',
    severity: 'warn',
    message: '"as any" type assertion detected — this disables type checking',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use a proper type, unknown + type guards, or a more specific assertion',
  };
}

const rule: Rule = {
  id: 'tech-debt/missing-types',
  name: 'Missing Types',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects missing TypeScript type annotations on function parameters, and ts-ignore/as any usages',
  why: 'Missing types defeat TypeScript\'s purpose. AI models frequently omit type annotations in generated code, creating hidden type mismatches that only surface at runtime.',
  fix: 'Add explicit types to all function parameters. Replace "as any" with proper types or unknown + type guards.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    if (!isTypeScriptFile(filePath)) return [];
    const findings: Finding[] = [];
    const funcTypes = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

    walk(ast, {
      enter(rawNode, parentNode) {
        if (funcTypes.has(rawNode.type)) {
          const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
          findings.push(...checkFunctionParams(funcNode, parentNode, source, filePath));
        }
        if (rawNode.type === 'TSAsExpression') {
          const finding = checkAsAnyAssertions(rawNode as TSESTree.TSAsExpression, source, filePath);
          if (finding) findings.push(finding);
        }
        if (rawNode.type === 'TSTypeAssertion') {
          const finding = checkAsAnyAssertions(rawNode as TSESTree.TSTypeAssertion, source, filePath);
          if (finding) findings.push(finding);
        }
      },
    });

    findings.push(...checkTsIgnore(source, filePath));
    return findings;
  },
};

export default rule;
