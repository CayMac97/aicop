import { TSESTree } from '@typescript-eslint/typescript-estree';
import { FixReplacement, RuleFixer, registerFixer } from './index.js';
import { Finding, ParsedAST } from '../scanner/rules/types.js';
import { walk } from '../scanner/ast-walker.js';

export const MixedAsyncPatternsFixer: RuleFixer = {
  ruleId: 'ai-smell/mixed-async-patterns',
  fix(source: string, ast: ParsedAST, findings: Finding[]): FixReplacement[] {
    const replacements: FixReplacement[] = [];

    const asyncFindings = findings.filter(f => f.message.includes('async function never uses await'));
    const awaitFindings = findings.filter(f => f.message.includes('await used on a literal value'));

    walk(ast, {
      AwaitExpression(rawNode) {
        const node = rawNode as TSESTree.AwaitExpression;
        if (!node.loc || !node.range) return;

        const isTarget = awaitFindings.some(f => f.line === node.loc!.start.line);
        if (!isTarget) return;

        // An await expression looks like "await literal". We replace "await " with nothing.
        const argRange = node.argument.range;
        if (argRange) {
           replacements.push({
             start: node.range[0],
             end: argRange[0],
             text: '' // This removes "await " including the space
           });
        }
      },
      enter(rawNode) {
        if (
          rawNode.type !== 'FunctionDeclaration' &&
          rawNode.type !== 'FunctionExpression' &&
          rawNode.type !== 'ArrowFunctionExpression'
        ) return;

        const node = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        if (!node.loc || !node.range || !node.async) return;

        const isTarget = asyncFindings.some(f => f.line === node.loc!.start.line);
        if (!isTarget) return;

        // Try to remove "async "
        // We know node.range[0] starts where the function starts, which could be "async function", "async () =>"
        const sourceText = source.slice(node.range[0], node.range[1]);
        const asyncMatch = sourceText.match(/^(\s*async\s+)/);
        if (asyncMatch) {
           replacements.push({
             start: node.range[0],
             end: node.range[0] + asyncMatch[1].length,
             text: ''
           });
        }
      }
    });

    return replacements;
  }
};

registerFixer(MixedAsyncPatternsFixer);
