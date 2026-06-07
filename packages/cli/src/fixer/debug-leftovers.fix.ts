import { TSESTree } from '@typescript-eslint/typescript-estree';
import { FixReplacement, RuleFixer, registerFixer } from './index.js';
import { Finding, ParsedAST } from '../scanner/rules/types.js';
import { walk } from '../scanner/ast-walker.js';

export const DebugLeftoversFixer: RuleFixer = {
  ruleId: 'ai-smell/debug-leftovers',
  fix(source: string, ast: ParsedAST, findings: Finding[]): FixReplacement[] {
    const replacements: FixReplacement[] = [];

    const consoleFindings = findings.filter(f => f.message.includes('console.'));
    const debuggerFindings = findings.filter(f => f.message.includes('debugger; statement'));

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (!node.loc || !node.range) return;
        
        const isTarget = consoleFindings.some(f => f.line === node.loc!.start.line);
        if (!isTarget) return;

        if (node.callee.type !== 'MemberExpression') return;
        const object = (node.callee as any).object;
        if (object && object.name === 'console') {
          replacements.push({
            start: node.range[0],
            end: node.range[1],
            text: '/* console removed */'
          });
        }
      },
      DebuggerStatement(rawNode) {
        const node = rawNode as TSESTree.DebuggerStatement;
        if (!node.loc || !node.range) return;
        
        const isTarget = debuggerFindings.some(f => f.line === node.loc!.start.line);
        if (!isTarget) return;

        replacements.push({
          start: node.range[0],
          end: node.range[1],
          text: '/* debugger removed */'
        });
      }
    });

    return replacements;
  }
};

registerFixer(DebugLeftoversFixer);
