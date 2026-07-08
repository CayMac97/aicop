import { TSESTree } from '@typescript-eslint/typescript-estree';
import { FixReplacement, RuleFixer, registerFixer } from './index.js';
import { Finding, ParsedAST } from '../scanner/rules/types.js';
import { walk } from '../scanner/ast-walker.js';
import { isLiteral } from '../utils/ast-helpers.js';

export const WeakCryptoFixer: RuleFixer = {
  ruleId: 'security/weak-crypto',
  fix(_source: string, ast: ParsedAST, findings: Finding[]): FixReplacement[] {
    const replacements: FixReplacement[] = [];

    const saltFindings = findings.filter(f => f.message.includes('bcrypt salt rounds') && f.message.includes('too weak'));
    const mathRandomFindings = findings.filter(f => f.message.includes('Math.random() is not cryptographically secure'));

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (!node.loc || !node.range) return;
        
        const isSaltTarget = saltFindings.some(f => f.line === node.loc!.start.line);
        if (!isSaltTarget) return;

        if (node.callee.type !== 'MemberExpression') return;
        const method = (node.callee as any).property?.name;

        if (method === 'hashSync' || method === 'hash') {
          const saltArg = node.arguments[1];
          if (saltArg && isLiteral(saltArg) && typeof saltArg.value === 'number' && saltArg.range) {
            replacements.push({
              start: saltArg.range[0],
              end: saltArg.range[1],
              text: '12'
            });
          } else if (saltArg && saltArg.type === 'CallExpression') {
             const callArg = saltArg as TSESTree.CallExpression;
             if (callArg.callee.type === 'MemberExpression' && ((callArg.callee as any).property?.name === 'genSaltSync' || (callArg.callee as any).property?.name === 'genSalt')) {
                const roundArg = callArg.arguments[0];
                if (roundArg && isLiteral(roundArg) && typeof roundArg.value === 'number' && roundArg.range) {
                   replacements.push({
                     start: roundArg.range[0],
                     end: roundArg.range[1],
                     text: '12'
                   });
                }
             }
          }
        } else if (method === 'genSaltSync' || method === 'genSalt') {
           const roundArg = node.arguments[0];
           if (roundArg && isLiteral(roundArg) && typeof roundArg.value === 'number' && roundArg.range) {
               replacements.push({
                 start: roundArg.range[0],
                 end: roundArg.range[1],
                 text: '12'
               });
           }
        }
      },
      VariableDeclarator(rawNode) {
        const node = rawNode as TSESTree.VariableDeclarator;
        if (!node.loc || !node.range || !node.init) return;
        
        const isTarget = mathRandomFindings.some(f => f.line >= node.loc!.start.line && f.line <= node.loc!.end.line);
        if (!isTarget) return;

        if (node.init.range) {
          replacements.push({
            start: node.init.range[0],
            end: node.init.range[1],
            text: `require('crypto').randomBytes(32).toString('hex')`
          });
        }
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (!node.loc || !node.range) return;
        
        const isTarget = mathRandomFindings.some(f => f.line >= node.loc!.start.line && f.line <= node.loc!.end.line);
        if (!isTarget) return;

        if (node.right.range) {
          replacements.push({
            start: node.right.range[0],
            end: node.right.range[1],
            text: `require('crypto').randomBytes(32).toString('hex')`
          });
        }
      }
    });

    return replacements;
  }
};

registerFixer(WeakCryptoFixer);
