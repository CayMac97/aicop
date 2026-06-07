import { TSESTree } from '@typescript-eslint/typescript-estree';
import { FixReplacement, RuleFixer, registerFixer } from './index.js';
import { Finding, ParsedAST } from '../scanner/rules/types.js';
import { walk } from '../scanner/ast-walker.js';

export const JwtNoExpiryFixer: RuleFixer = {
  ruleId: 'security/jwt-no-expiry',
  fix(source: string, ast: ParsedAST, findings: Finding[]): FixReplacement[] {
    const replacements: FixReplacement[] = [];
    
    const fixableFindings = findings.filter(f => f.message.includes('missing expiresIn'));
    if (fixableFindings.length === 0) return [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (!node.loc || !node.range) return;
        
        const isTarget = fixableFindings.some(f => f.line === node.loc!.start.line);
        if (!isTarget) return;

        if (node.callee.type !== 'MemberExpression') return;
        const prop = (node.callee as any).property;
        if (!prop || prop.name !== 'sign') return;

        const args = node.arguments;
        if (args.length === 2) {
          const lastArg = args[1];
          if (!lastArg.range) return;
          replacements.push({
            start: lastArg.range[1],
            end: lastArg.range[1],
            text: `, { expiresIn: '15m' }`
          });
        } else if (args.length === 3) {
          const optionsArg = args[2];
          if (optionsArg.type === 'ObjectExpression' && optionsArg.range) {
            const props = optionsArg.properties;
            if (props.length === 0) {
              replacements.push({
                start: optionsArg.range[0] + 1,
                end: optionsArg.range[1] - 1,
                text: ` expiresIn: '15m' `
              });
            } else {
              const firstProp = props[0];
              if (firstProp.range) {
                replacements.push({
                  start: firstProp.range[0],
                  end: firstProp.range[0],
                  text: `expiresIn: '15m', `
                });
              }
            }
          }
        }
      }
    });

    return replacements;
  }
};

registerFixer(JwtNoExpiryFixer);
