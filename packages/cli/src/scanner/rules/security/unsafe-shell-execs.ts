import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const rule: Rule = {
  id: 'security/unsafe-shell-execs',
  name: 'Unsafe Shell Execs',
  category: 'security',
  severity: 'error',
  description: 'Detects unsafe child_process calls that use shell=true or exec/execSync without sanitization',
  why: 'Running shell commands with unsanitized inputs allows attackers to execute arbitrary commands on the host system.',
  fix: 'Use spawn or execFile instead of exec, and never set { shell: true } unless absolutely necessary with strictly sanitized input.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      enter(node) {
        if (node.type === 'CallExpression') {
          let isExec = false;
          let isShellTrue = false;

          if (node.callee.type === 'Identifier' && (node.callee.name === 'exec' || node.callee.name === 'execSync')) {
            isExec = true;
          } else if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier' && 
            (node.callee.property.name === 'exec' || node.callee.property.name === 'execSync')) {
            isExec = true;
          }

          // Check for { shell: true } in options argument
          if (node.arguments.length > 1) {
            const lastArg = node.arguments[node.arguments.length - 1];
            if (lastArg.type === 'ObjectExpression') {
              for (const prop of lastArg.properties) {
                if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === 'shell') {
                  if (prop.value.type === 'Literal' && prop.value.value === true) {
                    isShellTrue = true;
                  }
                }
              }
            }
          }

          if (isExec || isShellTrue) {
             // To reduce false positives, we only flag if the command is dynamic
             const firstArg = node.arguments[0];
             let isDynamic = false;
             
             if (firstArg) {
               if (firstArg.type !== 'Literal') {
                 isDynamic = true;
               }
             }

             if (isDynamic || isShellTrue) {
               findings.push({
                 ruleId: 'security/unsafe-shell-execs',
                 severity: 'error',
                 message: `Unsafe shell execution: ${isExec ? 'exec/execSync used with dynamic input' : '{ shell: true } used'}`,
                 file: filePath,
                 line: getLine(node),
                 column: getColumn(node),
                 snippet: extractSnippet(source, getLine(node)),
                 fix: 'Use spawn/execFile with an array of arguments, without shell=true',
               });
             }
          }
        }
      },
    });

    return findings;
  },
};

export default rule;
