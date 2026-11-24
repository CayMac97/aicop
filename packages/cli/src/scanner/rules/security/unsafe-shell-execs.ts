import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isArgContextuallyTainted, isStaticSafeValue, isNodeValidatedTaint } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';


const SHELL_MODULES = new Set(['child_process', 'node:child_process', 'shelljs']);

interface ShellBindings {
  namespaces: Set<string>; // const cp = require('child_process') / import * as cp / import cp
  functions: Set<string>;  // const { exec } = require(...) / import { exec as run }
}

function isShellModule(node: TSESTree.Node | null | undefined): boolean {
  return !!node && node.type === 'Literal' && typeof node.value === 'string' && SHELL_MODULES.has(node.value);
}

/** Which local names are bound to child_process / shelljs in this file? */
function collectShellBindings(ast: ParsedAST): ShellBindings {
  const b: ShellBindings = { namespaces: new Set(), functions: new Set() };
  const isExecName = (n: string) => n === 'exec' || n === 'execSync';
  walk(ast, {
    enter(node) {
      if (node.type === 'ImportDeclaration' && isShellModule(node.source)) {
        for (const sp of node.specifiers) {
          if (sp.type === 'ImportSpecifier') {
            const imported = sp.imported.type === 'Identifier' ? sp.imported.name : '';
            if (isExecName(imported)) b.functions.add(sp.local.name);
          } else {
            b.namespaces.add(sp.local.name);
          }
        }
        return;
      }
      if (node.type !== 'VariableDeclarator' || !node.init) return;
      const init = node.init;
      const isRequireShell = (n: TSESTree.Node): boolean =>
        n.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'require' && isShellModule(n.arguments[0]);
      if (isRequireShell(init)) {
        if (node.id.type === 'Identifier') b.namespaces.add(node.id.name);
        else if (node.id.type === 'ObjectPattern') {
          for (const prop of node.id.properties) {
            if (prop.type === 'Property' && prop.key.type === 'Identifier' && isExecName(prop.key.name) && prop.value.type === 'Identifier') {
              b.functions.add(prop.value.name);
            }
          }
        }
      } else if (init.type === 'MemberExpression' && isRequireShell(init.object) && node.id.type === 'Identifier') {
        b.functions.add(node.id.name); // const run = require('child_process').exec
      }
    },
  });
  return b;
}

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
    const bindings = collectShellBindings(ast);
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      enter(node) {
        if (node.type === 'CallExpression') {
          let isExec = false;
          let isShellTrue = false;

          // exec()/execSync() only count when they are bound to child_process/shelljs.
          // RegExp.prototype.exec() (re.exec(str)) must not be mistaken for a shell call.
          const isExecName = (n: string) => n === 'exec' || n === 'execSync';
          if (node.callee.type === 'Identifier') {
            if (bindings.functions.has(node.callee.name)) isExec = true;
          } else if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier' && isExecName(node.callee.property.name)) {
            const obj = node.callee.object;
            if (obj.type === 'Identifier' && bindings.namespaces.has(obj.name)) isExec = true;
            else if (obj.type === 'CallExpression' && obj.callee.type === 'Identifier' && obj.callee.name === 'require' && isShellModule(obj.arguments[0])) isExec = true;
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
               // Provable constants/numbers are harmless; user-controlled input is an error;
               // other dynamic commands are worth a look but not provably exploitable (info).
               const cmdArgs = node.arguments.filter((a) => a.type !== 'ObjectExpression');
               const allSafe = cmdArgs.length > 0 && cmdArgs.every((a) => a.type === 'ArrayExpression'
                 ? a.elements.every((e) => !e || e.type === 'SpreadElement' ? !e : isStaticSafeValue(e, parentMap))
                 : isStaticSafeValue(a, parentMap));
               if (allSafe) return;
               if (cmdArgs.length > 0 && cmdArgs.every((a) => isStaticSafeValue(a, parentMap) || isNodeValidatedTaint(a, taintResult, parentMap))) return;
               const userControlled = cmdArgs.some((a) => isArgContextuallyTainted(a, taintResult, parentMap));
               findings.push({
                 ruleId: 'security/unsafe-shell-execs',
                 severity: userControlled ? 'error' : 'info',
                 fixedSeverity: true,
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
