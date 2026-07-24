import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const dbMethodRegex = /^(find|findOne|findMany|query|execute|update|save|delete|insert)/i;

function extractVariablesFromPattern(pattern: any, varsSet: Set<string>) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') {
    varsSet.add(pattern.name);
  } else if (pattern.type === 'ObjectPattern') {
    for (const prop of pattern.properties) {
      if (prop.type === 'Property') {
        extractVariablesFromPattern(prop.value, varsSet);
      } else if (prop.type === 'RestElement') {
        extractVariablesFromPattern(prop.argument, varsSet);
      }
    }
  } else if (pattern.type === 'ArrayPattern') {
    for (const el of pattern.elements) {
      if (el) extractVariablesFromPattern(el, varsSet);
    }
  } else if (pattern.type === 'AssignmentPattern') {
    extractVariablesFromPattern(pattern.left, varsSet);
  }
}

const rule: Rule = {
  id: 'tech-debt/n-plus-one-queries',
  name: 'N+1 Queries',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects database queries executed inside a loop, causing N+1 performance issues',
  why: 'Running queries inside a loop executes a separate DB call for every iteration, drastically degrading performance.',
  fix: 'Batch the query outside the loop using IN clauses or Promise.all() with caution, or use a JOIN.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    // Track if we are inside a loop
    let loopDepth = 0;
    const loopVarsStack: Set<string>[] = [];

    walk(ast, {
      enter(node) {
        let isLoop = false;
        let newVars = new Set<string>();

        if (
          node.type === 'ForStatement' ||
          node.type === 'WhileStatement' ||
          node.type === 'DoWhileStatement'
        ) {
          isLoop = true;
        } else if (node.type === 'ForInStatement' || node.type === 'ForOfStatement') {
          isLoop = true;
          if (node.left.type === 'VariableDeclaration') {
            const decl = node.left.declarations[0];
            if (decl && decl.id) {
              extractVariablesFromPattern(decl.id, newVars);
            }
          }
        } else if (
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'map' || node.callee.property.name === 'forEach' || node.callee.property.name === 'filter')
        ) {
          isLoop = true;
          if (node.arguments[0] && (node.arguments[0].type === 'ArrowFunctionExpression' || node.arguments[0].type === 'FunctionExpression')) {
             const param = node.arguments[0].params[0];
             if (param) {
               extractVariablesFromPattern(param, newVars);
             }
          }
        }

        if (isLoop) {
          loopDepth++;
          loopVarsStack.push(newVars);
        }

        if (loopDepth > 0 && node.type === 'CallExpression') {
          let methodName = '';
          let callerName = '';
          
          if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier') {
            methodName = node.callee.property.name;
            if (node.callee.object.type === 'Identifier') {
              callerName = node.callee.object.name;
            }
          } else if (node.callee.type === 'Identifier') {
            methodName = node.callee.name;
          }

          let isDbCall = dbMethodRegex.test(methodName);
          
          if (isDbCall) {
            let isLocalToLoop = false;
            
            // Scope depth check: Is the callee derived from a loop variable?
            if (node.callee.type === 'MemberExpression') {
              let currentObj: any = node.callee.object;
              while (currentObj) {
                if (currentObj.type === 'Identifier') {
                  const rootName = currentObj.name;
                  if (loopVarsStack.some(vars => vars.has(rootName))) {
                    isLocalToLoop = true; // derived from loop variable (e.g. user.roles.find)
                  }
                  break;
                } else if (currentObj.type === 'MemberExpression') {
                  currentObj = currentObj.object;
                } else if (currentObj.type === 'CallExpression') {
                  currentObj = currentObj.callee;
                } else {
                  break;
                }
              }
            }

            // Fallback for Array.find if it wasn't caught by scope check (e.g. activeRoles.find)
            if (!isLocalToLoop && (methodName === 'find' || methodName === 'delete')) {
              // KNOWN LIMITATION: If a user assigns a loop variable to an intermediate variable (const r = user.roles; r.find()),
              // our scope tracker loses the chain. We fallback to a whitelist heuristic to prevent false positives.
              // This trades false positives (reporting arrays) for false negatives (missing custom ORM client names).
              if (callerName && !/^[A-Z]/.test(callerName) && !/db|repo|collection|store|prisma|mongoose|model|queryrunner|knex|datasource|client/i.test(callerName)) {
                isLocalToLoop = true;
              }
            }

            if (!isLocalToLoop) {
              findings.push({
                ruleId: 'tech-debt/n-plus-one-queries',
                severity: 'warn',
                message: `Possible N+1 query: database method "${methodName}" called inside a loop`,
                file: filePath,
                line: getLine(node),
                column: getColumn(node),
                snippet: extractSnippet(source, getLine(node)),
                fix: 'Fetch all required data in a single query outside the loop',
              });
            }
          }
        }
      },
      leave(node) {
        let isLoop = false;
        if (
          node.type === 'ForStatement' ||
          node.type === 'WhileStatement' ||
          node.type === 'DoWhileStatement' ||
          node.type === 'ForInStatement' ||
          node.type === 'ForOfStatement'
        ) {
          isLoop = true;
        } else if (
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          (node.callee.property.name === 'map' || node.callee.property.name === 'forEach' || node.callee.property.name === 'filter')
        ) {
          isLoop = true;
        }

        if (isLoop) {
          loopDepth--;
          loopVarsStack.pop();
        }
      }
    });

    return findings;
  },
};

export default rule;
