import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

function isTerminatingStatement(node: TSESTree.Statement): boolean {
  return (
    node.type === 'ReturnStatement' ||
    node.type === 'ThrowStatement' ||
    node.type === 'BreakStatement' ||
    node.type === 'ContinueStatement'
  );
}

function checkUnreachableCode(body: TSESTree.Statement[], source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < body.length - 1; i++) {
    const stmt = body[i];
    if (!stmt) continue;
    if (stmt.type === 'FunctionDeclaration') continue;
    if (isTerminatingStatement(stmt)) {
      let next: TSESTree.Statement | undefined;
      for (let j = i + 1; j < body.length; j++) {
        if (body[j] && body[j].type !== 'FunctionDeclaration') {
          next = body[j];
          break;
        }
      }
      
      if (!next) continue;
      
      findings.push({
        ruleId: 'ai-smell/dead-code-blocks',
        severity: 'warn',
        message: 'Unreachable code detected after a return/throw/break/continue statement',
        file: filePath,
        line: getLine(next),
        column: getColumn(next),
        snippet: extractSnippet(source, getLine(next)),
        fix: 'Remove the unreachable code block',
      });
      break;
    }
  }
  return findings;
}

function checkConstantConditions(node: TSESTree.IfStatement, source: string, filePath: string): Finding | null {
  const test = node.test;
  if (test.type !== 'Literal') return null;
  const val = (test as TSESTree.Literal).value;
  if (val !== true && val !== false) return null;
  return {
    ruleId: 'ai-smell/dead-code-blocks',
    severity: 'warn',
    message: `if(${String(val)}) — condition is always ${String(val)}, one branch is dead code`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Remove the constant condition and keep only the branch that will always execute',
  };
}

const rule: Rule = {
  id: 'ai-smell/dead-code-blocks',
  name: 'Dead Code Blocks',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects unreachable code after return/throw/break statements and constant boolean conditions',
  why: 'Dead code increases cognitive load, causes confusion during debugging, and suggests the developer (or AI) didn\'t fully think through the logic flow.',
  fix: 'Remove unreachable code blocks. Simplify constant conditions to just the branch that executes.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      BlockStatement(rawNode) {
        const node = rawNode as TSESTree.BlockStatement;
        const blockFindings = checkUnreachableCode(node.body, source, filePath);
        findings.push(...blockFindings);
      },
      IfStatement(rawNode) {
        const finding = checkConstantConditions(rawNode as TSESTree.IfStatement, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
