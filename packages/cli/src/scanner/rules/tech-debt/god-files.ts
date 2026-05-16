import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';

const WARN_LINES = 400;
const ERROR_LINES = 800;
const MAX_EXPORTS = 20;

function countExportDeclaration(decl: NonNullable<TSESTree.ExportNamedDeclaration['declaration']>): number {
  if (decl.type === 'VariableDeclaration') {
    return (decl as TSESTree.VariableDeclaration).declarations.length;
  }
  return 1;
}

function countExports(ast: ParsedAST): number {
  let count = 0;
  for (const node of ast.body) {
    if (node.type === 'ExportDefaultDeclaration') { count++; continue; }
    if (node.type !== 'ExportNamedDeclaration') continue;
    const ed = node as TSESTree.ExportNamedDeclaration;
    if (ed.specifiers.length > 0) {
      count += ed.specifiers.length;
    } else if (ed.declaration) {
      count += countExportDeclaration(ed.declaration);
    }
  }
  return count;
}

function countNonImportLogicalLines(source: string, ast: ParsedAST): number {
  let lastImportLine = 0;
  for (const node of ast.body) {
    if (node.type !== 'ImportDeclaration') break;
    if (node.loc) lastImportLine = node.loc.end.line;
  }
  return source
    .split('\n')
    .slice(lastImportLine)
    .filter((line) => {
      const trimmed = line.trim();
      return trimmed.length > 0 && !trimmed.startsWith('//') && !trimmed.startsWith('*');
    }).length;
}

const rule: Rule = {
  id: 'tech-debt/god-files',
  name: 'God Files',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects files that are too large (>400 lines warn, >800 error) or export too many things (>20)',
  why: 'God files violate the Single Responsibility Principle. They are hard to navigate, cause merge conflicts, and hide the structure of your codebase. AI models routinely generate monolithic files.',
  fix: 'Split the file into focused modules, each with a clear single responsibility. Group related exports together.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const logicalLines = countNonImportLogicalLines(source, ast);
    const exportCount = countExports(ast);

    if (logicalLines > WARN_LINES) {
      const severity = logicalLines > ERROR_LINES ? 'error' : 'warn';
      findings.push({
        ruleId: 'tech-debt/god-files',
        severity,
        message: `File has ${logicalLines} logical lines (warn: ${WARN_LINES}, error: ${ERROR_LINES})`,
        file: filePath,
        line: 1,
        column: 0,
        snippet: `// ${logicalLines} logical lines of code`,
        fix: 'Split this file into multiple focused modules. Start by identifying distinct responsibilities.',
      });
    }

    if (exportCount > MAX_EXPORTS) {
      findings.push({
        ruleId: 'tech-debt/god-files',
        severity: 'warn',
        message: `File exports ${exportCount} items (limit: ${MAX_EXPORTS}) — too many responsibilities`,
        file: filePath,
        line: 1,
        column: 0,
        snippet: `// ${exportCount} exports in one file`,
        fix: 'Group related exports into separate modules with focused responsibilities',
      });
    }

    return findings;
  },
};

export default rule;
