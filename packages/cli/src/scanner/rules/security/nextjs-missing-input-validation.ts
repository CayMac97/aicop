import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding } from '../types.js';

export const nextjsMissingInputValidation: Rule = {
  id: 'security/nextjs-missing-input-validation',
  category: 'security',
  severity: 'warn',
  description: 'Server Actions and Route Handlers should validate input using a schema library (e.g. Zod)',
  check(ast: TSESTree.Node, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    
    const isAppRouter = filePath.includes('app/') || filePath.includes('app\\');
    const isRoute = filePath.endsWith('route.ts') || filePath.endsWith('route.js');
    const isActionFile = filePath.endsWith('actions.ts') || filePath.endsWith('actions.js');
    
    let hasUseServer = false;
    if (ast.type === 'Program') {
      for (const stmt of ast.body) {
        if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'Literal' && stmt.expression.value === 'use server') {
          hasUseServer = true;
          break;
        }
      }
    }

    if (!isAppRouter && !hasUseServer && !isRoute && !isActionFile) {
      return findings;
    }

    const exportedAsyncFunctions: TSESTree.FunctionDeclaration[] | TSESTree.ArrowFunctionExpression[] = [];

    function traverse(node: TSESTree.Node) {
      if (node.type === 'ExportNamedDeclaration') {
        if (node.declaration?.type === 'FunctionDeclaration' && node.declaration.async && node.declaration.params.length > 0) {
          exportedAsyncFunctions.push(node.declaration);
        } else if (node.declaration?.type === 'VariableDeclaration') {
          for (const decl of node.declaration.declarations) {
            if (decl.init && (decl.init.type === 'ArrowFunctionExpression' || decl.init.type === 'FunctionExpression') && decl.init.async && decl.init.params.length > 0) {
               // @ts-ignore
               exportedAsyncFunctions.push(decl.init);
            }
          }
        }
      } else if (node.type === 'FunctionDeclaration' && node.async && hasUseServer && node.params.length > 0) {
         // In "use server" files, sometimes all exports are actions, or we just check all async functions.
      }
      
      for (const key in node) {
        if (node.hasOwnProperty(key)) {
          const child = (node as any)[key];
          if (Array.isArray(child)) {
            for (const c of child) if (c && typeof c.type === 'string') traverse(c);
          } else if (child && typeof child.type === 'string') {
            traverse(child);
          }
        }
      }
    }

    traverse(ast);

    for (const func of exportedAsyncFunctions) {
      const funcSource = source.substring(func.range[0], func.range[1]);
      const hasValidation = /parse\(|safeParse\(|validate\(|z\.|Joi\.|yup\./.test(funcSource);
      
      if (!hasValidation) {
        findings.push({
          ruleId: 'security/nextjs-missing-input-validation',
          message: 'Exported async function in Next.js Server Action / Route lacks input validation (e.g. Zod parse). Unvalidated input can lead to injection attacks.',
          severity: 'warn',
          line: func.loc.start.line,
          column: func.loc.start.column,
          suggestion: 'Use Zod, Valibot, or Yup to validate incoming parameters.',
        });
      }
    }

    return findings;
  }
};
