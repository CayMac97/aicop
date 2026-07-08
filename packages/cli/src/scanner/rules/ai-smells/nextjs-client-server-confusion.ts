import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding } from '../types.js';

export const nextjsClientServerConfusion: Rule = {
  id: 'ai-smell/nextjs-client-server-confusion',
  category: 'ai-smell',
  severity: 'warn',
  name: 'Next.js Client-Server Confusion',
  description: 'Detects client-side hooks or browser globals in Next.js files missing "use client"',
  why: 'Using client-side hooks like useState or accessing browser globals like window in a Server Component causes runtime crashes.',
  fix: 'Add "use client" to the top of the file, or refactor the code into a separate client component.',
  check(ast: TSESTree.Node, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Only apply in Next.js App Router files
    if (!filePath.match(/[\\/]app[\\/]/) || (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx'))) {
      return findings;
    }

    let hasUseClient = false;
    if (ast.type === 'Program') {
      for (const stmt of ast.body) {
        if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'Literal' && stmt.expression.value === 'use client') {
          hasUseClient = true;
          break;
        }
      }
    }

    if (hasUseClient) return findings;

    const CLIENT_HOOKS = new Set(['useState', 'useEffect', 'useContext', 'useRef', 'useReducer', 'useCallback', 'useMemo', 'useLayoutEffect']);
    const BROWSER_GLOBALS = new Set(['window', 'document', 'localStorage', 'sessionStorage']);

    function traverse(node: TSESTree.Node) {
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
        if (CLIENT_HOOKS.has(node.callee.name)) {
          const lines = source.split('\n');
          const snippet = lines[node.loc.start.line - 1] || '';
          findings.push({
            ruleId: 'ai-smell/nextjs-client-server-confusion',
            message: `Hook '${node.callee.name}' used in a file without 'use client'. This will crash in Next.js Server Components.`,
            severity: 'warn',
            file: filePath,
            line: node.loc.start.line,
            column: node.loc.start.column,
            snippet: snippet.trim(),
            fix: 'Add "use client" at the top of the file, or move this component to a client-side file.',
          });
        }
      } else if (node.type === 'Identifier' && BROWSER_GLOBALS.has(node.name)) {
        // We should skip checking properties of objects, only global identifiers
        const lines = source.split('\n');
        const snippet = lines[node.loc.start.line - 1] || '';
        findings.push({
          ruleId: 'ai-smell/nextjs-client-server-confusion',
          message: `Browser global '${node.name}' accessed in a Server Component context.`,
          severity: 'warn',
          file: filePath,
          line: node.loc.start.line,
          column: node.loc.start.column,
          snippet: snippet.trim(),
          fix: 'Ensure this code runs only on the client (e.g. inside useEffect or a "use client" component).',
        });
      }
      
      for (const key in node) {
        if (node.hasOwnProperty(key)) {
          if (key === 'property' && (node as any).type === 'MemberExpression' && !(node as any).computed) {
             // skip checking the property name if it's window.x or x.window (x.window shouldn't flag window)
             continue;
          }
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

    // Filter duplicates by line/message
    const unique = new Map<string, Finding>();
    for (const f of findings) {
       unique.set(`${f.line}-${f.message}`, f);
    }

    return Array.from(unique.values());
  }
};
