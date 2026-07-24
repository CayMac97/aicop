import { ParsedAST, Finding } from '../rules/types.js';

export function parsePython(source: string): ParsedAST {
  // Polyglot Fallback: Regex-based AST approximation for Python
  // Avoids native tree-sitter bindings for now to keep the npm package pure JS
  return {
    type: 'Program',
    sourceType: 'script',
    body: [],
    tokens: [],
    comments: [],
    loc: { start: { line: 1, column: 0 }, end: { line: source.split('\n').length, column: 0 } },
    range: [0, source.length],
    _pythonFallback: true,
  } as unknown as ParsedAST;
}

export function scanPythonFile(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split('\n');

  lines.forEach((line, index) => {
    // 1. Detect hardcoded secrets in Python
    if (/(api_key|password|secret|token)\s*=\s*['"][^'"]+['"]/i.test(line)) {
      findings.push({
        ruleId: 'security/hardcoded-secrets',
        severity: 'error',
        message: 'Hardcoded secret detected in Python file',
        file: filePath,
        line: index + 1,
        column: 0,
        snippet: line.trim(),
        fix: 'Use environment variables (os.getenv) or a secrets manager',
      });
    }

    // 2. Detect eval in Python
    if (/\beval\s*\(/.test(line)) {
      findings.push({
        ruleId: 'security/eval-usage',
        severity: 'error',
        message: 'Unsafe eval() usage in Python',
        file: filePath,
        line: index + 1,
        column: 0,
        snippet: line.trim(),
        fix: 'Avoid eval(), use ast.literal_eval() if parsing data',
      });
    }

    // 3. Detect subprocess with shell=True
    if (/subprocess\.(Popen|call|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True/.test(line)) {
       findings.push({
        ruleId: 'security/unsafe-shell-execs',
        severity: 'error',
        message: 'Unsafe subprocess call with shell=True',
        file: filePath,
        line: index + 1,
        column: 0,
        snippet: line.trim(),
        fix: 'Set shell=False and pass arguments as a list',
      });
    }
  });

  return findings;
}
