import * as vscode from 'vscode';
import type { Finding } from './scanner-bridge';

export interface DiagnosticWithFinding extends vscode.Diagnostic {
  _finding?: Finding;
}

export function findingToDiagnostic(finding: Finding, _docUri: vscode.Uri): vscode.Diagnostic {
  const line = Math.max(0, finding.line - 1);
  const col  = Math.max(0, finding.column);
  const range = new vscode.Range(line, col, line, Number.MAX_SAFE_INTEGER);

  const message = `[${finding.ruleId}] ${finding.message}${finding.fix ? `\n\nFIX: ${finding.fix}` : ''}`;
  const diagnostic = new vscode.Diagnostic(range, message, mapSeverity(finding.severity));
  diagnostic.source = 'VibeCop';
  diagnostic.code = finding.ruleId;

  if (finding.severity === 'info' && finding.ruleId.includes('debug-leftovers')) {
    diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
  }

  (diagnostic as DiagnosticWithFinding)._finding = finding;
  return diagnostic;
}

function mapSeverity(severity: Finding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'error': return vscode.DiagnosticSeverity.Error;
    case 'warn':  return vscode.DiagnosticSeverity.Warning;
    case 'info':  return vscode.DiagnosticSeverity.Information;
  }
}
