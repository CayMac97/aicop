import * as vscode from 'vscode';
import type { Finding } from './scanner-bridge';

export function findingToDiagnostic(finding: Finding, docUri: vscode.Uri): vscode.Diagnostic {
  const severity = mapSeverity(finding.severity);

  const line = Math.max(0, finding.line - 1);
  const col  = Math.max(0, finding.column);
  const endCol = col + Math.max(1, finding.snippet?.trim().length ?? 1);
  const range = new vscode.Range(line, col, line, endCol);

  const messageParts: string[] = [`[vibecop] ${finding.message}`];
  if (finding.fix) {
    messageParts.push(`FIX: ${finding.fix}`);
  }
  const diagnostic = new vscode.Diagnostic(range, messageParts.join('\n\n'), severity);
  diagnostic.source = 'VibeCop';
  diagnostic.code = finding.ruleId;

  if (
    finding.severity === 'info' &&
    finding.ruleId.includes('debug-leftovers')
  ) {
    diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
  }

  diagnostic.relatedInformation = [];

  (diagnostic as DiagnosticWithFinding)._finding = finding;

  return diagnostic;
}

export interface DiagnosticWithFinding extends vscode.Diagnostic {
  _finding?: Finding;
}

function mapSeverity(severity: Finding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'error': return vscode.DiagnosticSeverity.Error;
    case 'warn':  return vscode.DiagnosticSeverity.Warning;
    case 'info':  return vscode.DiagnosticSeverity.Information;
  }
}
