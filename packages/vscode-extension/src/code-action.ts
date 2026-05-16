import * as vscode from 'vscode';
import type { DiagnosticWithFinding } from './diagnostics';

export class VibeCopCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== 'VibeCop') continue;

      const ruleId = typeof diag.code === 'string' ? diag.code : '';
      const finding = (diag as DiagnosticWithFinding)._finding;
      const lineNum = diag.range.start.line;
      const currentLine = document.lineAt(lineNum);
      const indent = currentLine.text.match(/^\s*/)?.[0] ?? '';
      const insertPos = new vscode.Position(lineNum, 0);

      const ignoreAll = new vscode.CodeAction(
        'VibeCop: Suppress this line (vibecop-ignore)',
        vscode.CodeActionKind.QuickFix,
      );
      ignoreAll.edit = new vscode.WorkspaceEdit();
      ignoreAll.edit.insert(document.uri, insertPos, `${indent}// vibecop-ignore\n`);
      ignoreAll.diagnostics = [diag];
      ignoreAll.isPreferred = true;
      actions.push(ignoreAll);

      if (ruleId) {
        const ignoreRule = new vscode.CodeAction(
          `VibeCop: Suppress rule "${ruleId}"`,
          vscode.CodeActionKind.QuickFix,
        );
        ignoreRule.edit = new vscode.WorkspaceEdit();
        ignoreRule.edit.insert(document.uri, insertPos, `${indent}// vibecop-ignore ${ruleId}\n`);
        ignoreRule.diagnostics = [diag];
        actions.push(ignoreRule);
      }

      if (finding?.fix) {
        const copyFix = new vscode.CodeAction(
          `VibeCop: Copy fix suggestion`,
          vscode.CodeActionKind.QuickFix,
        );
        copyFix.command = {
          command: 'vibecop._copyFix',
          title: 'Copy Fix Suggestion',
          arguments: [finding.fix],
        };
        copyFix.diagnostics = [diag];
        actions.push(copyFix);
      }
    }

    return actions;
  }
}
