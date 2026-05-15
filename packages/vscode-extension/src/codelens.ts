import * as vscode from 'vscode';
import type { DiagnosticWithFinding } from './diagnostics';

export class VibeCopCodeLensProvider implements vscode.CodeLensProvider {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  constructor(collection: vscode.DiagnosticCollection) {
    this.collection = collection;
  }

  refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const diagnostics = this.collection.get(document.uri);
    if (!diagnostics || diagnostics.length === 0) return [];

    const lenses: vscode.CodeLens[] = [];

    const firstDiag = [...diagnostics].sort((a, b) => a.range.start.line - b.range.start.line)[0];
    if (firstDiag) {
      lenses.push(new vscode.CodeLens(firstDiag.range, {
        title: '🤖 Generate fix prompt for this file →',
        command: 'vibecop.generateFixPrompt',
        arguments: [],
      }));
    }

    for (const diag of diagnostics) {
      const finding = (diag as DiagnosticWithFinding)._finding;
      const ruleLabel = typeof diag.code === 'string'
        ? diag.code.replace(/^(security|ai-smell|tech-debt)\//, '')
        : 'vibecop';

      const lens = new vscode.CodeLens(diag.range, {
        title: `⚠ VibeCop: ${ruleLabel} — click for details`,
        command: 'vibecop._showFindingDetail',
        arguments: [finding ?? { ruleId: diag.code, message: diag.message }],
      });
      lenses.push(lens);
    }
    return lenses;
  }

  dispose(): void {
    this._onDidChangeCodeLenses.dispose();
  }
}

export async function showFindingDetail(finding: {
  ruleId: string;
  message: string;
  fix?: string;
}): Promise<void> {
  const ruleId = String(finding.ruleId ?? '');
  const fix    = finding.fix ? `FIX: ${finding.fix}` : '';
  const docsUrl = `https://vibecop.net/rules/${ruleId.replace('/', '-')}`;

  const picked = await vscode.window.showQuickPick(
    [
      { label: `⚠  ${finding.message}`, description: ruleId, alwaysShow: true },
      ...(fix ? [{ label: fix, description: '', alwaysShow: true }] : []),
      { label: '🔗 View rule docs', description: docsUrl, alwaysShow: true },
    ],
    { title: `VibeCop — ${ruleId}`, placeHolder: 'Select an option' },
  );

  if (picked?.label === '🔗 View rule docs') {
    await vscode.env.openExternal(vscode.Uri.parse(docsUrl));
  }
}
