import * as vscode from 'vscode';
import type { DiagnosticWithFinding } from './diagnostics';

export class VibeCopCodeLensProvider implements vscode.CodeLensProvider, vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.emitter.event;

  constructor(collection: vscode.DiagnosticCollection) {
    this.collection = collection;
  }

  refresh(): void {
    this.emitter.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const diagnostics = this.collection.get(document.uri);
    if (!diagnostics || diagnostics.length === 0) return [];

    const sorted = [...diagnostics].sort((a, b) => a.range.start.line - b.range.start.line);
    const lenses: vscode.CodeLens[] = [];

    lenses.push(new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
      title: '🤖 Generate fix prompt →',
      command: 'vibecop.generateFixPrompt',
      arguments: [],
    }));

    for (const diag of diagnostics) {
      const finding = (diag as DiagnosticWithFinding)._finding;
      const ruleLabel = typeof diag.code === 'string'
        ? diag.code.replace(/^(security|ai-smell|tech-debt)\//, '')
        : 'vibecop';
      lenses.push(new vscode.CodeLens(diag.range, {
        title: `⚠ ${ruleLabel}`,
        command: 'vibecop._showFindingDetail',
        arguments: [finding ?? { ruleId: diag.code, message: diag.message }],
      }));
    }

    return lenses;
  }

  dispose(): void {
    this.emitter.dispose();
  }
}

export async function showFindingDetail(finding: {
  ruleId: string;
  message: string;
  fix?: string;
}): Promise<void> {
  const ruleId  = String(finding.ruleId ?? '');
  const docsUrl = `https://vibecop.net/rules/${ruleId.replace('/', '-')}`;
  const items: vscode.QuickPickItem[] = [
    { label: `⚠  ${finding.message}`, description: ruleId, alwaysShow: true },
    ...(finding.fix ? [{ label: `FIX: ${finding.fix}`, description: '', alwaysShow: true }] : []),
    { label: '🔗 View rule docs', description: docsUrl, alwaysShow: true },
  ];

  const picked = await vscode.window.showQuickPick(items, {
    title: `VibeCop — ${ruleId}`,
    placeHolder: 'Select an option',
  });

  if (picked?.label === '🔗 View rule docs') {
    await vscode.env.openExternal(vscode.Uri.parse(docsUrl));
  }
}
