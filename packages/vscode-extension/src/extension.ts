import * as vscode from 'vscode';
import * as path from 'path';
import { getConfig } from './config';
import { findingToDiagnostic } from './diagnostics';
import { scanFile as bridgeScanFile, scanDirectory, generateFixPromptForFile, computeFileVibeScore, loadBaseline, saveBaseline, ScanResult } from './scanner-bridge';
import { VibeStatusBar } from './status-bar';
import { VibeCopCodeLensProvider, showFindingDetail } from './codelens';
import { VibeCopCodeActionProvider } from './code-action';

let collection: vscode.DiagnosticCollection;
let statusBar: VibeStatusBar;
let codeLensProvider: VibeCopCodeLensProvider;
const fileScores = new Map<string, number>();
let lastScanResult: ScanResult | null = null;

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection('vibecop');
  statusBar  = new VibeStatusBar();
  codeLensProvider = new VibeCopCodeLensProvider(collection);

  const JS_TS_SELECTOR = [
    { language: 'typescript' },
    { language: 'javascript' },
    { language: 'typescriptreact' },
    { language: 'javascriptreact' },
  ];

  context.subscriptions.push(
    collection,
    statusBar,
    codeLensProvider,

    vscode.languages.registerCodeActionsProvider(
      JS_TS_SELECTOR,
      new VibeCopCodeActionProvider(),
      { providedCodeActionKinds: VibeCopCodeActionProvider.providedCodeActionKinds },
    ),

    vscode.commands.registerCommand('vibecop._copyFix', (fix: string) => {
      void vscode.env.clipboard.writeText(fix).then(() => {
        void vscode.window.showInformationMessage('VibeCop: fix suggestion copied to clipboard.');
      });
    }),

    vscode.languages.registerCodeLensProvider(JS_TS_SELECTOR, codeLensProvider),

    vscode.commands.registerCommand('vibecop.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) void scanActiveFile(editor.document);
    }),

    vscode.commands.registerCommand('vibecop.scanWorkspace', () => {
      void scanWorkspace();
    }),

    vscode.commands.registerCommand('vibecop.clearDiagnostics', () => {
      collection.clear();
      fileScores.clear();
      lastScanResult = null;
      statusBar.showIdle();
      codeLensProvider.refresh();
    }),

    vscode.commands.registerCommand('vibecop.saveBaseline', () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders?.length) {
        void vscode.window.showWarningMessage('VibeCop: no workspace folder open.');
        return;
      }
      if (!lastScanResult) {
        void vscode.window.showWarningMessage('VibeCop: run a workspace scan first.');
        return;
      }
      saveBaseline(folders[0].uri.fsPath, lastScanResult);
      void vscode.window.showInformationMessage(`VibeCop: baseline saved (VibeScore ${lastScanResult.vibeScore}/100).`);
    }),

    vscode.commands.registerCommand('vibecop._showFindingDetail', (finding: unknown) => {
      void showFindingDetail(finding as Parameters<typeof showFindingDetail>[0]);
    }),

    vscode.commands.registerCommand('vibecop.generateFixPrompt', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showWarningMessage('VibeCop: open a file first.');
        return;
      }
      void generateFixPromptCommand(editor.document);
    }),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!getConfig().scanOnSave || !isJsTs(doc)) return;
      void scanActiveFile(doc);
    }),

    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (!getConfig().scanOnOpen || !isJsTs(doc)) return;
      void scanActiveFile(doc);
    }),

    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (!editor || !isJsTs(editor.document)) { statusBar.showIdle(); return; }
      const cached = fileScores.get(editor.document.uri.toString());
      if (cached !== undefined) {
        statusBar.updateScore(cached);
      } else {
        statusBar.showIdle();
      }
    }),
  );

  const editor = vscode.window.activeTextEditor;
  if (editor && isJsTs(editor.document)) {
    void scanActiveFile(editor.document);
  }
}

export function deactivate(): void {
  collection?.dispose();
}

async function scanActiveFile(document: vscode.TextDocument): Promise<void> {
  const cfg = getConfig();
  if (!cfg.enabled) return;

  statusBar.showScanning();
  try {
    const { findings, vibeScore } = await bridgeScanFile(document.uri.fsPath, cfg.minSeverity, cfg.ruleOverrides);
    collection.set(document.uri, findings.map((f) => findingToDiagnostic(f, document.uri)));
    fileScores.set(document.uri.toString(), vibeScore);
    codeLensProvider.refresh();
    if (cfg.showVibeScore) statusBar.updateScore(vibeScore);
  } catch (err) {
    void vscode.window.showErrorMessage(`VibeCop scan failed: ${String(err)}`);
    statusBar.showIdle();
  }
}

async function scanWorkspace(): Promise<void> {
  const cfg = getConfig();
  if (!cfg.enabled) return;

  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    void vscode.window.showWarningMessage('VibeCop: no workspace folder open.');
    return;
  }

  statusBar.showScanning();
  collection.clear();
  fileScores.clear();

  try {
    for (const folder of folders) {
      const result = await scanDirectory(folder.uri.fsPath, cfg.minSeverity, cfg.ruleOverrides);
      lastScanResult = result;
      const baseline = loadBaseline(folder.uri.fsPath);

      for (const fileResult of result.files) {
        const uri = vscode.Uri.file(fileResult.filePath);
        if (fileResult.findings.length > 0) {
          collection.set(uri, fileResult.findings.map((f) => findingToDiagnostic(f, uri)));
        }
        fileScores.set(uri.toString(), computeFileVibeScore(fileResult.findings));
      }

      if (cfg.showVibeScore) {
        const editor = vscode.window.activeTextEditor;
        const displayScore = editor
          ? (fileScores.get(editor.document.uri.toString()) ?? result.vibeScore)
          : result.vibeScore;
        statusBar.updateScore(displayScore, baseline?.vibeScore);

        if (baseline && result.vibeScore < baseline.vibeScore) {
          void vscode.window.showWarningMessage(
            `VibeCop: VibeScore dropped ${result.vibeScore - baseline.vibeScore} pts vs baseline (${baseline.vibeScore}/100 → ${result.vibeScore}/100)`,
          );
        }
      }
    }
    codeLensProvider.refresh();
  } catch (err) {
    void vscode.window.showErrorMessage(`VibeCop workspace scan failed: ${String(err)}`);
    statusBar.showIdle();
  }
}

async function generateFixPromptCommand(document: vscode.TextDocument): Promise<void> {
  const fileName = path.basename(document.uri.fsPath);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `VibeCop: generating fix prompt for ${fileName}…`, cancellable: false },
    async () => {
      try {
        const prompt = await generateFixPromptForFile(document.uri.fsPath);
        const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: prompt });
        await vscode.window.showTextDocument(doc, { preview: false });
        const choice = await vscode.window.showInformationMessage(
          '✅ Fix prompt generated — paste into Claude, Cursor, or ChatGPT',
          'Copy to clipboard',
        );
        if (choice === 'Copy to clipboard') {
          await vscode.env.clipboard.writeText(prompt);
        }
      } catch (err) {
        void vscode.window.showErrorMessage(`VibeCop: fix prompt failed — ${String(err)}`);
      }
    },
  );
}

function isJsTs(document: vscode.TextDocument): boolean {
  return ['typescript', 'javascript', 'typescriptreact', 'javascriptreact'].includes(document.languageId);
}
