import * as vscode from 'vscode';
import * as path from 'path';
import { getConfig } from './config';
import { findingToDiagnostic } from './diagnostics';
import { scanFile as bridgeScanFile, scanDirectory, generateFixPromptForFile } from './scanner-bridge';
import { VibeStatusBar } from './status-bar';
import { VibeCopCodeLensProvider, showFindingDetail } from './codelens';

let collection: vscode.DiagnosticCollection;
let statusBar: VibeStatusBar;
let codeLensProvider: VibeCopCodeLensProvider;
let codeLensDisposable: vscode.Disposable;

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection('vibecop');

  statusBar = new VibeStatusBar();

  codeLensProvider = new VibeCopCodeLensProvider(collection);
  codeLensDisposable = vscode.languages.registerCodeLensProvider(
    [
      { language: 'typescript' },
      { language: 'javascript' },
      { language: 'typescriptreact' },
      { language: 'javascriptreact' },
    ],
    codeLensProvider,
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vibecop.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) void scanActiveFile(editor.document);
    }),

    vscode.commands.registerCommand('vibecop.scanWorkspace', () => {
      void scanWorkspace();
    }),

    vscode.commands.registerCommand('vibecop.clearDiagnostics', () => {
      collection.clear();
      statusBar.showIdle();
      codeLensProvider.refresh();
    }),

    vscode.commands.registerCommand('vibecop._showFindingDetail', (finding: unknown) => {
      void showFindingDetail(finding as Parameters<typeof showFindingDetail>[0]);
    }),

    vscode.commands.registerCommand('vibecop.generateFixPrompt', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showWarningMessage('VibeCop: Open a file to generate a fix prompt.');
        return;
      }
      void generateFixPromptForCurrentFile(editor.document);
    }),
  );


  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!getConfig().scanOnSave) return;
      if (isJsTs(doc)) void scanActiveFile(doc);
    }),

    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (!getConfig().scanOnOpen) return;
      if (isJsTs(doc)) void scanActiveFile(doc);
    }),

    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (!editor) { statusBar.showIdle(); return; }
      const diags = collection.get(editor.document.uri);
      if (diags && diags.length > 0) {
        void scanActiveFile(editor.document, /* silent */ true);
      } else {
        statusBar.showIdle();
      }
    }),

    collection,
    codeLensDisposable,
    statusBar,
  );


  const editor = vscode.window.activeTextEditor;
  if (editor && isJsTs(editor.document)) {
    void scanActiveFile(editor.document);
  }
}

export function deactivate(): void {
  collection?.dispose();
}

async function scanActiveFile(
  document: vscode.TextDocument,
  silent = false,
): Promise<void> {
  const cfg = getConfig();
  if (!cfg.enabled) return;

  if (!silent) statusBar.showScanning();

  try {
    const filePath = document.uri.fsPath;
    const { findings, vibeScore } = await bridgeScanFile(filePath, cfg.minSeverity);

    const diagnostics = findings.map((f) => findingToDiagnostic(f, document.uri));
    collection.set(document.uri, diagnostics);
    codeLensProvider.refresh();

    if (cfg.showVibeScore) {
      statusBar.updateScore(vibeScore);
    }
  } catch (err) {
    if (!silent) {
      void vscode.window.showErrorMessage(`VibeCop scan failed: ${String(err)}`);
    }
    statusBar.showIdle();
  }
}

async function scanWorkspace(): Promise<void> {
  const cfg = getConfig();
  if (!cfg.enabled) return;

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    void vscode.window.showWarningMessage('VibeCop: No workspace folder open.');
    return;
  }

  statusBar.showScanning();
  collection.clear();

  try {
    for (const folder of workspaceFolders) {
      const result = await scanDirectory(folder.uri.fsPath, cfg.minSeverity);

      for (const fileResult of result.files) {
        if (fileResult.findings.length === 0) continue;
        const fileUri = vscode.Uri.file(fileResult.filePath);
        const diagnostics = fileResult.findings.map((f) =>
          findingToDiagnostic(f, fileUri),
        );
        collection.set(fileUri, diagnostics);
      }

      if (cfg.showVibeScore) {
        statusBar.updateScore(result.vibeScore);
      }
    }
    codeLensProvider.refresh();
  } catch (err) {
    void vscode.window.showErrorMessage(`VibeCop workspace scan failed: ${String(err)}`);
    statusBar.showIdle();
  }
}

function isJsTs(document: vscode.TextDocument): boolean {
  return ['typescript', 'javascript', 'typescriptreact', 'javascriptreact'].includes(
    document.languageId,
  );
}

async function generateFixPromptForCurrentFile(document: vscode.TextDocument): Promise<void> {
  const filePath = document.uri.fsPath;
  const fileName = path.basename(filePath);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `VibeCop: generating fix prompt for ${fileName}…`, cancellable: false },
    async () => {
      try {
        const prompt = await generateFixPromptForFile(filePath);
        // Open prompt in a new untitled markdown document
        const doc = await vscode.workspace.openTextDocument({
          language: 'markdown',
          content: prompt,
        });
        await vscode.window.showTextDocument(doc, { preview: false });
        const choice = await vscode.window.showInformationMessage(
          '✅ Fix prompt generated — copy it and paste into Claude, Cursor, or ChatGPT',
          'Copy to clipboard',
        );
        if (choice === 'Copy to clipboard') {
          await vscode.env.clipboard.writeText(prompt);
          void vscode.window.showInformationMessage('✅ Prompt copied to clipboard!');
        }
      } catch (err) {
        void vscode.window.showErrorMessage(`VibeCop: fix prompt generation failed — ${String(err)}`);
      }
    },
  );
}
