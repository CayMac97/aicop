import * as vscode from 'vscode';

export class VibeStatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100,
    );
    this.item.command = 'vibecop.scanWorkspace';
    this.item.tooltip = 'VibeCop — Click to scan workspace';
    this.item.text = '🛡️ VibeCop';
    this.item.show();
  }

  showScanning(): void {
    this.item.text = '🛡️ VibeCop: scanning…';
    this.item.backgroundColor = undefined;
  }

  updateScore(score: number): void {
    if (score >= 100) {
      this.item.text = '🛡️ VibeCop: ✓ clean';
      this.item.backgroundColor = undefined;
    } else {
      this.item.text = `🛡️ VibeScore: ${score}/100`;
      this.item.backgroundColor = this.colorForScore(score);
    }
  }

  showIdle(): void {
    this.item.text = '🛡️ VibeCop';
    this.item.backgroundColor = undefined;
  }

  dispose(): void {
    this.item.dispose();
  }

  private colorForScore(score: number): vscode.ThemeColor | undefined {
    if (score >= 90) return undefined;
    if (score >= 60) return new vscode.ThemeColor('statusBarItem.warningBackground');
    return new vscode.ThemeColor('statusBarItem.errorBackground');
  }
}
