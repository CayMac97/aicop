import * as vscode from 'vscode';

export class VibeStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = 'vibecop.scanWorkspace';
    this.item.tooltip = 'VibeCop — Click to scan workspace';
    this.item.text = '🛡️ VibeCop';
    this.item.show();
  }

  showScanning(): void {
    this.item.text = '🛡️ VibeCop: scanning…';
    this.item.backgroundColor = undefined;
  }

  showIdle(): void {
    this.item.text = '🛡️ VibeCop';
    this.item.backgroundColor = undefined;
  }

  updateScore(score: number, baseline?: number | null): void {
    if (score >= 100) {
      this.item.text = '🛡️ VibeCop: ✓ clean';
      this.item.backgroundColor = undefined;
    } else {
      this.item.text = `🛡️ VibeScore: ${score}/100`;
      this.item.backgroundColor = colorForScore(score);
    }
    if (baseline != null) {
      const delta = score - baseline;
      const sign = delta > 0 ? '+' : '';
      this.item.tooltip = `VibeCop — Click to scan workspace\nBaseline: ${baseline}/100  (${sign}${delta} pts)`;
    } else {
      this.item.tooltip = 'VibeCop — Click to scan workspace';
    }
  }

  dispose(): void {
    this.item.dispose();
  }
}

function colorForScore(score: number): vscode.ThemeColor | undefined {
  if (score >= 90) return undefined;
  if (score >= 60) return new vscode.ThemeColor('statusBarItem.warningBackground');
  return new vscode.ThemeColor('statusBarItem.errorBackground');
}
