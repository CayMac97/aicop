import * as vscode from 'vscode';

export interface VibeCopConfig {
  enabled: boolean;
  scanOnSave: boolean;
  scanOnOpen: boolean;
  minSeverity: 'info' | 'warn' | 'error';
  showVibeScore: boolean;
  excludePatterns: string[];
  ruleOverrides: Record<string, 'off' | 'info' | 'warn' | 'error'>;
}

export function getConfig(): VibeCopConfig {
  const cfg = vscode.workspace.getConfiguration('vibecop');
  return {
    enabled:         cfg.get<boolean>('enabled', true),
    scanOnSave:      cfg.get<boolean>('scanOnSave', true),
    scanOnOpen:      cfg.get<boolean>('scanOnOpen', true),
    minSeverity:     cfg.get<'info' | 'warn' | 'error'>('minSeverity', 'warn'),
    showVibeScore:   cfg.get<boolean>('showVibeScore', true),
    excludePatterns: cfg.get<string[]>('excludePatterns', ['node_modules/**', 'dist/**', 'build/**']),
    ruleOverrides:   cfg.get<Record<string, 'off' | 'info' | 'warn' | 'error'>>('ruleOverrides', {}),
  };
}
