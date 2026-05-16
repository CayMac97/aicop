import * as vscode from 'vscode';

export interface AICopConfig {
  enabled: boolean;
  scanOnSave: boolean;
  scanOnOpen: boolean;
  minSeverity: 'info' | 'warn' | 'error';
  showAIScore: boolean;
  excludePatterns: string[];
  ruleOverrides: Record<string, 'off' | 'info' | 'warn' | 'error'>;
}

export function getConfig(): AICopConfig {
  const cfg = vscode.workspace.getConfiguration('aicop');
  return {
    enabled:         cfg.get<boolean>('enabled', true),
    scanOnSave:      cfg.get<boolean>('scanOnSave', true),
    scanOnOpen:      cfg.get<boolean>('scanOnOpen', true),
    minSeverity:     cfg.get<'info' | 'warn' | 'error'>('minSeverity', 'warn'),
    showAIScore:     cfg.get<boolean>('showAIScore', true),
    excludePatterns: cfg.get<string[]>('excludePatterns', ['node_modules/**', 'dist/**', 'build/**']),
    ruleOverrides:   cfg.get<Record<string, 'off' | 'info' | 'warn' | 'error'>>('ruleOverrides', {}),
  };
}
