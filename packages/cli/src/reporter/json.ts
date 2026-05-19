import { ScanResult, FileScanResult, Finding } from '../scanner/rules/types.js';

export function formatJson(result: ScanResult, version: string): string {
  const output = {
    version,
    scannedAt: new Date().toISOString(),
    summary: {
      filesScanned: result.filesScanned,
      filesWithIssues: result.filesWithIssues,
      totalFindings: result.totalFindings,
      errors: result.errorCount,
      warnings: result.warnCount,
      info: result.infoCount,
      parseErrors: result.parseErrors,
      aiScore: result.aiScore,
      scanDurationMs: result.scanDurationMs,
    },
    topIssues: result.topIssues,
    files: result.files.map(serializeFileResult),
  };
  return JSON.stringify(output, null, 2);
}

function serializeFileResult(file: FileScanResult): Record<string, unknown> {
  return {
    path: file.relativePath,
    aiScore: file.aiScore,
    parseError: file.parseError ?? null,
    findings: file.findings.map(serializeFinding),
  };
}

function serializeFinding(finding: Finding): Record<string, unknown> {
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    line: finding.line,
    column: finding.column,
    snippet: finding.snippet,
    fix: finding.fix ?? null,
  };
}
