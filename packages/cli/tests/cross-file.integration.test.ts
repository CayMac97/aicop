import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { scan } from '../src/scanner/index.js';
import { loadConfig } from '../src/config/loader.js';

describe('Cross-File Integration', () => {
  it('detects a deep SQL injection across multiple files', async () => {
    const fixturePath = path.resolve(__dirname, 'fixtures', 'cross-file-project');

    const config = await loadConfig();

    const result = await scan({
      path: fixturePath,
      config,
      noAiScore: true,
      includeTests: false,
      severity: 'info',
      ci: false,
      fix: false,
      watch: false,
      format: 'terminal'
    });

    const findings = result.files.flatMap(f => f.findings);
    const sqlInjections = findings.filter(f => f.ruleId === 'security/sql-injection');

    expect(sqlInjections.length).toBeGreaterThan(0);

    const crossFileInjections = sqlInjections.filter(f => f.message.includes('Cross-File'));
    expect(crossFileInjections.length).toBeGreaterThan(0);
  });
});
