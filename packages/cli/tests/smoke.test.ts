import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, loadConfig, DEFAULT_CONFIG } from '../src/lib.js';
import type { ScanOptions } from '../src/lib.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, 'fixtures');

/** Minimal base scan options using the default config. */
function makeScanOpts(fixturePath: string, overrides: Partial<ScanOptions> = {}): ScanOptions {
  return {
    path: fixturePath,
    config: DEFAULT_CONFIG,
    format: 'terminal',
    severity: 'warn',
    ci: true,
    fix: false,
    noAiScore: false,
    watch: false,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite 1 — Clean fixture produces zero findings
// ─────────────────────────────────────────────────────────────────────────────
describe('clean fixture (should-not-flag/clean-express-api.ts)', () => {
  const CLEAN = join(FIXTURES, 'should-not-flag', 'clean-express-api.ts');

  it('returns 0 errors at warn severity', async () => {
    const result = await scan(makeScanOpts(CLEAN));
    expect(result.errorCount).toBe(0);
  });

  it('returns 0 warnings at warn severity', async () => {
    const result = await scan(makeScanOpts(CLEAN));
    expect(result.warnCount).toBe(0);
  });

  it('achieves VibeScore 100 when there are no warn/error findings', async () => {
    const result = await scan(makeScanOpts(CLEAN));
    expect(result.vibeScore).toBe(100);
  });

  it('scans exactly 1 file', async () => {
    const result = await scan(makeScanOpts(CLEAN));
    expect(result.filesScanned).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Suite 2 — Buggy auth fixture triggers expected findings
// ─────────────────────────────────────────────────────────────────────────────
describe('auth fixture (should-flag/auth-fixture-buggy.ts)', () => {
  const BUGGY = join(FIXTURES, 'should-flag', 'auth-fixture-buggy.ts');
  const INFO_OPTS = makeScanOpts(BUGGY, { severity: 'info' });

  it('produces at least 8 errors', async () => {
    const result = await scan(INFO_OPTS);
    expect(result.errorCount).toBeGreaterThanOrEqual(8);
  });

  it('flags security/hardcoded-secrets', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('security/hardcoded-secrets');
  });

  it('flags security/sql-injection', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('security/sql-injection');
  });

  it('flags security/jwt-no-expiry', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('security/jwt-no-expiry');
  });

  it('flags security/weak-crypto', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('security/weak-crypto');
  });

  it('flags ai-smell/todo-stub-functions', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('ai-smell/todo-stub-functions');
  });

  it('flags ai-smell/mixed-async-patterns', async () => {
    const result = await scan(INFO_OPTS);
    const ruleIds = result.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    expect(ruleIds).toContain('ai-smell/mixed-async-patterns');
  });

  it('does not parse-error on the fixture file', async () => {
    const result = await scan(INFO_OPTS);
    const parseErrors = result.files.filter((f) => f.parseError);
    expect(parseErrors).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Suite 3 — Config loader
// ─────────────────────────────────────────────────────────────────────────────
describe('loadConfig', () => {
  it('returns a valid config with rules when no config file is present', async () => {
    // Use a temp directory that has no vibescan config
    const config = await loadConfig(join(__dirname, '..', 'dist'));
    expect(config).toBeDefined();
    expect(typeof config.rules).toBe('object');
    expect(Object.keys(config.rules).length).toBeGreaterThan(0);
  });

  it('returned config includes expected security rules', async () => {
    const config = await loadConfig();
    expect(config.rules['security/hardcoded-secrets']).toBeDefined();
    expect(config.rules['security/sql-injection']).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Suite 4 — DEFAULT_CONFIG shape
// ─────────────────────────────────────────────────────────────────────────────
describe('DEFAULT_CONFIG', () => {
  it('has a version field', () => {
    expect(DEFAULT_CONFIG.version).toBeDefined();
  });

  it('marks hardcoded-secrets as error', () => {
    expect(DEFAULT_CONFIG.rules['security/hardcoded-secrets']).toBe('error');
  });

  it('marks sql-injection as error', () => {
    expect(DEFAULT_CONFIG.rules['security/sql-injection']).toBe('error');
  });

  it('has include patterns', () => {
    expect(DEFAULT_CONFIG.include.length).toBeGreaterThan(0);
  });

  it('excludes node_modules', () => {
    expect(DEFAULT_CONFIG.exclude.some((p) => p.includes('node_modules'))).toBe(true);
  });
});
