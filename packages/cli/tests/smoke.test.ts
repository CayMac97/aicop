import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, loadConfig, DEFAULT_CONFIG } from '../src/lib.js';
import type { ScanOptions } from '../src/lib.js';
import { isVendorFile } from '../src/scanner/file-collector.js';
import { parse } from '@typescript-eslint/typescript-estree';
import functionLengthRule from '../src/scanner/rules/tech-debt/function-length.js';

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

  it('achieves AIScore 100 when there are no warn/error findings', async () => {
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
describe('NoSQL injection fixtures', () => {
  const VULNERABLE = join(FIXTURES, 'should-flag', 'nosql-injection.ts');
  const SAFE = join(FIXTURES, 'should-not-flag', 'safe-mongo.ts');

  it('flags at least 4 NoSQL injection errors', async () => {
    const result = await scan(makeScanOpts(VULNERABLE, {
      severity: 'info',
      ruleId: 'security/nosql-injection',
    }));
    const findings = result.files.flatMap((f) => f.findings);
    expect(result.errorCount).toBeGreaterThanOrEqual(4);
    expect(findings.filter((f) => f.ruleId === 'security/nosql-injection')).toHaveLength(4);
  });

  it('does not flag sanitized Mongo queries', async () => {
    const result = await scan(makeScanOpts(SAFE, {
      severity: 'info',
      ruleId: 'security/nosql-injection',
    }));
    const findings = result.files.flatMap((f) => f.findings);
    expect(findings.filter((f) => f.ruleId === 'security/nosql-injection')).toHaveLength(0);
  });
});

describe('isVendorFile', () => {
  it('flags files in a vendor directory', () => {
    expect(isVendorFile('/app/vendor/jquery.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/vendors/bootstrap.js', '', 1000)).toBe(true);
  });

  it('flags minified files by filename', () => {
    expect(isVendorFile('/app/public/app.min.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/dist/bundle.bundle.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/dist/chunk.chunk.js', '', 1000)).toBe(true);
  });

  it('flags jquery.js / bootstrap.js via exact stem match', () => {
    expect(isVendorFile('/app/js/jquery.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/js/bootstrap.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/js/jquery.slim.js', '', 1000)).toBe(true);
  });

  it('flags known library filenames by token (versioned / suffixed)', () => {
    expect(isVendorFile('/app/js/jquery-3.6.0.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/js/jquery.min.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/js/lodash.esm.js', '', 1000)).toBe(true);
    expect(isVendorFile('/app/js/bootstrap.bundle.js', '', 1000)).toBe(true);
  });

  it('does not flag non-library files with lib-like tokens', () => {
    expect(isVendorFile('/app/src/jquery-migration-helper.js', '', 1000)).toBe(false);
    expect(isVendorFile('/app/src/react-query-adapter.ts', '', 1000)).toBe(false);
  });

  it('flags files with /*! or @license in first bytes', () => {
    const vendorContent = '/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors */\nvar jQuery = {};';
    expect(isVendorFile('/app/src/some-file.js', vendorContent, 1000)).toBe(true);
  });

  it('flags Babel/Browserify bundles >50KB starting with !function(', () => {
    const babelContent = '!function(e,t){"use strict";var r={}';
    const over50kb = 51 * 1024;
    expect(isVendorFile('/app/dist/app.js', babelContent, over50kb)).toBe(true);
  });

  it('flags Babel bundles starting with [function(', () => {
    const babelContent = '[function(e,t,r){"use strict";module.exports=r(0)';
    const over50kb = 51 * 1024;
    expect(isVendorFile('/app/dist/app.js', babelContent, over50kb)).toBe(true);
  });

  it('does not flag small files with !function( (could be app code)', () => {
    const content = '!function(e){window.myLib=e()}(function(){return{}})';
    expect(isVendorFile('/app/src/tiny.js', content, 1000)).toBe(false);
  });

  it('flags non-TS files over 200KB regardless of content', () => {
    const over200kb = 201 * 1024;
    expect(isVendorFile('/app/public/legacy.js', '', over200kb)).toBe(true);
    expect(isVendorFile('/app/public/legacy.jsx', '', over200kb)).toBe(true);
  });

  it('does not auto-flag .ts/.tsx files over 200KB', () => {
    const over200kb = 201 * 1024;
    expect(isVendorFile('/app/src/generated.ts', 'export {}', over200kb)).toBe(false);
    expect(isVendorFile('/app/src/generated.tsx', 'export {}', over200kb)).toBe(false);
  });

  it('does not flag normal source files', () => {
    expect(isVendorFile('/app/src/auth.ts', 'import express from "express";\n', 500)).toBe(false);
    expect(isVendorFile('/app/src/utils/helper.js', 'export function helper() {}', 500)).toBe(false);
  });
});

describe('aicop-ignore inline suppression', () => {
  const IGNORE_CLEAN = join(FIXTURES, 'should-not-flag', 'ignore-comments.ts');
  const IGNORE_WRONG = join(FIXTURES, 'should-flag', 'ignore-wrong-rule.ts');

  it('suppresses findings when // aicop-ignore precedes the line', async () => {
    const result = await scan(makeScanOpts(IGNORE_CLEAN, { severity: 'info', ruleId: 'security/hardcoded-secrets' }));
    const findings = result.files.flatMap((f) => f.findings);
    expect(findings.filter((f) => f.ruleId === 'security/hardcoded-secrets')).toHaveLength(0);
  });

  it('suppresses when // aicop-ignore rule-id matches', async () => {
    const result = await scan(makeScanOpts(IGNORE_CLEAN, { severity: 'info' }));
    const findings = result.files.flatMap((f) => f.findings);
    expect(findings.filter((f) => f.ruleId === 'security/hardcoded-secrets')).toHaveLength(0);
  });

  it('still flags when // aicop-ignore uses a different rule id', async () => {
    const result = await scan(makeScanOpts(IGNORE_WRONG, { severity: 'info', ruleId: 'security/hardcoded-secrets' }));
    const findings = result.files.flatMap((f) => f.findings);
    expect(findings.filter((f) => f.ruleId === 'security/hardcoded-secrets').length).toBeGreaterThan(0);
  });
});

describe('loadConfig', () => {
  it('returns a valid config with rules when no config file is present', async () => {
    // Use a temp directory that has no aicop config
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

// ─────────────────────────────────────────────────────────────────────────────
// Suite 5 — function-length thresholds (60 warn / 100 error)
// ─────────────────────────────────────────────────────────────────────────────
function makeFunction(lines: number): string {
  const body = Array.from({ length: lines - 2 }, (_, i) => `  const _v${i} = ${i};`).join('\n');
  return `function longFn() {\n${body}\n}`;
}

function scanFunctionLength(source: string) {
  const ast = parse(source, { loc: true, range: true, jsx: false });
  return functionLengthRule.check(ast, source, 'test.ts');
}

describe('function-length rule thresholds', () => {
  it('does not flag a 55-line function', () => {
    const findings = scanFunctionLength(makeFunction(55));
    expect(findings).toHaveLength(0);
  });

  it('flags a 65-line function as warn', () => {
    const findings = scanFunctionLength(makeFunction(65));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('warn');
  });

  it('flags a 105-line function as error', () => {
    const findings = scanFunctionLength(makeFunction(105));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('error');
  });
});
