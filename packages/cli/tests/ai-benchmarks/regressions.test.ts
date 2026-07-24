import { describe, it, expect } from 'vitest';
import { parse } from '@typescript-eslint/typescript-estree';
import hardcodedSecretsRule from '../../src/scanner/rules/security/hardcoded-secrets.js';
import nPlusOneQueriesRule from '../../src/scanner/rules/tech-debt/n-plus-one-queries.js';

function getAst(code: string) {
  return parse(code, { loc: true, range: true, comment: true, jsx: false }) as any;
}

describe('Regression Tests for Bugs', () => {
  it('should report hardcoded secrets as warn in test files with correct message', () => {
    const code = `
      const JWT_SECRET = 'use_a_long_random_string_here_min_32_chars';
    `;
    const ast = getAst(code);
    const findings = hardcodedSecretsRule.check(ast, code, 'my-test.test.ts');
    
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('warn');
    expect(findings[0].message).toBe('hardcoded secret in test file — use environment variables even in tests');
  });

  it('should flag N+1 query for db method in loop', () => {
    const code = `
      for (const user of users) {
        db.users.find({ id: user.id });
      }
    `;
    const ast = getAst(code);
    const findings = nPlusOneQueriesRule.check(ast, code, 'file.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('warn');
  });

  it('should ignore Array.find inside loop when called on loop variable property', () => {
    const code = `
      users.map(user => user.roles.find(r => r === 'admin'));
    `;
    const ast = getAst(code);
    const findings = nPlusOneQueriesRule.check(ast, code, 'file.ts');
    expect(findings.length).toBe(0);
  });

  it('should ignore nested scopes with shadowing correctly', () => {
    const code = `
      users.map(user => user.orders.map(order => order.items.find(i => i.id === 1)));
    `;
    const ast = getAst(code);
    const findings = nPlusOneQueriesRule.check(ast, code, 'file.ts');
    expect(findings.length).toBe(0);
  });

  it('should ignore destructuring in map correctly', () => {
    const code = `
      users.map(({ roles }) => roles.find(r => r === 'admin'));
    `;
    const ast = getAst(code);
    const findings = nPlusOneQueriesRule.check(ast, code, 'file.ts');
    expect(findings.length).toBe(0);
  });

  it('should ignore intermediate variables through fallback whitelist', () => {
    const code = `
      users.map(user => { const r = user.roles; return r.find(x => x); })
    `;
    const ast = getAst(code);
    const findings = nPlusOneQueriesRule.check(ast, code, 'file.ts');
    expect(findings.length).toBe(0);
  });
});
