import { describe, it, expect, beforeEach, vi } from 'vitest';
import { parse } from '@typescript-eslint/typescript-estree';
import { buildContextualTaintMap, getCrossFileTaints } from '../src/utils/taint-tracker.js';
import { crossFileCache } from '../src/scanner/cross-file/cross-file-resolver.js';
import { globalSymbolTable } from '../src/scanner/cross-file/global-symbol-table.js';
import * as moduleResolver from '../src/scanner/cross-file/module-resolver.js';
import path from 'node:path';

vi.mock('../src/scanner/cross-file/module-resolver.js', async (importOriginal) => {
  return {
    ...await importOriginal<any>(),
    resolveLocalModule: vi.fn((importPath: string) => {
      if (importPath === './db') return path.resolve('/app/db.js').replace(/\\/g, '/');
      return null;
    })
  };
});

describe('TaintTracker', () => {
  beforeEach(() => {
    crossFileCache.clear();
    globalSymbolTable.clear();
    vi.mocked(moduleResolver.resolveLocalModule).mockImplementation((importPath: string) => {
      if (importPath === './db') return path.resolve('/app/db.js').replace(/\\/g, '/');
      return null;
    });
  });

  it('detects simple cross-file taints', () => {
    const mainCode = `
      import { doTask } from './db';
      app.get('/users', (req, res) => {
        const id = req.query.id;
        doTask(id);
      });
    `;

    const dbCode = `
      export function doTask(q) {
        db.query(q);
      }
    `;

    const mainAst = parse(mainCode, { jsx: false, loc: true, range: true });
    
    const dbPath = path.resolve('/app/db.js').replace(/\\/g, '/');
    const mainPath = path.resolve('/app/main.js').replace(/\\/g, '/');

    crossFileCache.initWithSources({ [dbPath]: dbCode });

    const taints = buildContextualTaintMap(mainAst, mainPath);
    const crossTaints = getCrossFileTaints(mainAst, mainPath, taints);
    expect(crossTaints.length).toBe(1);
    expect(crossTaints[0].externalFilePath).toBe(dbPath);
    expect(crossTaints[0].taintedParams.has('q')).toBe(true);
  });

  it('detects export default cross-file taints', () => {
    const mainCode = `
      import runDB from './db';
      app.post('/users', (req, res) => {
        runDB(req.body.name);
      });
    `;

    const dbCode = `
      function internalTask(data) {
        db.execute(data);
      }
      export default internalTask;
    `;

    const mainAst = parse(mainCode, { jsx: false, loc: true, range: true });
    const dbPath = path.resolve('/app/db.js').replace(/\\/g, '/');
    const mainPath = path.resolve('/app/main.js').replace(/\\/g, '/');

    crossFileCache.initWithSources({ [dbPath]: dbCode });

    const taints = buildContextualTaintMap(mainAst, mainPath);
    const crossTaints = getCrossFileTaints(mainAst, mainPath, taints);
    expect(crossTaints.length).toBe(1);
    expect(crossTaints[0].externalFilePath).toBe(dbPath);
    expect(crossTaints[0].taintedParams.has('data')).toBe(true);
  });

  it('detects export * cross-file taints', () => {
    const mainCode = `
      import { processDB } from './db';
      app.post('/users', (req, res) => {
        processDB(req.body.name);
      });
    `;

    const dbCode = `
      export * from './internal';
    `;

    const internalCode = `
      export function processDB(info) {
        db.run(info);
      }
    `;

    const mainAst = parse(mainCode, { jsx: false, loc: true, range: true });
    const dbPath = path.resolve('/app/db.js').replace(/\\/g, '/');
    const internalPath = path.resolve('/app/internal.js').replace(/\\/g, '/');
    const mainPath = path.resolve('/app/main.js').replace(/\\/g, '/');

    vi.mocked(moduleResolver.resolveLocalModule).mockImplementation((importPath: string) => {
      if (importPath === './db') return dbPath;
      if (importPath === './internal') return internalPath;
      return null;
    });

    crossFileCache.initWithSources({ 
      [dbPath]: dbCode,
      [internalPath]: internalCode
    });

    const taints = buildContextualTaintMap(mainAst, mainPath);
    const crossTaints = getCrossFileTaints(mainAst, mainPath, taints);
    expect(crossTaints.length).toBe(1);
    expect(crossTaints[0].externalFilePath).toBe(internalPath);
    expect(crossTaints[0].taintedParams.has('info')).toBe(true);
  });
});
