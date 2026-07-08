import { parentPort, workerData } from 'node:worker_threads';
import { scanFile, getEnabledRules, PARSE_OPTIONS } from './scan-file.js';
import { VibescanConfig, Severity } from './rules/types.js';
import { parse } from '@typescript-eslint/typescript-estree';
import path from 'node:path';

export interface WorkerData {
  files: string[];
  basePath: string;
  config: VibescanConfig;
  minSeverity: Severity;
  noAiScore: boolean;
  includeTests: boolean;
  ruleId?: string;
  preloadedSources?: Record<string, string>;
}

if (parentPort) {
  const data = workerData as WorkerData;
  const rules = getEnabledRules(data.config, data.ruleId);

  if (data.preloadedSources) {
    const { crossFileCache } = require('./cross-file/cross-file-resolver.js');
    crossFileCache.initWithSources(data.preloadedSources);
    const { runPhase1 } = require('./cross-file/phase1-parser.js');
    
    // Build globalSymbolTable locally in worker
    for (const [filePath, source] of Object.entries(data.preloadedSources)) {
      try {
        const ext = path.extname(filePath).toLowerCase();
        let ast;
        try {
          ast = parse(source as string, { ...PARSE_OPTIONS, jsx: ext === '.jsx' || ext === '.tsx' });
        } catch {
          try { ast = parse(source as string, { ...PARSE_OPTIONS, jsx: true }); } catch { continue; }
        }
        runPhase1(ast, filePath);
      } catch {}
    }
  }

  for (const file of data.files) {
    try {
      const source = data.preloadedSources ? data.preloadedSources[file] : undefined;
      const result = scanFile(file, data.basePath, rules, data.config, data.minSeverity, data.noAiScore, source, undefined, data.includeTests);
      parentPort.postMessage({ type: 'result', result });
    } catch (err) {
      parentPort.postMessage({ type: 'result', result: { filePath: file, relativePath: file, findings: [], aiScore: 0, parseError: String(err) }});
    }
  }

  parentPort.postMessage({ type: 'done' });
}
