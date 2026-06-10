import { parentPort, workerData } from 'node:worker_threads';
import { scanFile, getEnabledRules } from './scan-file.js';
import { VibescanConfig, Severity } from './rules/types.js';

export interface WorkerData {
  files: string[];
  basePath: string;
  config: VibescanConfig;
  minSeverity: Severity;
  noAiScore: boolean;
  includeTests: boolean;
  ruleId?: string;
}

if (parentPort) {
  const data = workerData as WorkerData;
  const rules = getEnabledRules(data.config, data.ruleId);

  for (const file of data.files) {
    const result = scanFile(file, data.basePath, rules, data.config, data.minSeverity, data.noAiScore, undefined, data.includeTests);
    parentPort.postMessage({ type: 'result', result });
  }

  parentPort.postMessage({ type: 'done' });
}
