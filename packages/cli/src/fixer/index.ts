// packages/cli/src/fixer/index.ts
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { ScanResult, ParsedAST, Finding } from '../scanner/rules/types.js';
import { parse } from '@typescript-eslint/typescript-estree';

export interface FixReplacement {
  start: number;
  end: number;
  text: string;
}

export interface RuleFixer {
  ruleId: string;
  fix(source: string, ast: ParsedAST, findings: Finding[]): FixReplacement[];
}

const fixers = new Map<string, RuleFixer>();

export function registerFixer(fixer: RuleFixer) {
  fixers.set(fixer.ruleId, fixer);
}

// Import fixers
import './jwt-no-expiry.fix.js';
import './weak-crypto.fix.js';
import './debug-leftovers.fix.js';
import './mixed-async-patterns.fix.js';

export interface FixEngineOptions {
  dryRun?: boolean;
}

export async function applyFixes(result: ScanResult, opts: FixEngineOptions = {}) {
  const backupDir = path.join(process.cwd(), '.aicop-backup', Date.now().toString());
  
  let totalFixed = 0;

  for (const fileResult of result.files) {
    if (fileResult.findings.length === 0) continue;

    const fileFixers = new Map<string, Finding[]>();
    for (const finding of fileResult.findings) {
      if (fixers.has(finding.ruleId)) {
        if (!fileFixers.has(finding.ruleId)) {
          fileFixers.set(finding.ruleId, []);
        }
        fileFixers.get(finding.ruleId)!.push(finding);
      }
    }

    if (fileFixers.size === 0) continue;

    const fullPath = fileResult.filePath;
    if (!fs.existsSync(fullPath)) continue;

    let source = fs.readFileSync(fullPath, 'utf8');
    let ast;
    try {
      ast = parse(source, { loc: true, range: true, jsx: true });
    } catch {
      continue;
    }

    let modified = false;
    let allReplacements: FixReplacement[] = [];

    for (const [ruleId, findings] of fileFixers.entries()) {
      const fixer = fixers.get(ruleId);
      if (!fixer) continue;

      try {
        const replacements = fixer.fix(source, ast, findings);
        if (replacements && replacements.length > 0) {
          allReplacements.push(...replacements);
          modified = true;
        }
      } catch (e) {
        // Ignored
      }
    }

    if (modified && allReplacements.length > 0) {
      if (!opts.dryRun) {
        // Create backup
        const backupPath = path.join(backupDir, fileResult.relativePath);
        fs.mkdirSync(path.dirname(backupPath), { recursive: true });
        fs.writeFileSync(backupPath, fs.readFileSync(fullPath));
      }

      // Apply replacements descending by start
      allReplacements.sort((a, b) => b.start - a.start);
      let newSource = source;
      for (const r of allReplacements) {
        newSource = newSource.slice(0, r.start) + r.text + newSource.slice(r.end);
      }

      if (!opts.dryRun) {
        fs.writeFileSync(fullPath, newSource, 'utf8');
      }
      
      const fixCount = allReplacements.length; // Approximate
      totalFixed += fixCount;
      
      const prefix = opts.dryRun ? chalk.yellow('[DRY-RUN]') : chalk.green('[FIXED]');
      console.log(`${prefix} Applied ${fixCount} fix(es) in ${fileResult.relativePath}`);
    }
  }

  if (totalFixed > 0 && !opts.dryRun) {
    console.log(chalk.blue(`ℹ Backups saved to ${backupDir}`));
  }
}
