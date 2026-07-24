import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Finding } from './rules/types.js';
import crypto from 'node:crypto';

import { LRUCache } from '../utils/lru-cache.js';

export interface CachedBlock {
  hash: string;
  startLine: number;
  findings: Finding[];
}

export interface CachedScan {
  blocks: CachedBlock[];
}

export type SkipRange = [number, number];

export class IncrementalCache {
  private cache = new LRUCache<string, CachedScan>(100);

  /**
   * Hashes a string using fast MD5
   */
  private hashString(content: string): string {
    return crypto.createHash('md5').update(content).digest('hex');
  }

  /**
   * Compares the new AST with the cached scan and returns the byte ranges
   * of unmodified top-level blocks to skip, along with their findings.
   */
  public getSkipRanges(
    filePath: string,
    newSource: string,
    newAst: TSESTree.Program
  ): { skipRanges: SkipRange[]; reusedFindings: Finding[] } {
    const skipRanges: SkipRange[] = [];
    const reusedFindings: Finding[] = [];

    const cached = this.cache.get(filePath);
    if (!cached) return { skipRanges, reusedFindings };

    // Build a map of old block hashes
    const oldHashMap = new Map<string, CachedBlock>();
    for (const block of cached.blocks) {
      oldHashMap.set(block.hash, block);
    }

    // Now check new statements
    for (const statement of newAst.body) {
      if (!statement.range || !statement.loc) continue;
      const newSnippet = newSource.substring(statement.range[0], statement.range[1]);
      const hash = this.hashString(newSnippet);

      const match = oldHashMap.get(hash);
      if (match) {
        // Unmodified block!
        skipRanges.push([statement.range[0], statement.range[1]]);
        
        // Compute line delta in case the block shifted up/down
        const lineDelta = statement.loc.start.line - match.startLine;
        
        for (const finding of match.findings) {
          reusedFindings.push({
            ...finding,
            line: finding.line + lineDelta
          });
        }
        
        // Remove from map to avoid duplicates if identical blocks exist
        oldHashMap.delete(hash);
      }
    }

    return { skipRanges, reusedFindings };
  }

  public saveScan(filePath: string, source: string, ast: TSESTree.Program, findings: Finding[]) {
    const blocks: CachedBlock[] = [];
    
    for (const statement of ast.body) {
      if (!statement.range || !statement.loc) continue;
      const snippet = source.substring(statement.range[0], statement.range[1]);
      const hash = this.hashString(snippet);
      
      const statementFindings = findings.filter(f => 
        f.line >= statement.loc.start.line && f.line <= statement.loc.end.line
      );
      
      blocks.push({
        hash,
        startLine: statement.loc.start.line,
        findings: statementFindings
      });
    }
    
    this.cache.set(filePath, { blocks });
  }
}

export const incrementalCache = new IncrementalCache();
