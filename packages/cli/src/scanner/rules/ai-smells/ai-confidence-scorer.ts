import { Rule, Finding, ParsedAST } from '../types.js';

interface ScoreFactors {
  todoCount: number;
  hasInconsistentErrors: boolean;
  hasHallucinatedApis: boolean;
  magicNumberCount: number;
  hasDeadCode: boolean;
  hasMixedAsync: boolean;
  genericVarRatio: number;
  hasHardcodedSecrets: boolean;
}

function calculateScore(factors: ScoreFactors): number {
  let score = 0;
  if (factors.todoCount > 3) score += 15;
  else if (factors.todoCount > 0) score += 5;
  if (factors.hasInconsistentErrors) score += 10;
  if (factors.hasHallucinatedApis) score += 20;
  if (factors.magicNumberCount > 5) score += 10;
  else if (factors.magicNumberCount > 0) score += 5;
  if (factors.hasDeadCode) score += 15;
  if (factors.hasMixedAsync) score += 10;
  if (factors.genericVarRatio > 0.3) score += 10;
  if (factors.hasHardcodedSecrets) score += 20;
  return Math.min(100, score);
}

function scoreLabel(score: number): string {
  if (score <= 20) return 'Looks clean';
  if (score <= 50) return 'AI-touched';
  if (score <= 80) return 'Heavy AI-smell';
  return 'Needs rewrite';
}

function scoreEmoji(score: number): string {
  if (score <= 20) return '🟢';
  if (score <= 50) return '🟡';
  if (score <= 80) return '🟠';
  return '🔴';
}

function extractFactors(findings: Finding[]): ScoreFactors {
  const ruleIds = findings.map((f) => f.ruleId);
  const todoCount = ruleIds.filter((id) => id === 'ai-smell/todo-stub-functions').length;
  const identifiers = new Set<string>();
  let genericCount = 0;
  findings
    .filter((f) => f.ruleId === 'ai-smell/generic-variable-names')
    .forEach((f) => {
      const match = f.message.match(/"([^"]+)"/);
      if (match?.[1]) { identifiers.add(match[1]); genericCount++; }
    });
  return {
    todoCount,
    hasInconsistentErrors: ruleIds.includes('ai-smell/inconsistent-error-handling'),
    hasHallucinatedApis: ruleIds.includes('ai-smell/hallucinated-api-calls'),
    magicNumberCount: ruleIds.filter((id) => id === 'ai-smell/magic-numbers').length,
    hasDeadCode: ruleIds.includes('ai-smell/dead-code-blocks'),
    hasMixedAsync: ruleIds.includes('ai-smell/mixed-async-patterns'),
    genericVarRatio: identifiers.size > 0 ? genericCount / Math.max(identifiers.size, 10) : 0,
    hasHardcodedSecrets: ruleIds.includes('security/hardcoded-secrets'),
  };
}

const rule: Rule = {
  id: 'ai-smell/ai-confidence-scorer',
  name: 'AI Confidence Scorer',
  category: 'ai-smell',
  severity: 'info',
  description: 'Calculates an AI-Smell Score (0-100) per file based on the density and severity of AI-specific patterns',
  why: 'AI-generated code has recognizable fingerprints. A high AI-smell score indicates the code was likely written by an AI without careful review.',
  fix: 'Review code with high AI-smell scores carefully. Refactor to remove AI-specific patterns before production.',

  check(_ast: ParsedAST, _source: string, _filePath: string): Finding[] {
    return [];
  },
};

export function computeAiScore(findings: Finding[]): number {
  const factors = extractFactors(findings);
  return calculateScore(factors);
}

export function getScoreLabel(score: number): string {
  return scoreLabel(score);
}

export function getScoreEmoji(score: number): string {
  return scoreEmoji(score);
}

export default rule;
