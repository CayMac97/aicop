import { Rule } from './types.js';

import hardcodedSecrets from './security/hardcoded-secrets.js';
import sqlInjection from './security/sql-injection.js';
import xssVulnerabilities from './security/xss-vulnerabilities.js';
import evalUsage from './security/eval-usage.js';
import weakCrypto from './security/weak-crypto.js';
import jwtNoExpiry from './security/jwt-no-expiry.js';
import jwtUnsafeVerify from './security/jwt-unsafe-verify.js';
import missingRateLimit from './security/missing-rate-limit.js';
import pathTraversal from './security/path-traversal.js';
import ssrfRisk from './security/ssrf-risk.js';
import corsMisconfiguration from './security/cors-misconfiguration.js';
import prototypePollution from './security/prototype-pollution.js';
import regexDos from './security/regex-dos.js';
import commandInjection from './security/command-injection.js';
import codeInjection from './security/code-injection.js';
import openRedirect from './security/open-redirect.js';
import insecureDeserialization from './security/insecure-deserialization.js';
import xxeInjection from './security/xxe-injection.js';
import nosqlInjection from './security/nosql-injection.js';
import csrfMissing from './security/csrf-missing.js';
import insecureSession from './security/insecure-session.js';
import promptInjection from './security/prompt-injection.js';
import unsafeShellExecs from './security/unsafe-shell-execs.js';

import deadCodeBlocks from './ai-smells/dead-code-blocks.js';
import inconsistentErrorHandling from './ai-smells/inconsistent-error-handling.js';
import todoStubFunctions from './ai-smells/todo-stub-functions.js';
import hallucinatedApiCalls from './ai-smells/hallucinated-api-calls.js';
import copyPastePatterns from './ai-smells/copy-paste-patterns.js';
import missingNullChecks from './ai-smells/missing-null-checks.js';
import debugLeftovers from './ai-smells/debug-leftovers.js';
import mixedAsyncPatterns from './ai-smells/mixed-async-patterns.js';
import magicNumbers from './ai-smells/magic-numbers.js';
import genericVariableNames from './ai-smells/generic-variable-names.js';
import aiConfidenceScorer from './ai-smells/ai-confidence-scorer.js';

import cyclomaticComplexity from './tech-debt/cyclomatic-complexity.js';
import functionLength from './tech-debt/function-length.js';
import nestingDepth from './tech-debt/nesting-depth.js';
import godFiles from './tech-debt/god-files.js';
import hardcodedConfig from './tech-debt/hardcoded-config.js';
import missingTypes from './tech-debt/missing-types.js';
import godFunctions from './tech-debt/god-functions.js';
import nPlusOneQueries from './tech-debt/n-plus-one-queries.js';

import { nextjsMissingInputValidation } from './security/nextjs-missing-input-validation.js';
import { nextjsClientServerConfusion } from './ai-smells/nextjs-client-server-confusion.js';

const ALL_RULES: Rule[] = [
  hardcodedSecrets,
  sqlInjection,
  xssVulnerabilities,
  evalUsage,
  weakCrypto,
  jwtNoExpiry,
  jwtUnsafeVerify,
  missingRateLimit,
  pathTraversal,
  ssrfRisk,
  corsMisconfiguration,
  prototypePollution,
  regexDos,
  commandInjection,
  codeInjection,
  openRedirect,
  insecureDeserialization,
  xxeInjection,
  nosqlInjection,
  csrfMissing,
  insecureSession,
  promptInjection,
  deadCodeBlocks,
  inconsistentErrorHandling,
  todoStubFunctions,
  hallucinatedApiCalls,
  copyPastePatterns,
  missingNullChecks,
  debugLeftovers,
  mixedAsyncPatterns,
  magicNumbers,
  genericVariableNames,
  aiConfidenceScorer,
  cyclomaticComplexity,
  functionLength,
  nestingDepth,
  godFiles,
  hardcodedConfig,
  missingTypes,
  godFunctions,
  nPlusOneQueries,
  nextjsMissingInputValidation,
  nextjsClientServerConfusion,
  unsafeShellExecs,
];

const RULE_REGISTRY: Map<string, Rule> = new Map(
  ALL_RULES.map((rule) => [rule.id, rule]),
);

export function getAllRules(): Rule[] {
  return ALL_RULES;
}

export function getRuleById(id: string): Rule | undefined {
  return RULE_REGISTRY.get(id);
}

export function getRulesByCategory(category: Rule['category']): Rule[] {
  return ALL_RULES.filter((r) => r.category === category);
}

export function getRuleCount(): number {
  return ALL_RULES.length;
}
