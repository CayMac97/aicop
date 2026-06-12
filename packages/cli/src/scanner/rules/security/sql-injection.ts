import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, readFileContent } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isMemberExpression, isIdentifier } from '../../../utils/ast-helpers.js';
import { buildTaintMap, buildContextualTaintMap, getCrossFileTaints, TaintResult, isNodeContextuallyTainted, isDynamicExpr, buildParentMap } from '../../../utils/taint-tracker.js';
import { crossFileCache } from '../../cross-file/cross-file-resolver.js';

const SQL_VERB_PATTERN = /\b(SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|EXEC(?:UTE)?)\b/i;
const HTML_TAG_PATTERN = /<(?:select|table|input|form|option|textarea)\b/i;
const USER_INPUT_SOURCES = new Set(['params', 'body', 'query', 'headers', 'cookies']);
const PARAMETERIZED_PATTERN = /\?\s*[,)]/;

const DB_CALL_METHODS = new Set(['query', 'execute', 'raw', 'prepare', 'run', 'all', 'get', 'any', 'one', 'none', 'many', 'manyOrNone', 'oneOrNone', 'result']);
const SAFE_SINK_METHODS = new Set(['log', 'warn', 'error', 'info', 'debug', 'send', 'json', 'render', 'write', 'end', 'format', 'trace', 'dir', 'table', 'print']);
const SAFE_SINK_ROOTS = new Set(['console', 'logger', 'log', 'res', 'response', 'winston', 'pino', 'bunyan']);

function isExpressionNode(node: TSESTree.Expression | TSESTree.PrivateIdentifier): node is TSESTree.Expression {
  return node.type !== 'PrivateIdentifier';
}

function isUserInputExpression(node: TSESTree.Expression): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (!isMemberExpression(me.object)) return false;
  const parent = me.object as TSESTree.MemberExpression;
  if (!isIdentifier(parent.object)) return false;
  const objName = (parent.object as TSESTree.Identifier).name;
  if (!isIdentifier(parent.property)) return false;
  const propName = (parent.property as TSESTree.Identifier).name;
  return objName === 'req' && USER_INPUT_SOURCES.has(propName);
}

function templateHasUserInput(node: TSESTree.TemplateLiteral, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  return node.expressions.some((expr) => {
    if (isUserInputExpression(expr)) return true;
    if (isIdentifier(expr) && isNodeContextuallyTainted(expr, taintResult, parentMap)) return true;
    return false;
  });
}

function concatHasUserInput(node: TSESTree.BinaryExpression, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (node.operator !== '+') return false;
  if (!isExpressionNode(node.left) || !isExpressionNode(node.right)) return false;
  return isDynamicExpr(node.left, taintResult, parentMap) || isDynamicExpr(node.right, taintResult, parentMap);
}

function looksLikeSQL(text: string): boolean {
  if (!SQL_VERB_PATTERN.test(text)) return false;
  if (HTML_TAG_PATTERN.test(text)) return false;
  return true;
}

function extractLiterals(node: TSESTree.Node): string[] {
  if (isStringLiteral(node)) return [String((node as TSESTree.StringLiteral).value)];
  if (node.type === 'TemplateLiteral') return (node as TSESTree.TemplateLiteral).quasis.map(q => q.value.raw);
  if (node.type === 'BinaryExpression' && (node as TSESTree.BinaryExpression).operator === '+') {
    const be = node as TSESTree.BinaryExpression;
    return [...extractLiterals(be.left), ...extractLiterals(be.right)];
  }
  return [];
}

function isDbCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return DB_CALL_METHODS.has((me.property as TSESTree.Identifier).name);
}

function isSafeSinkCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  if (!SAFE_SINK_METHODS.has((me.property as TSESTree.Identifier).name)) return false;
  let obj: TSESTree.Expression | TSESTree.PrivateIdentifier = me.object;
  while (isMemberExpression(obj)) {
    obj = (obj as TSESTree.MemberExpression).object;
  }
  if (!isIdentifier(obj)) return false;
  return SAFE_SINK_ROOTS.has((obj as TSESTree.Identifier).name.toLowerCase());
}

// aicop-ignore tech-debt/cyclomatic-complexity
function findContext(
  sqlNode: TSESTree.Node,
  parentMap: Map<TSESTree.Node, TSESTree.Node>,
): { kind: 'db-call' | 'safe-sink' | 'var'; varName?: string } | null {
  let current = sqlNode;
  let functionBoundaries = 0;
  for (let depth = 0; depth < 25; depth++) {
    const parent = parentMap.get(current);
    if (!parent) return null;

    if (parent.type === 'CallExpression') {
      const call = parent as TSESTree.CallExpression;
      if (isDbCall(call)) return { kind: 'db-call' };
      if (isSafeSinkCall(call)) return { kind: 'safe-sink' };
      return null;
    }

    if (parent.type === 'VariableDeclarator') {
      const decl = parent as TSESTree.VariableDeclarator;
      if (isIdentifier(decl.id)) return { kind: 'var', varName: (decl.id as TSESTree.Identifier).name };
      return null;
    }

    if (parent.type === 'AssignmentExpression') {
      const assign = parent as TSESTree.AssignmentExpression;
      if (isExpressionNode(assign.left) && isIdentifier(assign.left)) {
        return { kind: 'var', varName: (assign.left as TSESTree.Identifier).name };
      }
      return null;
    }

    if (parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression') {
      functionBoundaries++;
      if (functionBoundaries > 2) return null;
    }

    current = parent;
  }
  return null;
}

function collectDbCallVars(ast: TSESTree.Node): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    CallExpression(rawNode) {
      const call = rawNode as TSESTree.CallExpression;
      if (!isDbCall(call) || call.arguments.length === 0) return;
      const firstArg = call.arguments[0];
      if (firstArg && isIdentifier(firstArg)) {
        vars.add((firstArg as TSESTree.Identifier).name);
      }
    },
  });
  return vars;
}

const rule: Rule = {
  id: 'security/sql-injection',
  name: 'SQL Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects SQL queries built via string concatenation or template literals with user input',
  why: 'SQL injection allows attackers to manipulate your database queries, potentially reading all data, bypassing authentication, or destroying the database.',
  fix: 'Always use parameterized queries or a query builder. Never concatenate user input directly into SQL.',
  fixCode: `// Instead of (VULNERABLE):
const query = "SELECT * FROM users WHERE username = '" + username + "'";
db.query(query, callback);

// Use parameterized query (SAFE):
const query = "SELECT * FROM users WHERE username = ?";
db.query(query, [username], (err, results) => {
  if (err) return next(err);
  // handle results
});

// With mysql2/promise:
const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const parentMap = buildParentMap(ast);
    const dbCallVars = collectDbCallVars(ast);
    const taintResult = buildContextualTaintMap(ast, filePath);

    const reportedIntraLocations = new Set<string>();

    function tryFlag(node: TSESTree.Node, message: string, fixMsg: string): void {
      const line = getLine(node);
      const dedupeKey = `${filePath}:${line}`;
      if (reportedIntraLocations.has(dedupeKey)) return;
      
      if (PARAMETERIZED_PATTERN.test(extractSnippet(source, line))) return;
      const ctx = findContext(node, parentMap);
      if (ctx && ctx.kind === 'safe-sink') return;

      reportedIntraLocations.add(dedupeKey);
      findings.push({
        ruleId: 'security/sql-injection',
        severity: 'error',
        message,
        explain: 'SQL string built via concatenation/template — user input reaches query without parameterization',
        confidence: 'HIGH',
        file: filePath,
        line,
        column: getColumn(node),
        snippet: extractSnippet(source, line),
        fix: fixMsg,
      });
    }

    walk(ast, {
      TemplateLiteral(rawNode) {
        const node = rawNode as TSESTree.TemplateLiteral;
        const raw = node.quasis.map((q) => q.value.raw).join('');
        if (!looksLikeSQL(raw) || !templateHasUserInput(node, taintResult, parentMap)) return;
        tryFlag(node, 'SQL template literal with user input — injection risk',
          'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])');
      },
      BinaryExpression(rawNode) {
        const node = rawNode as TSESTree.BinaryExpression;
        if (node.operator !== '+') return;
        const strings = extractLiterals(node);
        if (!strings.some(looksLikeSQL) || !concatHasUserInput(node, taintResult, parentMap)) return;
        tryFlag(node, 'SQL string concat with user input — injection risk',
          'Use parameterized queries or a query builder like Prisma, Knex, or TypeORM');
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (node.operator !== '+=') return;
        if (!isExpressionNode(node.right)) return;
        if (!isDynamicExpr(node.right, taintResult, parentMap)) return;
        
        let reachesDb = false;
        if (isIdentifier(node.left)) {
          reachesDb = dbCallVars.has((node.left as TSESTree.Identifier).name);
        } else {
          // Fallback to original parent walking if it's not a simple variable assignment
          const ctx = findContext(node, parentMap);
          reachesDb = ctx?.kind === 'db-call';
        }
        
        if (reachesDb) {
          tryFlag(node, 'SQL string built via AssignmentExpression (+=) with user input — injection risk',
            'Use parameterized queries or a query builder like Prisma, Knex, or TypeORM');
        }
      },
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        if (isMemberExpression(node.callee) && isIdentifier(node.callee.property)) {
          const methodName = node.callee.property.name;
          if (['where', 'andWhere', 'orWhere', 'having', 'andHaving', 'orHaving'].includes(methodName)) {
            const firstArg = node.arguments[0];
            if (firstArg) {
              if (firstArg.type === 'BinaryExpression' && concatHasUserInput(firstArg as TSESTree.BinaryExpression, taintResult, parentMap)) {
                tryFlag(node, `SQL injection risk in query builder — user input in ${methodName}() string concatenation`, 'Use parameterized conditions: where("user.id = :id", { id: req.query.id })');
              } else if (firstArg.type === 'TemplateLiteral' && templateHasUserInput(firstArg as TSESTree.TemplateLiteral, taintResult, parentMap)) {
                tryFlag(node, `SQL injection risk in query builder — user input in ${methodName}() template literal`, 'Use parameterized conditions: where("user.id = :id", { id: req.query.id })');
              }
            }
          }
          if (methodName === 'join' || methodName === 'concat') {
            const obj = node.callee.object;
            if (obj.type === 'ArrayExpression') {
              let elements = [...(obj as TSESTree.ArrayExpression).elements];
              if (methodName === 'concat') {
                elements.push(...node.arguments);
              }
              const strings = elements.map(e => isStringLiteral(e) ? String((e as TSESTree.StringLiteral).value) : '').filter(Boolean);
              if (strings.some(looksLikeSQL)) {
                if (elements.some(e => e && isDynamicExpr(e as TSESTree.Node, taintResult, parentMap))) {
                  let reachesDb = false;
                  const ctx = findContext(node, parentMap);
                  reachesDb = ctx?.kind === 'db-call';
                  if (ctx?.kind === 'var' && ctx.varName) {
                    reachesDb = dbCallVars.has(ctx.varName);
                  }
                  if (reachesDb) {
                    tryFlag(node, `SQL string built via Array.${methodName}() with user input — injection risk`, 'Use parameterized queries or a query builder like Prisma, Knex, or TypeORM');
                  }
                }
              }
            }
          }
        }
      },
    });

    function tryFlagCrossFile(crossCall: any, externalNode: TSESTree.Node, message: string, fixMsg: string): void {
      const extLine = getLine(externalNode);
      try {
        const extSource = crossFileCache.getFileSource(crossCall.externalFilePath) || readFileContent(crossCall.externalFilePath);
        if (PARAMETERIZED_PATTERN.test(extractSnippet(extSource, extLine))) return;
      } catch { /* ignore */ }

      const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
      const line = getLine(sourceNode);
      findings.push({
        ruleId: 'security/sql-injection',
        severity: 'error',
        message,
        explain: 'SQL string built via concatenation/template in an imported function using tainted arguments',
        confidence: 'HIGH',
        file: filePath,
        line,
        column: getColumn(sourceNode),
        snippet: extractSnippet(source, line),
        fix: fixMsg,
      });
    }

    // Cross-file logic
    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();
    
    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode);
      walk(crossCall.externalNode, {
        TemplateLiteral(rawNode) {
          const node = rawNode as TSESTree.TemplateLiteral;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(rawNode)}:template`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          const raw = node.quasis.map((q) => q.value.raw).join('');
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          if (!looksLikeSQL(raw) || !templateHasUserInput(node, crossTaintResult, extParentMap)) return;
          
          reportedExternalLocations.add(dedupeKey);
          tryFlagCrossFile(crossCall, node, 'Cross-File SQL Injection: User input flows into SQL query in imported function',
            'Parameterize the SQL query inside the imported function');
        },
        BinaryExpression(rawNode) {
          const node = rawNode as TSESTree.BinaryExpression;
          if (node.operator !== '+') return;
          
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(rawNode)}:binary`;
          if (reportedExternalLocations.has(dedupeKey)) return;

          const strings = extractLiterals(node);
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          if (!strings.some(looksLikeSQL) || !concatHasUserInput(node, crossTaintResult, extParentMap)) return;
          
          reportedExternalLocations.add(dedupeKey);
          tryFlagCrossFile(crossCall, node, 'Cross-File SQL Injection: User input concatenated into SQL query in imported function',
            'Parameterize the SQL query inside the imported function');
        },
        AssignmentExpression(rawNode) {
          const node = rawNode as TSESTree.AssignmentExpression;
          if (node.operator !== '+=') return;
          if (!isExpressionNode(node.right)) return;
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
          if (!isDynamicExpr(node.right, crossTaintResult, extParentMap)) return;
          
          let reachesDb = false;
          if (isIdentifier(node.left)) {
            const extDbCallVars = collectDbCallVars(crossCall.externalNode);
            reachesDb = extDbCallVars.has((node.left as TSESTree.Identifier).name);
          } else {
            const ctx = findContext(node, extParentMap);
            reachesDb = ctx?.kind === 'db-call';
          }
          
          if (!reachesDb) return;
          
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(rawNode)}:assign`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          reportedExternalLocations.add(dedupeKey);
          
          tryFlagCrossFile(crossCall, node, 'Cross-File SQL Injection: User input concatenated via += into SQL query in imported function',
            'Parameterize the SQL query inside the imported function');
        },
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          if (isMemberExpression(node.callee) && isIdentifier(node.callee.property)) {
            const methodName = node.callee.property.name;
            if (methodName === 'join' || methodName === 'concat') {
              const obj = node.callee.object;
              if (obj.type === 'ArrayExpression') {
                let elements = [...(obj as TSESTree.ArrayExpression).elements];
                if (methodName === 'concat') {
                  elements.push(...node.arguments);
                }
                const strings = elements.map(e => isStringLiteral(e) ? String((e as TSESTree.StringLiteral).value) : '').filter(Boolean);
                if (strings.some(looksLikeSQL)) {
                  const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map() };
                  if (elements.some(e => e && isDynamicExpr(e as TSESTree.Node, crossTaintResult, extParentMap))) {
                    let reachesDb = false;
                    const ctx = findContext(node, extParentMap);
                    reachesDb = ctx?.kind === 'db-call';
                    if (ctx?.kind === 'var' && ctx.varName) {
                      const extDbCallVars = collectDbCallVars(crossCall.externalNode);
                      reachesDb = extDbCallVars.has(ctx.varName);
                    }
                    if (reachesDb) {
                      const dedupeKey = `${crossCall.externalFilePath}:${getLine(rawNode)}:${methodName}`;
                      if (reportedExternalLocations.has(dedupeKey)) return;
                      reportedExternalLocations.add(dedupeKey);
                      tryFlagCrossFile(crossCall, node, `Cross-File SQL Injection: User input concatenated via Array.${methodName}() into SQL query in imported function`,
                        'Parameterize the SQL query inside the imported function');
                    }
                  }
                }
              }
            }
          }
        },
      });
    }

    return findings;
  },
};

export default rule;
