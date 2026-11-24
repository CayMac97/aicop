import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk, getSkipRanges } from '../scanner/ast-walker.js';
import { ParsedAST } from '../scanner/rules/types.js';
import { isIdentifier, isMemberExpression } from './ast-helpers.js';
import { crossFileCache } from '../scanner/cross-file/cross-file-resolver.js';

export interface TaintResult {
  globalTaints: Set<string>;
  localTaints: Map<TSESTree.Node, Set<string>>;
  sanitizedExpressions: Set<string>;
}

function extractParamNames(param: TSESTree.Node): string[] {
  const names: string[] = [];
  if (param.type === 'Identifier') {
    names.push((param as TSESTree.Identifier).name);
  } else if (param.type === 'ObjectPattern') {
    for (const prop of (param as TSESTree.ObjectPattern).properties) {
      if (prop.type === 'Property') {
        names.push(...extractParamNames(prop.value));
      } else if (prop.type === 'RestElement') {
        names.push(...extractParamNames(prop.argument));
      }
    }
  } else if (param.type === 'ArrayPattern') {
    for (const element of (param as TSESTree.ArrayPattern).elements) {
      if (element) {
        names.push(...extractParamNames(element));
      }
    }
  } else if (param.type === 'AssignmentPattern') {
    names.push(...extractParamNames((param as TSESTree.AssignmentPattern).left));
  } else if (param.type === 'RestElement') {
    names.push(...extractParamNames((param as TSESTree.RestElement).argument));
  }
  return names;
}

function extractPatternIdentifiers(node: TSESTree.Node, taints: Set<string>): void {
  extractParamNames(node).forEach(name => taints.add(name));
}

function unwrapAwait(node: TSESTree.Node): TSESTree.Node {
  if (node.type === 'AwaitExpression') {
    return (node as TSESTree.AwaitExpression).argument;
  }
  return node;
}

export function buildParentMap(ast: ParsedAST | TSESTree.Node): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) {
      if (parent) map.set(node, parent);
    },
  });
  return map;
}

export function isDynamicExpr(n: TSESTree.Expression, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isDirectUserInputExpr(n)) return true;
  if (isNodeContextuallyTainted(n, taintResult, parentMap)) return true;
  if (n.type === 'ArrayExpression') {
    return n.elements.some((e) => e && e.type !== 'SpreadElement' && isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap));
  }
  if (n.type === 'TemplateLiteral') {
    return (n as TSESTree.TemplateLiteral).expressions.some(
      (e) => isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap)
    );
  }
  if (n.type === 'BinaryExpression' && (n as TSESTree.BinaryExpression).operator === '+') {
    const be = n as TSESTree.BinaryExpression;
    return isDynamicExpr(be.left as TSESTree.Expression, taintResult, parentMap) ||
           isDynamicExpr(be.right as TSESTree.Expression, taintResult, parentMap);
  }
  if (n.type === 'LogicalExpression') {
    const le = n as TSESTree.LogicalExpression;
    return isDynamicExpr(le.left as TSESTree.Expression, taintResult, parentMap) ||
           isDynamicExpr(le.right as TSESTree.Expression, taintResult, parentMap);
  }
  if (n.type === 'AwaitExpression') {
    return isDynamicExpr((n as TSESTree.AwaitExpression).argument as TSESTree.Expression, taintResult, parentMap);
  }
  if (n.type === 'CallExpression') {
    const ce = n as TSESTree.CallExpression;
    if (isMemberExpression(ce.callee) && isIdentifier(ce.callee.property)) {
      if (ce.callee.property.name === 'join' && ce.callee.object.type === 'ArrayExpression') {
        return ce.callee.object.elements.some(
          (e) => e && e.type !== 'SpreadElement' && isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap)
        );
      }
      if (isIdentifier(ce.callee.object) && ce.callee.object.name === 'Object' && ce.callee.property.name === 'fromEntries') {
        if (ce.arguments[0]) return isDynamicExpr(ce.arguments[0] as TSESTree.Expression, taintResult, parentMap);
      }
    }
  }
  return false;
}

const REQ_USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies', 'signedCookies', 'files', 'file', 'rawBody']);
const NEST_INPUT_DECORATORS = new Set(['Body', 'Query', 'Param', 'Headers', 'Cookies', 'UploadedFile', 'UploadedFiles', 'Ip', 'Session']);
const REQUEST_ROOT_NAMES = new Set(['req', 'request']);
// Koa: ctx.query / ctx.params / ctx.headers are inputs; ctx.body is the RESPONSE body, so it is not listed.
const KOA_CTX_INPUT_PROPS = new Set(['query', 'params', 'headers', 'querystring']);
const REQUEST_ACCESSOR_METHODS = new Set(['get', 'header', 'param']);

/** Strip wrappers that do not change the value: (x as T), x!, <T>x, x?.y */
function unwrapValueWrappers(node: TSESTree.Node): TSESTree.Node {
  let cur = node;
  for (;;) {
    if (cur.type === 'TSAsExpression' || cur.type === 'TSNonNullExpression' || cur.type === 'TSTypeAssertion' || cur.type === 'TSSatisfiesExpression') {
      cur = (cur as TSESTree.TSAsExpression).expression;
    } else if (cur.type === 'ChainExpression') {
      cur = (cur as TSESTree.ChainExpression).expression;
    } else {
      return cur;
    }
  }
}

/** req.get('x') / req.header('x') / ctx.get('x') / ctx.request.get('x') / ctx.cookies.get('x') */
function isRequestAccessorCall(node: TSESTree.Node): boolean {
  const n = unwrapValueWrappers(node);
  if (n.type !== 'CallExpression' || !isMemberExpression(n.callee) || !isIdentifier(n.callee.property)) return false;
  if (!REQUEST_ACCESSOR_METHODS.has(n.callee.property.name)) return false;
  const obj = unwrapValueWrappers(n.callee.object);
  if (isIdentifier(obj)) return REQUEST_ROOT_NAMES.has(obj.name) || obj.name === 'ctx';
  if (isMemberExpression(obj) && isIdentifier(obj.object) && isIdentifier(obj.property)) {
    if (obj.object.name === 'ctx' && (obj.property.name === 'request' || obj.property.name === 'cookies')) return true;
  }
  return false;
}

export function astToString(node: TSESTree.Node): string | null {
  if (isIdentifier(node)) return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (isMemberExpression(node)) {
    const obj = astToString(node.object);
    let prop = '';
    if (isIdentifier(node.property)) prop = node.property.name;
    else if (node.property.type === 'Literal') prop = String(node.property.value);
    
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

export function isDirectUserInputExpr(rawNode: TSESTree.Node): boolean {
  const node = unwrapValueWrappers(rawNode);
  if (isRequestAccessorCall(node)) return true;
  if (!isMemberExpression(node)) return false;

  let current: TSESTree.Node = node;
  const properties: string[] = [];

  while (true) {
    current = unwrapValueWrappers(current);
    if (!isMemberExpression(current)) break;
    const me = current as TSESTree.MemberExpression;
    if (isIdentifier(me.property)) properties.unshift(me.property.name);
    else if (me.property.type === 'Literal') properties.unshift(String(me.property.value));
    current = me.object;
  }

  if (isIdentifier(current) && properties.length > 0) {
    if (REQUEST_ROOT_NAMES.has(current.name) && REQ_USER_INPUT_PROPS.has(properties[0])) return true;
    if (current.name === 'ctx') {
      if (properties[0] === 'request' && properties.length > 1 && REQ_USER_INPUT_PROPS.has(properties[1])) return true;
      if (KOA_CTX_INPUT_PROPS.has(properties[0])) return true;
    }
  }

  return false;
}

/**
 * Recognises the two common escaping idioms built from chained replace() calls:
 *   html:  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;")
 *   sql identifier quoting:  .replace(/"/g, '""')
 * The chain's outermost replace() is passed in; it is sanitising when the chain escapes < together with a quote.
 */
function escapesForSink(outer: TSESTree.CallExpression): boolean {
  let lt = false, quote = false, sqlDouble = false;
  let cur: TSESTree.Node = outer;
  while (cur.type === 'CallExpression' && isMemberExpression(cur.callee) && isIdentifier(cur.callee.property)
    && (cur.callee.property.name === 'replace' || cur.callee.property.name === 'replaceAll')) {
    const pat = cur.arguments[0], rep = cur.arguments[1];
    const patText = pat && pat.type === 'Literal' ? ((pat as TSESTree.Literal & { regex?: { pattern: string } }).regex?.pattern ?? String(pat.value)) : '';
    const repText = rep && rep.type === 'Literal' && typeof rep.value === 'string' ? rep.value : '';
    if (/^&(lt|#0*60|#x0*3c);$/i.test(repText)) lt = true;
    if (/^&(quot|#0*34|#x0*22|#0*39|#x0*27|apos);$/i.test(repText)) quote = true;
    if ((patText === '"' && repText === '""') || (patText === "'" && repText === "''")) sqlDouble = true;
    cur = cur.callee.object;
  }
  return (lt && quote) || sqlDouble;
}

export function isTaintedExpr(rawNode: TSESTree.Node, tainted: Set<string>, sanitizedExpressions: Set<string>): boolean {
  const node = unwrapValueWrappers(rawNode);
  if (isDirectUserInputExpr(node)) return true;
  if (isTaintedNode(node, tainted)) return true;
  
  const str = astToString(node);
  if (str && sanitizedExpressions.has(str)) return false;

  if (isMemberExpression(node)) {
    let current: TSESTree.Node = node;
    while (isMemberExpression(current)) current = current.object;
    if (isTaintedExpr(current, tainted, sanitizedExpressions)) return true;
  }

  if (node.type === 'ArrayExpression') {
    return node.elements.some(e => e && e.type !== 'SpreadElement' && isTaintedExpr(e, tainted, sanitizedExpressions));
  }
  if (node.type === 'ObjectExpression') {
    // Only accessors are treated as carriers ({ get value() { return input; } }); plain data objects are
    // judged by their consumer, otherwise every `{ a: input }` literal would become a taint source.
    return node.properties.some((p) => {
      if (p.type !== 'Property' || p.kind !== 'get' || p.value.type !== 'FunctionExpression') return false;
      let carries = false;
      walk(p.value.body, {
        ReturnStatement(r) {
          const ret = r as TSESTree.ReturnStatement;
          if (ret.argument && isTaintedExpr(ret.argument, tainted, sanitizedExpressions)) carries = true;
        },
      });
      return carries;
    });
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isTaintedExpr(node.left, tainted, sanitizedExpressions) || isTaintedExpr(node.right, tainted, sanitizedExpressions);
  }
  if (node.type === 'LogicalExpression') {
    return isTaintedExpr(node.left, tainted, sanitizedExpressions) || isTaintedExpr(node.right, tainted, sanitizedExpressions);
  }
  if (node.type === 'AwaitExpression') {
    return isTaintedExpr((node as TSESTree.AwaitExpression).argument, tainted, sanitizedExpressions);
  }
  if (node.type === 'NewExpression') {
    // new URL(input) / new URLSearchParams(input) / new Request(input): the parsed parts (host, path, query) stay attacker-controlled
    if (isIdentifier(node.callee) && ['URL', 'URLSearchParams', 'Request'].includes(node.callee.name)) {
      return node.arguments.some((a) => a.type !== 'SpreadElement' && isTaintedExpr(a, tainted, sanitizedExpressions));
    }
    return false;
  }
  if (node.type === 'ConditionalExpression') {
    // the test does not flow into the value; either branch can.
    // `allowed.includes(x) ? x : 'default'`: the value returned in the consequent was just checked against an allowlist.
    const consequentTainted = isTaintedExpr(node.consequent, tainted, sanitizedExpressions)
      && !testValidates(node.test, identifierNamesIn(node.consequent));
    return consequentTainted || isTaintedExpr(node.alternate, tainted, sanitizedExpressions);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some(expr => isTaintedExpr(expr, tainted, sanitizedExpressions));
  }
  if (node.type === 'CallExpression') {
    const call = node as TSESTree.CallExpression;
    // calling a function value that was built from tainted data (const read = capture(input); read())
    if (isIdentifier(call.callee) && tainted.has(call.callee.name)) return true;
    // util.format('%s', input) / nodeUtil.format(...)
    if (isMemberExpression(call.callee) && isIdentifier(call.callee.object) && /^(node)?util$/i.test(call.callee.object.name)
      && isIdentifier(call.callee.property) && call.callee.property.name === 'format') {
      return call.arguments.some((a) => a.type !== 'SpreadElement' && isTaintedExpr(a, tainted, sanitizedExpressions));
    }
    if (isMemberExpression(call.callee)) {
      const me = call.callee as TSESTree.MemberExpression;
      if (isIdentifier(me.property)) {
        const method = me.property.name;
        const TAINT_PRESERVING_METHODS = new Set(['trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase', 'substring', 'substr', 'slice', 'replace', 'replaceAll', 'concat', 'toString', 'join', 'split', 'map', 'filter', 'reduce', 'flat', 'flatMap', 'normalize', 'padStart', 'padEnd', 'repeat', 'charAt', 'at', 'pop', 'shift']);
        if (isIdentifier(me.object) && (me.object.name === 'path' || me.object.name === 'node:path')) {
          if (method === 'join' || method === 'resolve' || method === 'normalize') {
            return call.arguments.some(arg => isTaintedExpr(arg, tainted, sanitizedExpressions));
          }
        }
        if ((method === 'replace' || method === 'replaceAll') && escapesForSink(call)) return false;
        if (TAINT_PRESERVING_METHODS.has(method)) {
          return isTaintedExpr(me.object, tainted, sanitizedExpressions) || call.arguments.some(arg => isTaintedExpr(arg, tainted, sanitizedExpressions));
        }
        if (isIdentifier(me.object) && me.object.name === 'Object' && method === 'fromEntries') {
          if (call.arguments[0]) return isTaintedExpr(call.arguments[0], tainted, sanitizedExpressions);
        }
      }
    }
    // schema.validate(x) / schema.parse(x) / schema.safeParse(x): the returned value is validated (joi, zod, yup ...)
    if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)
      && ['validate', 'validateSync', 'parse', 'parseAsync', 'safeParse', 'safeParseAsync'].includes(call.callee.property.name)
      && !(isIdentifier(call.callee.object) && ['JSON', 'Date', 'path', 'url', 'qs', 'querystring'].includes(call.callee.object.name))) {
      return false;
    }
    // Number()/parseInt()/parseFloat()/Boolean() only yield numbers/booleans: not injectable, so they are NOT propagated.
    if (isIdentifier(call.callee) && ['String', 'decodeURIComponent', 'decodeURI', 'unescape', 'atob'].includes(call.callee.name)) {
      if (call.arguments[0]) return isTaintedExpr(call.arguments[0], tainted, sanitizedExpressions);
    }
    if (isMemberExpression(call.callee) && isIdentifier(call.callee.object) && isIdentifier(call.callee.property)) {
      const o = call.callee.object.name, m = call.callee.property.name;
      if ((o === 'Buffer' && m === 'from') || (o === 'JSON' && m === 'parse') || (o === 'Array' && m === 'from')) {
        if (call.arguments[0]) return isTaintedExpr(call.arguments[0], tainted, sanitizedExpressions);
      }
    }
  }
  return false;
}

export function buildTaintMap(ast: ParsedAST): { tainted: Set<string>, sanitizedExpressions: Set<string> } {
  const tainted = new Set<string>();
  const sanitizedExpressions = new Set<string>();

  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;

      if (node.id.type === 'Identifier') {
        const name = (node.id as TSESTree.Identifier).name;
        if (isTaintedExpr(node.init, tainted, sanitizedExpressions)) {
          tainted.add(name);
        } else if (node.init.type === 'CallExpression' && isIdentifier(node.init.callee) && node.init.callee.name === 'sanitize') {
          sanitizedExpressions.add(name);
        }
        return;
      }

      if (node.id.type === 'ObjectPattern' && isDirectUserInputExpr(node.init)) {
        const pattern = node.id as TSESTree.ObjectPattern;
        for (const prop of pattern.properties) {
          if (prop.type === 'Property' && isIdentifier(prop.value)) {
            tainted.add((prop.value as TSESTree.Identifier).name);
          } else if (prop.type === 'RestElement') {
            extractParamNames(prop.argument).forEach(name => tainted.add(name));
          }
        }
      }

      if (node.id.type === 'ArrayPattern' && isDirectUserInputExpr(node.init)) {
        extractParamNames(node.id).forEach(name => tainted.add(name));
      }
    },

    ForOfStatement(rawNode) {
      const node = rawNode as TSESTree.ForOfStatement;
      if (!isTaintedExpr(node.right, tainted, sanitizedExpressions)) return;
      if (node.left.type === 'VariableDeclaration') {
        for (const d of node.left.declarations) extractParamNames(d.id).forEach((n) => tainted.add(n));
      } else if (node.left.type === 'Identifier') {
        tainted.add(node.left.name);
      }
    },

    CallExpression(rawNode) {
      // parts.push(tainted) / set.add(tainted) / list.unshift(tainted): the container becomes tainted
      const node = rawNode as TSESTree.CallExpression;
      if (!isMemberExpression(node.callee) || !isIdentifier(node.callee.property) || !isIdentifier(node.callee.object)) return;
      if (!['push', 'unshift', 'add', 'append'].includes(node.callee.property.name)) return;
      if (node.arguments.some((a) => a.type !== 'SpreadElement' && isTaintedExpr(a, tainted, sanitizedExpressions))) {
        tainted.add(node.callee.object.name);
      }
    },

    // NestJS: handler parameters bound by decorators are request input
    FunctionExpression(rawNode) {
      const node = rawNode as TSESTree.FunctionExpression;
      for (const param of node.params) {
        const decorators = (param as unknown as { decorators?: TSESTree.Decorator[] }).decorators;
        if (!decorators || decorators.length === 0) continue;
        const isInput = decorators.some((dec) => {
          const e = dec.expression;
          const callee = e.type === 'CallExpression' ? e.callee : e;
          return isIdentifier(callee) && NEST_INPUT_DECORATORS.has(callee.name);
        });
        if (isInput) extractParamNames(param).forEach((n) => tainted.add(n));
      }
    },

    AssignmentExpression(rawNode) {
      const node = rawNode as TSESTree.AssignmentExpression;
      if (node.left.type === 'Identifier') {
        const name = (node.left as TSESTree.Identifier).name;
        if (isTaintedExpr(node.right, tainted, sanitizedExpressions)) {
          tainted.add(name);
        } else {
          tainted.delete(name);
        }
      } else if (node.left.type === 'MemberExpression') {
        const me = node.left as TSESTree.MemberExpression;
        if (isIdentifier(me.object)) {
          if (isTaintedExpr(node.right, tainted, sanitizedExpressions)) {
            tainted.add((me.object as TSESTree.Identifier).name);
          }
        }
      }
    }
  });

  return { tainted, sanitizedExpressions };
}

export function isTaintedNode(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return isTaintedNode((node as TSESTree.TSAsExpression | TSESTree.TSNonNullExpression).expression, tainted);
  }
  return isIdentifier(node) && tainted.has((node as TSESTree.Identifier).name);
}

export function isArgTainted(node: TSESTree.Node, tainted: Set<string>, sanitized: Set<string>): boolean {
  if (isTaintedNode(node, tainted) || isTaintedExpr(node, tainted, sanitized)) return true;
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(p => {
      if (p.type === 'Property') return isArgTainted(p.value, tainted, sanitized);
      if (p.type === 'SpreadElement') return isArgTainted(p.argument, tainted, sanitized);
      return false;
    });
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(e => e && isArgTainted(e, tainted, sanitized));
  }
  return false;
}

// ---------------------------------------------------------------------------
// Validation-guard recognition
// ---------------------------------------------------------------------------

// Root objects that stand for "the whole request/response"; comparing a different property of them
// (req.files.x.mimetype == 'text/xml') must never count as validating another property (req.files.x.data).
const GUARD_ROOT_IDENTIFIERS = new Set([...REQUEST_ROOT_NAMES, 'ctx', 'res', 'response', 'process']);

/**
 * Tokens that identify the VALUES an expression is built from: local variable names plus the full
 * (outermost) member chains such as "#req.query.id". Request roots alone are not tokens.
 */
function identifierNamesIn(expr: TSESTree.Node): Set<string> {
  const out = new Set<string>();
  walk(expr, {
    Identifier(n, parent) {
      const id = n as TSESTree.Identifier;
      if (parent && parent.type === 'MemberExpression' && parent.property === id && !parent.computed) return;
      if (parent && parent.type === 'Property' && parent.key === id && !parent.computed && !parent.shorthand) return;
      if (GUARD_ROOT_IDENTIFIERS.has(id.name)) return;
      out.add(id.name);
    },
    MemberExpression(n, parent) {
      if (parent && parent.type === 'MemberExpression' && parent.object === n) return; // only the outermost chain
      const key = astToString(n);
      if (key) out.add('#' + key);
    },
  });
  return out;
}

function isFunctionNode(n: TSESTree.Node): boolean {
  return n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression';
}

/** name -> identifiers its value was computed from (const a = f(b, c)  =>  a -> {b, c}) within one scope */
function collectDerivations(scope: TSESTree.Node): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  const add = (name: string, from: Set<string>) => {
    const cur = map.get(name) ?? new Set<string>();
    from.forEach((f) => cur.add(f));
    map.set(name, cur);
  };
  const body = (scope as TSESTree.FunctionDeclaration).body ?? scope;
  walk(body, {
    VariableDeclarator(n) {
      const d = n as TSESTree.VariableDeclarator;
      if (!d.init) return;
      const from = identifierNamesIn(d.init);
      extractParamNames(d.id).forEach((name) => add(name, from));
    },
    AssignmentExpression(n) {
      const a = n as TSESTree.AssignmentExpression;
      if (a.left.type === 'Identifier') add(a.left.name, identifierNamesIn(a.right));
    },
  });
  return map;
}

function isAnchoredRegexLiteral(n: TSESTree.Node): boolean {
  if (n.type !== 'Literal') return false;
  const re = (n as TSESTree.Literal & { regex?: { pattern: string } }).regex;
  return !!re && re.pattern.startsWith('^') && re.pattern.endsWith('$');
}

const VALIDATOR_NAME = /^(is|validate|check|verify|assert|ensure)[A-Z_]?/;

/** Does `test` contain an allowlist-style check on one of the identifiers in `closure`? */
function testValidates(test: TSESTree.Node, closure: Set<string>): boolean {
  let found = false;
  const touches = (n: TSESTree.Node | undefined): boolean => {
    if (!n) return false;
    for (const id of identifierNamesIn(n)) if (closure.has(id)) return true;
    return false;
  };
  walk(test, {
    CallExpression(n) {
      if (found) return;
      const call = n as TSESTree.CallExpression;
      const arg0 = call.arguments[0];
      if (isMemberExpression(call.callee) && isIdentifier(call.callee.property)) {
        const m = call.callee.property.name;
        const recv = call.callee.object;
        if ((m === 'has' || m === 'includes' || m === 'indexOf') && arg0 && touches(arg0) && !touches(recv)) { found = true; return; }
        if (m === 'test' && arg0 && touches(arg0) && isAnchoredRegexLiteral(recv)) { found = true; return; }
        if (VALIDATOR_NAME.test(m) && call.arguments.some((a) => touches(a))) { found = true; return; }
      } else if (isIdentifier(call.callee)) {
        if (VALIDATOR_NAME.test(call.callee.name) && call.arguments.some((a) => touches(a))) { found = true; return; }
      }
    },
    BinaryExpression(n) {
      if (found) return;
      const b = n as TSESTree.BinaryExpression;
      if (!['===', '==', '!==', '!='].includes(b.operator)) return;
      const lit = (x: TSESTree.Node) => x.type === 'Literal' && typeof (x as TSESTree.Literal).value === 'string';
      if ((lit(b.left) && touches(b.right)) || (lit(b.right) && touches(b.left))) found = true;
    },
  });
  return found;
}

function exitsEarly(n: TSESTree.Node): boolean {
  let exits = false;
  walk(n, {
    ReturnStatement() { exits = true; },
    ThrowStatement() { exits = true; },
    ContinueStatement() { exits = true; },
  });
  return exits;
}

/**
 * True when the value used at `node` was validated before use:
 *   if (!allowed.has(x)) return ...;  use(x)          (early-exit guard)
 *   if (/^[a-z]+$/.test(x)) { use(x) }                (use inside the guarded branch)
 * x may be connected to the sink argument through assignment chains (const p = x).
 */
export function isValidatedByGuard(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  const sinkIds = identifierNamesIn(node);
  if (sinkIds.size === 0) return false;

  let scope: TSESTree.Node | undefined = parentMap.get(node);
  while (scope && !isFunctionNode(scope) && scope.type !== 'Program') scope = parentMap.get(scope);
  if (!scope) return false;

  const deriv = collectDerivations(scope);
  // Names connected to the sink argument through assignment chains, in BOTH directions:
  //   backwards: const p = x; use(p)          -> checking x validates p
  //   forwards:  const host = new URL(x).host -> checking host validates x
  const closure = new Set<string>(sinkIds);
  let grew = true;
  while (grew) {
    grew = false;
    for (const [name, from] of deriv) {
      const nameIn = closure.has(name);
      const fromIn = [...from].some((f) => closure.has(f));
      if (nameIn && !fromIn) {
        for (const f of from) if (!closure.has(f)) { closure.add(f); grew = true; } // only "grew" if something was added
      } else if (fromIn && !nameIn) {
        closure.add(name);
        grew = true;
      }
    }
  }

  let child: TSESTree.Node = node;
  let cur: TSESTree.Node | undefined = parentMap.get(node);
  while (cur) {
    if (cur.type === 'IfStatement' && child === cur.consequent && testValidates(cur.test, closure)) return true;
    if (cur.type === 'ConditionalExpression' && child === cur.consequent && testValidates(cur.test, closure)) return true;
    if (cur.type === 'LogicalExpression' && cur.operator === '&&' && child === cur.right && testValidates(cur.left, closure)) return true;
    if (cur.type === 'BlockStatement' || cur.type === 'Program') {
      const body = cur.body as TSESTree.Node[];
      const idx = body.indexOf(child);
      for (let i = 0; i < idx; i++) {
        const stmt = body[i];
        if (stmt.type === 'IfStatement' && testValidates(stmt.test, closure) && exitsEarly(stmt.consequent)) return true;
      }
    }
    if (isFunctionNode(cur)) break;
    child = cur;
    cur = parentMap.get(cur);
  }
  return false;
}

/**
 * True when the expression can only evaluate to a constant, a number or a boolean:
 * literals, parseInt()/parseFloat()/Number()/Boolean()/Math.*, arithmetic, ternaries of such values,
 * and local identifiers initialised with such a value. Such values cannot carry an injection payload.
 */
export function isStaticSafeValue(
  rawNode: TSESTree.Node,
  parentMap: Map<TSESTree.Node, TSESTree.Node>,
  seen: Set<string> = new Set(),
): boolean {
  const node = unwrapValueWrappers(rawNode);
  switch (node.type) {
    case 'Literal':
      return true;
    case 'TemplateLiteral':
      return node.expressions.every((e) => isStaticSafeValue(e, parentMap, seen));
    case 'UnaryExpression':
      return true; // -x, +x, !x, typeof x, void x, delete x: always number / boolean / fixed string
    case 'BinaryExpression':
      if (['-', '*', '/', '%', '**', '<', '>', '<=', '>=', '===', '!==', '==', '!=', '<<', '>>', '>>>', '&', '|', '^'].includes(node.operator)) return true;
      return isStaticSafeValue(node.left, parentMap, seen) && isStaticSafeValue(node.right, parentMap, seen);
    case 'ConditionalExpression':
      return isStaticSafeValue(node.consequent, parentMap, seen) && isStaticSafeValue(node.alternate, parentMap, seen);
    case 'CallExpression': {
      const callee = node.callee;
      if (isIdentifier(callee) && ['parseInt', 'parseFloat', 'Number', 'Boolean'].includes(callee.name)) return true;
      if (isMemberExpression(callee) && isIdentifier(callee.object) && callee.object.name === 'Math') return true;
      return false;
    }
    case 'Identifier': {
      if (seen.has(node.name)) return false;
      seen.add(node.name);
      let scope: TSESTree.Node | undefined = parentMap.get(node);
      while (scope && !isFunctionNode(scope) && scope.type !== 'Program') scope = parentMap.get(scope);
      if (!scope) return false;
      let result: boolean | null = null; // null: no declaration seen
      const body = (scope as TSESTree.FunctionDeclaration).body ?? scope;
      walk(body, {
        VariableDeclarator(n) {
          const d = n as TSESTree.VariableDeclarator;
          if (d.id.type === 'Identifier' && d.id.name === node.name && d.init) {
            const safe = isStaticSafeValue(d.init, parentMap, new Set(seen));
            result = result === null ? safe : result && safe;
          }
        },
        AssignmentExpression(n) {
          const a = n as TSESTree.AssignmentExpression;
          if (a.left.type === 'Identifier' && a.left.name === node.name) {
            const safe = isStaticSafeValue(a.right, parentMap, new Set(seen));
            result = result === null ? safe : result && safe;
          }
        },
      });
      return result === true;
    }
    default:
      return false;
  }
}

export function isNodeContextuallyTainted(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  // A tainted value that was checked against an allowlist before use is no longer attacker-controlled.
  return isNodeRawTainted(node, taintResult, parentMap) && !isValidatedByGuard(node, parentMap);
}

/** Tainted by data flow alone, ignoring validation guards (use isNodeContextuallyTainted for findings). */
export function isNodeRawTainted(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  if (isTaintedExpr(node, taintResult.globalTaints, taintResult.sanitizedExpressions)) return true;
  let current: TSESTree.Node | undefined = parentMap.get(node);
  while (current) {
    if (current.type === 'FunctionDeclaration' || current.type === 'ArrowFunctionExpression' || current.type === 'FunctionExpression') {
      const localTaints = taintResult.localTaints.get(current);
      if (localTaints && isTaintedExpr(node, localTaints, taintResult.sanitizedExpressions)) return true;
    }
    current = parentMap.get(current);
  }
  return false;
}

/** Tainted AND checked against an allowlist before use: provably neutralised, as opposed to merely unproven. */
export function isNodeValidatedTaint(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  return isNodeRawTainted(node, taintResult, parentMap) && isValidatedByGuard(node, parentMap);
}

/**
 * Tainted via variables OR used straight from the request (req.query.x), unless the very same value was
 * validated before use. Rules should prefer this over `isDirectUserInputExpr(x)` on its own.
 */
export function isUserControlledExpr(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  return isDirectUserInputExpr(node) && !isValidatedByGuard(node, parentMap);
}

export function isArgContextuallyTainted(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) {
    return true;
  }
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(p => {
      if (p.type === 'Property') return isArgContextuallyTainted(p.value, taintResult, parentMap);
      if (p.type === 'SpreadElement') return isArgContextuallyTainted(p.argument, taintResult, parentMap);
      return false;
    });
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(e => e && isArgContextuallyTainted(e, taintResult, parentMap));
  }
  return false;
}

interface TaintCacheEntry {
  skipRanges: [number, number][];
  result: TaintResult;
}

// ~25 rules ask for the taint map of the same AST; computing it once per AST is a large speedup.
const taintCache = new WeakMap<object, TaintCacheEntry>();

/**
 * Memoized per AST. Callers get their own copies of the mutable collections
 * (some rules, e.g. prompt-injection, delete entries from globalTaints).
 * The cache is invalidated when the walker's global skip ranges changed.
 */
export function buildContextualTaintMap(ast: ParsedAST, filePath: string): TaintResult {
  const skipRanges = getSkipRanges();
  let entry = taintCache.get(ast);
  if (!entry || entry.skipRanges !== skipRanges) {
    entry = { skipRanges, result: computeContextualTaintMap(ast, filePath) };
    taintCache.set(ast, entry);
  }
  const r = entry.result;
  return {
    globalTaints: new Set(r.globalTaints),
    localTaints: new Map(r.localTaints),
    sanitizedExpressions: new Set(r.sanitizedExpressions),
  };
}

function computeContextualTaintMap(ast: ParsedAST, _filePath: string): TaintResult {
  const { tainted: globalTaints, sanitizedExpressions } = buildTaintMap(ast);
  const localTaints = new Map<TSESTree.Node, Set<string>>();
  
  const parentMap = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) { if (parent) parentMap.set(node, parent); }
  });

  const namespaceImports = new Map<string, string>();
  const localFunctions = new Map<string, TSESTree.Node>();
  
  let functionCount = 0;

  walk(ast, {
    ImportDeclaration(rawNode) {
      const node = rawNode as TSESTree.ImportDeclaration;
      if (node.source.type !== 'Literal' || typeof node.source.value !== 'string') return;
      const source = node.source.value;
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportNamespaceSpecifier') {
          namespaceImports.set(spec.local.name, source);
        }
      }
    },
    FunctionDeclaration(rawNode) {
      functionCount++;
      const node = rawNode as TSESTree.FunctionDeclaration;
      if (node.id) localFunctions.set(node.id.name, node);
    },
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (node.id.type === 'Identifier' && node.init && (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression')) {
        functionCount++;
        localFunctions.set(node.id.name, node.init);
      }
    }
  });

  if (functionCount > 500) return { globalTaints, localTaints, sanitizedExpressions };

  for (const funcNode of localFunctions.values()) {
    localTaints.set(funcNode, new Set<string>());
  }

  const isCurrentlyTainted = (node: TSESTree.Node, funcContext?: TSESTree.Node): boolean => {
    if (isTaintedExpr(node, globalTaints, sanitizedExpressions)) return true;
    let curr = funcContext || parentMap.get(node);
    let isTainted = false;
    while (curr) {
      if (curr.type === 'FunctionDeclaration' || curr.type === 'ArrowFunctionExpression' || curr.type === 'FunctionExpression') {
        const lt = localTaints.get(curr);
        if (lt && isTaintedExpr(node, lt, sanitizedExpressions)) {
          isTainted = true;
          break;
        }
      }
      curr = parentMap.get(curr);
    }
    if (isTainted) return true;

    if (node.type === 'ObjectExpression') {
      return (node as TSESTree.ObjectExpression).properties.some(p => {
        if (p.type === 'Property') return isCurrentlyTainted(p.value, funcContext);
        if (p.type === 'SpreadElement') return isCurrentlyTainted(p.argument, funcContext);
        return false;
      });
    }
    if (node.type === 'ArrayExpression') {
      return (node as TSESTree.ArrayExpression).elements.some(e => e && isCurrentlyTainted(e, funcContext));
    }

    return false;
  };

  let changed = true;
  while (changed) {
    changed = false;
    
    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        let funcName: string | null = null;
        if (node.callee.type === 'Identifier') {
          funcName = node.callee.name;
        } else if (node.callee.type === 'MemberExpression') {
          const me = node.callee as TSESTree.MemberExpression;
          if (isIdentifier(me.object) && isIdentifier(me.property)) {
            const nsName = me.object.name;
            if (namespaceImports.has(nsName)) funcName = `${nsName}.${me.property.name}`;
          }
        }
        
        if (!funcName) return;
        
        const targetNode = localFunctions.get(funcName);
        if (!targetNode) return;
        
        node.arguments.forEach((arg, index) => {
          if (isCurrentlyTainted(arg)) {
            // @ts-expect-error params exist
            const params = targetNode.params || [];
            const param = params[index];
            if (!param) return;
            
            const lt = localTaints.get(targetNode)!;
            const beforeSize = lt.size;
            extractPatternIdentifiers(param, lt);
            if (lt.size > beforeSize) changed = true;
          }
        });
      }
    });

    for (const [funcNode, lt] of localTaints.entries()) {
      const beforeSize = lt.size;
      // @ts-expect-error body exists
      walk(funcNode.body, {
        VariableDeclarator(vNode) {
          const vd = vNode as TSESTree.VariableDeclarator;
          if (!vd.init) return;
          if (isCurrentlyTainted(vd.init, funcNode)) {
            if (vd.id.type === 'Identifier') {
              lt.add(vd.id.name);
            } else if (vd.id.type === 'ObjectPattern' || vd.id.type === 'ArrayPattern') {
              extractPatternIdentifiers(vd.id, lt);
            }
          }
        },
        AssignmentExpression(aNode) {
          const ae = aNode as TSESTree.AssignmentExpression;
          if (ae.left.type === 'Identifier') {
            if (isCurrentlyTainted(ae.right, funcNode)) {
              lt.add(ae.left.name);
            } else if (lt.has(ae.left.name)) {
              lt.delete(ae.left.name);
            }
          } else if (ae.left.type === 'MemberExpression') {
            const str = astToString(ae.left);
            if (str) {
              if (isCurrentlyTainted(ae.right, funcNode)) {
                if (str.startsWith('this.')) {
                  if (!globalTaints.has(str)) {
                    globalTaints.add(str);
                    changed = true;
                  }
                } else {
                  lt.add(str);
                }
              } else if (lt.has(str)) {
                lt.delete(str);
              }
            }
          }
        },
        CallExpression(cNode) {
          const call = cNode as TSESTree.CallExpression;
          if (isMemberExpression(call.callee) && isIdentifier(call.callee.object) && call.callee.object.name === 'Object') {
            if (isIdentifier(call.callee.property) && call.callee.property.name === 'assign') {
              if (call.arguments.length >= 2) {
                const firstArg = call.arguments[0];
                const sources = call.arguments.slice(1);
                if (isIdentifier(firstArg) && sources.some(s => isCurrentlyTainted(s, funcNode))) {
                  lt.add(firstArg.name);
                } else if (firstArg.type === 'MemberExpression') {
                  const str = astToString(firstArg);
                  if (str && sources.some(s => isCurrentlyTainted(s, funcNode))) {
                    lt.add(str);
                  }
                }
              }
            }
          }
        }
      });
      if (lt.size > beforeSize) changed = true;
    }

    const taintsReturn = new Set<string>();
    // Values a function can return: `return x`, an expression body (v => String(v).trim()),
    // and, for factories, whatever the returned inner function returns (v => () => v.trim()).
    const returnedExpressions = (fn: TSESTree.Node, depth = 0): TSESTree.Node[] => {
      const out: TSESTree.Node[] = [];
      const body = (fn as TSESTree.ArrowFunctionExpression).body;
      if (!body) return out;
      const consider = (e: TSESTree.Node | null | undefined) => {
        if (!e) return;
        if ((e.type === 'ArrowFunctionExpression' || e.type === 'FunctionExpression') && depth < 3) {
          out.push(...returnedExpressions(e, depth + 1));
        } else {
          out.push(e);
        }
      };
      if (body.type !== 'BlockStatement') {
        consider(body);
      } else {
        walk(body, {
          ReturnStatement(rNode) {
            const ret = rNode as TSESTree.ReturnStatement;
            // returns inside nested functions (callbacks) belong to those functions, not to `fn`
            let owner: TSESTree.Node | undefined = parentMap.get(rNode);
            while (owner && !isFunctionNode(owner)) owner = parentMap.get(owner);
            if (owner === fn) consider(ret.argument);
          },
        });
      }
      return out;
    };
    for (const [funcName, funcNode] of localFunctions.entries()) {
      let returnsTaint = returnedExpressions(funcNode).some((e) => isCurrentlyTainted(e, funcNode));
      if (!returnsTaint) {
        // @ts-expect-error body exists
        walk(funcNode.body, {
          CallExpression(cNode) {
            const call = cNode as TSESTree.CallExpression;
            if (isIdentifier(call.callee) && (call.callee.name === 'resolve' || call.callee.name === 'next')) {
              if (call.arguments[0] && isCurrentlyTainted(call.arguments[0], funcNode)) {
                returnsTaint = true;
              }
            }
          }
        });
      }
      if (returnsTaint) taintsReturn.add(funcName);
    }

    if (taintsReturn.size > 0) {
      walk(ast, {
        VariableDeclarator(rawNode) {
          const node = rawNode as TSESTree.VariableDeclarator;
          if (!node.init || node.id.type !== 'Identifier') return;
          const unwrapped = unwrapAwait(node.init);
          if (unwrapped.type === 'CallExpression' && isIdentifier(unwrapped.callee) && taintsReturn.has(unwrapped.callee.name)) {
            if (!globalTaints.has(node.id.name)) {
              globalTaints.add(node.id.name);
              changed = true;
            }
          }
        },
        AssignmentExpression(rawNode) {
          const node = rawNode as TSESTree.AssignmentExpression;
          if (node.left.type === 'Identifier') {
            const unwrapped = unwrapAwait(node.right);
            if (unwrapped.type === 'CallExpression' && isIdentifier(unwrapped.callee) && taintsReturn.has(unwrapped.callee.name)) {
              if (!globalTaints.has(node.left.name)) {
                globalTaints.add(node.left.name);
                changed = true;
              }
            }
          }
        }
      });
    }
  }

  return { globalTaints, localTaints, sanitizedExpressions };
}

export function buildExtendedTaintMap(ast: ParsedAST, filePath: string): Set<string> {
  return buildContextualTaintMap(ast, filePath).globalTaints;
}

export interface CrossFileCall {
  externalFilePath: string;
  externalNode: TSESTree.Node;
  taintedParams: Set<string>;
  callNode: TSESTree.CallExpression;
  awaitNode?: TSESTree.AwaitExpression;
}

export function getCrossFileTaints(ast: ParsedAST, filePath: string, taintResult: TaintResult): CrossFileCall[] {

  const crossFileCalls: CrossFileCall[] = [];
  
  const imports = new Map<string, { source: string; name: string }>();
  const namespaceImports = new Map<string, string>();
  walk(ast, {
    ImportDeclaration(rawNode) {
      const node = rawNode as TSESTree.ImportDeclaration;
      if (node.source.type !== 'Literal' || typeof node.source.value !== 'string') return;
      const source = node.source.value;
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportSpecifier') {
          imports.set(spec.local.name, { source, name: spec.imported.name });
        } else if (spec.type === 'ImportDefaultSpecifier') {
          imports.set(spec.local.name, { source, name: 'default' });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          namespaceImports.set(spec.local.name, source);
        }
      }
    }
  });

  // instanceName -> className. Independent of any single call, so compute it once
  // (it used to be recomputed by walking the whole AST for every call expression: O(calls * nodes)).
  const instantiatedClasses = new Map<string, string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const vNode = rawNode as TSESTree.VariableDeclarator;
      if (vNode.id.type === 'Identifier' && vNode.init && vNode.init.type === 'NewExpression') {
        const newExpr = vNode.init as TSESTree.NewExpression;
        if (newExpr.callee.type === 'Identifier') {
          instantiatedClasses.set(vNode.id.name, newExpr.callee.name);
        }
      }
    }
  });

  walk(ast, {
    CallExpression(rawNode, parentNode) {
      const node = rawNode as TSESTree.CallExpression;
      let importInfo: { source: string; name: string } | undefined;
      
      if (node.callee.type === 'Identifier') {
        const funcName = (node.callee as TSESTree.Identifier).name;
        importInfo = imports.get(funcName);
      } else if (node.callee.type === 'MemberExpression') {
        const me = node.callee as TSESTree.MemberExpression;
        if (isIdentifier(me.object) && isIdentifier(me.property)) {
          const nsName = (me.object as TSESTree.Identifier).name;
          if (namespaceImports.has(nsName)) {
            importInfo = { source: namespaceImports.get(nsName)!, name: (me.property as TSESTree.Identifier).name };
          }
        }
      }

      if (!importInfo && node.callee.type === 'MemberExpression') {
        const me = node.callee as TSESTree.MemberExpression;
        if (isIdentifier(me.object) && isIdentifier(me.property)) {
          const instanceName = me.object.name;
          if (instantiatedClasses.has(instanceName)) {
            const className = instantiatedClasses.get(instanceName)!;
            const classImport = imports.get(className);
            if (classImport) {
              importInfo = { source: classImport.source, name: className };
              // We will need to look for the method me.property.name inside this class
              (node as any)._methodName = me.property.name;
            }
          }
        }
      }

      if (!importInfo) return;

      const taintedArgIndices = new Set<number>();
      node.arguments.forEach((arg, index) => {
        if (isArgTainted(arg, taintResult.globalTaints, taintResult.sanitizedExpressions)) {
          taintedArgIndices.add(index);
        }
      });

      if (taintedArgIndices.size === 0) return;

      const externalInfo = crossFileCache.getExportInfo(importInfo.source, filePath, importInfo.name);
      if (!externalInfo) return;
      const externalNode = externalInfo.node;
      const externalFilePath = externalInfo.filePath;

      let targetNode = externalNode;
      if ((node as any)._methodName) {
        const methodName = (node as any)._methodName;
        let foundMethod: TSESTree.Node | null = null;
        
        if (targetNode.type === 'ClassDeclaration' || targetNode.type === 'ClassExpression') {
          for (const member of targetNode.body.body) {
            if (member.type === 'MethodDefinition' && isIdentifier(member.key) && member.key.name === methodName) {
              foundMethod = member.value;
              break;
            }
          }
        } else if (targetNode.type === 'FunctionDeclaration' || targetNode.type === 'FunctionExpression' || targetNode.type === 'ArrowFunctionExpression') {
          walk(targetNode.body, {
            AssignmentExpression(aNode) {
              const ae = aNode as TSESTree.AssignmentExpression;
              if (ae.left.type === 'MemberExpression') {
                const me = ae.left;
                if (me.object.type === 'ThisExpression' && isIdentifier(me.property) && me.property.name === methodName) {
                  if (ae.right.type === 'FunctionExpression' || ae.right.type === 'ArrowFunctionExpression') {
                    foundMethod = ae.right;
                  }
                }
              }
            }
          });
        }
        
        if (foundMethod) targetNode = foundMethod;
        else return; // method not found, assume safe or dynamic
      }

      if (targetNode.type !== 'FunctionDeclaration' && targetNode.type !== 'ArrowFunctionExpression' && targetNode.type !== 'FunctionExpression') return;
      
      const taintedParams = new Set<string>();
      const params = targetNode.params || [];
      params.forEach((param: TSESTree.Node, index: number) => {
        if (taintedArgIndices.has(index)) {
          extractParamNames(param).forEach((name: string) => taintedParams.add(name));
        }
      });

      if (taintedParams.size > 0) {
        let awaitNode: TSESTree.AwaitExpression | undefined;
        if (parentNode && parentNode.type === 'AwaitExpression') {
          awaitNode = parentNode as TSESTree.AwaitExpression;
        }
        crossFileCalls.push({ externalFilePath, externalNode: targetNode, taintedParams, callNode: node, awaitNode });
      }
    }
  });

  return crossFileCalls;
}
