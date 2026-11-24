import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { TSESTree } from '@typescript-eslint/typescript-estree';
import { buildParentMap } from '../../../utils/taint-tracker.js';
import { HALLUCINATED_API_MAP, HALLUCINATED_CHAIN_MAP } from './hallucinated-apis.data.js';


/**
 * `res` is only the Express response when it is a handler parameter that follows
 * `req`, e.g. (req, res) => ... Otherwise it is just a variable name, such as the
 * result of a custom fetch wrapper (`const res = await shopifyFetch(...)`).
 */
const BUILTIN_CONSTRUCTORS = new Set(['URLSearchParams', 'URL', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Headers', 'FormData', 'Array', 'Object', 'String']);

/**
 * `const params = new URLSearchParams(...)` - the name is bound to a built-in object here,
 * so the "params / searchParams / arr / str ..." hallucination tables don't apply.
 */
function isBoundToBuiltin(node: TSESTree.Node, name: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let cur: TSESTree.Node | undefined = parentMap.get(node);
  while (cur) {
    if (cur.type === 'BlockStatement' || cur.type === 'Program') {
      for (const stmt of cur.body) {
        if (stmt.type !== 'VariableDeclaration') continue;
        for (const d of stmt.declarations) {
          if (d.id.type === 'Identifier' && d.id.name === name && d.init?.type === 'NewExpression'
            && d.init.callee.type === 'Identifier' && BUILTIN_CONSTRUCTORS.has(d.init.callee.name)) {
            return true;
          }
        }
      }
    }
    cur = parentMap.get(cur);
  }
  return false;
}

function isExpressResponse(node: TSESTree.Node, name: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (name !== 'res') return !isBoundToBuiltin(node, name, parentMap);
  let cur: TSESTree.Node | undefined = parentMap.get(node);
  while (cur) {
    if (cur.type === 'FunctionDeclaration' || cur.type === 'FunctionExpression' || cur.type === 'ArrowFunctionExpression') {
      const params = cur.params;
      for (let i = 1; i < params.length; i++) {
        const p = params[i];
        const prev = params[i - 1];
        if (p.type === 'Identifier' && p.name === 'res' && prev.type === 'Identifier' && /^_?req(uest)?$/.test(prev.name)) {
          return true;
        }
      }
    }
    cur = parentMap.get(cur);
  }
  return false;
}

function checkSingleLevelCall(node: TSESTree.CallExpression, source: string, filePath: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  
  let objectName = '';
  if (isIdentifier(me.object)) {
    objectName = (me.object as TSESTree.Identifier).name;
  } else if (me.object.type === 'CallExpression') {
    const innerCall = me.object as TSESTree.CallExpression;
    if (isIdentifier(innerCall.callee) && innerCall.callee.name === 'expect') {
      objectName = 'expect(...)';
    } else {
      return null;
    }
  } else {
    return null;
  }
  
  const methodName = (me.property as TSESTree.Identifier).name;
  const methodMap = HALLUCINATED_API_MAP.get(objectName);
  if (!methodMap) return null;
  const alternative = methodMap.get(methodName);
  if (!alternative) return null;
  if (!isExpressResponse(node, objectName, parentMap)) return null;
  return {
    ruleId: 'ai-smell/hallucinated-api-calls',
    severity: 'error',
    message: `${objectName}.${methodName}() does not exist — this is a hallucinated API call`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: alternative,
  };
}

function getFullChain(callee: TSESTree.Expression | TSESTree.PrivateIdentifier): { root: string; chain: string[] } | null {
  const parts: string[] = [];
  let current: TSESTree.Expression | TSESTree.PrivateIdentifier = callee;

  while (isMemberExpression(current)) {
    const me = current as TSESTree.MemberExpression;
    if (!isIdentifier(me.property)) return null;
    parts.unshift((me.property as TSESTree.Identifier).name);
    current = me.object;
  }

  if (!isIdentifier(current)) return null;
  return { root: (current as TSESTree.Identifier).name, chain: parts };
}

function checkChainedCall(node: TSESTree.CallExpression, source: string, filePath: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const chainInfo = getFullChain(node.callee);
  if (!chainInfo || chainInfo.chain.length < 2) return null;

  const propMap = HALLUCINATED_CHAIN_MAP.get(chainInfo.root);
  if (!propMap) return null;

  const firstProp = chainInfo.chain[0];
  const alternative = propMap.get(firstProp);
  if (!alternative) return null;
  if (!isExpressResponse(node, chainInfo.root, parentMap)) return null;

  const fullChain = `${chainInfo.root}.${chainInfo.chain.join('.')}()`;
  return {
    ruleId: 'ai-smell/hallucinated-api-calls',
    severity: 'error',
    message: `${fullChain} — hallucinated API chain (${chainInfo.root}.${firstProp} does not exist)`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: alternative,
  };
}

const rule: Rule = {
  id: 'ai-smell/hallucinated-api-calls',
  name: 'Hallucinated API Calls',
  category: 'ai-smell',
  severity: 'error',
  description: 'Detects calls to methods that do not exist on well-known Node.js/Express/Mongoose objects',
  why: 'AI models confidently generate method calls that do not exist. These cause immediate runtime crashes that are difficult to diagnose without knowing they were hallucinated.',
  fix: 'Verify method names against official documentation. These methods were fabricated by an AI and will throw "TypeError: X.Y is not a function" at runtime.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const finding = checkSingleLevelCall(node, source, filePath, parentMap)
          ?? checkChainedCall(node, source, filePath, parentMap);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
