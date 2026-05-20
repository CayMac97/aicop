import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

function isWildcardOrigin(node: TSESTree.Expression): boolean {
  return isStringLiteral(node) && String((node as TSESTree.StringLiteral).value) === '*';
}

function isRequestHeaderOrigin(node: TSESTree.Expression): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (!isMemberExpression(me.object)) return false;
  const parent = me.object as TSESTree.MemberExpression;
  if (!isIdentifier(parent.object)) return false;
  const objName = (parent.object as TSESTree.Identifier).name;
  return (objName === 'req' || objName === 'request') &&
    isIdentifier(parent.property) &&
    (parent.property as TSESTree.Identifier).name === 'headers';
}

function getObjectPropValue(obj: TSESTree.ObjectExpression, propName: string): TSESTree.Expression | null {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property') continue;
    const p = prop as TSESTree.Property;
    if (!isIdentifier(p.key)) continue;
    if ((p.key as TSESTree.Identifier).name !== propName) continue;
    return p.value as TSESTree.Expression;
  }
  return null;
}

function callbackReflectsOrigin(call: TSESTree.CallExpression, cbName: string, originName: string): boolean {
  if (!isIdentifier(call.callee) || (call.callee as TSESTree.Identifier).name !== cbName) return false;
  const args = call.arguments;
  return args.length >= 2 && !!args[1] && isIdentifier(args[1]) && (args[1] as TSESTree.Identifier).name === originName;
}

function isOriginReflectCallback(node: TSESTree.Expression): boolean {
  if (node.type !== 'ArrowFunctionExpression' && node.type !== 'FunctionExpression') return false;
  const fn = node as TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression;
  if (fn.params.length < 2) return false;
  const originParam = fn.params[0];
  const callbackParam = fn.params[1];
  if (!isIdentifier(originParam) || !isIdentifier(callbackParam)) return false;
  const originName = (originParam as TSESTree.Identifier).name;
  const cbName = (callbackParam as TSESTree.Identifier).name;
  const body = fn.body;
  if (body.type === 'BlockStatement') {
    const stmts = (body as TSESTree.BlockStatement).body;
    if (stmts.length !== 1 || stmts[0].type !== 'ExpressionStatement') return false;
    const expr = (stmts[0] as TSESTree.ExpressionStatement).expression;
    if (expr.type !== 'CallExpression') return false;
    return callbackReflectsOrigin(expr as TSESTree.CallExpression, cbName, originName);
  }
  if (body.type === 'CallExpression') {
    return callbackReflectsOrigin(body as TSESTree.CallExpression, cbName, originName);
  }
  return false;
}

function checkCorsObjectMisconfiguration(obj: TSESTree.ObjectExpression, node: TSESTree.Node, source: string, filePath: string): Finding | null {
  const origin = getObjectPropValue(obj, 'origin');
  const credentials = getObjectPropValue(obj, 'credentials');
  if (!origin) return null;

  if (isOriginReflectCallback(origin)) {
    const credIsTrue = credentials?.type === 'Literal' && (credentials as TSESTree.Literal).value === true;
    return {
      ruleId: 'security/cors-misconfiguration',
      severity: 'error',
      message: credIsTrue
        ? 'CORS origin callback unconditionally reflects any origin with credentials: true — credential theft risk'
        : 'CORS origin callback unconditionally reflects any origin — cross-origin access risk',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Validate origin against an allowlist: if (!ALLOWED_ORIGINS.includes(origin)) return callback(new Error("Not allowed"))',
    };
  }

  if (!credentials) return null;
  const credIsTrue = credentials.type === 'Literal' && (credentials as TSESTree.Literal).value === true;
  if (!credIsTrue) return null;
  if (isWildcardOrigin(origin)) {
    return {
      ruleId: 'security/cors-misconfiguration',
      severity: 'error',
      message: 'CORS wildcard + credentials: true — invalid, browsers will reject it',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Use a specific origin allowlist with credentials: cors({ origin: "https://yourapp.com", credentials: true })',
    };
  }
  if (isRequestHeaderOrigin(origin)) {
    return {
      ruleId: 'security/cors-misconfiguration',
      severity: 'error',
      message: 'CORS reflects any origin with credentials: true — credential theft risk',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Validate origin against a whitelist: origin: (origin, cb) => { cb(null, ALLOWED_ORIGINS.includes(origin)) }',
    };
  }
  return null;
}

function hasAllowlistValidation(source: string, varName: string, line: number): boolean {
  const priorLines = source.split('\n').slice(Math.max(0, line - 15), line).join('\n');
  // Match prefix only (no closing paren) so 'includes(origin as string)' also works
  return priorLines.includes(`includes(${varName}`) ||
    priorLines.includes(`indexOf(${varName}`) ||
    priorLines.includes(`.has(${varName}`);
}

function unwrapTypeAssertion(node: TSESTree.Expression): TSESTree.Expression {
  const t = node.type;
  if (t === 'TSAsExpression' || t === 'TSTypeAssertion') {
    return unwrapTypeAssertion((node as unknown as { expression: TSESTree.Expression }).expression);
  }
  return node;
}

function checkResHeaderMisconfiguration(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'header' && method !== 'setHeader') return null;
  const keyArg = node.arguments[0];
  const valArg = node.arguments[1];
  if (!keyArg || !valArg) return null;
  if (!isStringLiteral(keyArg as TSESTree.Expression)) return null;
  const headerName = String((keyArg as TSESTree.StringLiteral).value);
  if (headerName !== 'Access-Control-Allow-Origin') return null;
  if (isStringLiteral(valArg as TSESTree.Expression)) return null;
  const innerVal = unwrapTypeAssertion(valArg as TSESTree.Expression);
  if (isIdentifier(innerVal)) {
    const varName = (innerVal as TSESTree.Identifier).name;
    if (hasAllowlistValidation(source, varName, getLine(node))) return null;
  }
  return {
    ruleId: 'security/cors-misconfiguration',
    severity: 'error',
    message: 'Access-Control-Allow-Origin set to a dynamic value without validation',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate the origin value against an allowlist before reflecting it in Access-Control-Allow-Origin',
  };
}

const rule: Rule = {
  id: 'security/cors-misconfiguration',
  name: 'CORS Misconfiguration',
  category: 'security',
  severity: 'error',
  description: 'Detects dangerous CORS configurations including wildcard + credentials and reflected origins',
  why: 'Misconfigured CORS can allow any website to make authenticated requests to your API, leading to credential theft and unauthorized data access.',
  fix: 'Use an explicit origin allowlist. Never combine wildcard origins with credentials.',
  fixCode: `// Instead of wildcard + credentials (DANGEROUS):
app.use(cors({ origin: '*', credentials: true }));

// Use an explicit allowlist (SAFE):
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? 'https://yourapp.com').split(',');
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const resF = checkResHeaderMisconfiguration(node, source, filePath);
        if (resF) { findings.push(resF); return; }
        const firstArg = node.arguments[0];
        if (!firstArg || firstArg.type !== 'ObjectExpression') return;
        const corsF = checkCorsObjectMisconfiguration(firstArg as TSESTree.ObjectExpression, node, source, filePath);
        if (corsF) findings.push(corsF);
      },
    });

    return findings;
  },
};

export default rule;
