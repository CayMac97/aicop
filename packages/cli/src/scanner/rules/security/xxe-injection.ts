import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral, unwrapNode } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, TaintResult } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const XML_PARSE_METHODS = new Set(['parseXmlString', 'parseXml']);
const UNSAFE_XML_PACKAGES = new Set(['libxmljs', 'libxmljs2', 'xml2js', 'fast-xml-parser', 'xmldom']);
const USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies', 'files']);

function hasNoentTrue(opts: TSESTree.ObjectExpression): boolean {
  return opts.properties.some((p) => {
    if (p.type !== 'Property') return false;
    const prop = p as TSESTree.Property;
    if (!isIdentifier(prop.key) || (prop.key as TSESTree.Identifier).name !== 'noent') return false;
    return prop.value.type === 'Literal' && (prop.value as TSESTree.Literal).value === true;
  });
}

function isUserInput(rawNode: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  const node = unwrapNode(rawNode);
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'req') {
    if (isIdentifier(me.property) && USER_INPUT_PROPS.has((me.property as TSESTree.Identifier).name)) {
      return true;
    }
  }
  return false;
}

function checkLibXmlJsNoent(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if (!XML_PARSE_METHODS.has((me.property as TSESTree.Identifier).name)) return null;
  const firstArg = node.arguments[0];
  if (!firstArg || firstArg.type === 'Literal') return null;
  const optsArg = node.arguments[1];
  if (!optsArg || optsArg.type !== 'ObjectExpression') return null;
  if (!hasNoentTrue(optsArg as TSESTree.ObjectExpression)) return null;
  return {
    ruleId: 'security/xxe-injection',
    severity: 'error',
    message: 'libxmljs XXE — noent:true with dynamic input enables XXE attacks',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Set noent:false (or remove the option) to disable external entity processing',
  };
}

function checkXml2jsUserInput(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || (me.property as TSESTree.Identifier).name !== 'parseString') return null;
  const firstArg = node.arguments[0];
  if (!firstArg || !isUserInput(firstArg, taintResult, parentMap)) return null;
  return {
    ruleId: 'security/xxe-injection',
    severity: 'warn',
    message: 'xml2js parsing user input — verify XXE protection is enabled',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use xml2js securely, or prefer fast-xml-parser with safe defaults',
  };
}

function checkXmldomParseFromString(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || me.property.name !== 'parseFromString') return null;
  
  const firstArg = node.arguments[0];
  if (!firstArg || !isUserInput(firstArg, taintResult, parentMap)) return null;
  
  return {
    ruleId: 'security/xxe-injection',
    severity: 'error',
    message: 'xmldom DOMParser XXE — DOMParser is vulnerable to XXE by default if not patched',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use a secure XML parser, or ensure @xmldom/xmldom is updated to latest safe version',
  };
}

function checkUnsafeXmlRequire(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee) || (node.callee as TSESTree.Identifier).name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  const pkg = String((arg as TSESTree.StringLiteral).value);
  if (!UNSAFE_XML_PACKAGES.has(pkg)) return null;
  return {
    ruleId: 'security/xxe-injection',
    severity: 'warn',
    message: `"${pkg}" XML parser can be vulnerable to XXE if external entities are not disabled`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Disable external entity processing and validate all XML input before parsing',
  };
}

const rule: Rule = {
  id: 'security/xxe-injection',
  name: 'XXE Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects XML parsers configured to process external entities with dynamic input',
  why: 'XXE attacks allow reading arbitrary server files, SSRF, and DoS by embedding external entity references in attacker-controlled XML.',
  fix: 'Set noent:false in libxmljs options; use JSON where possible; validate and sanitize all XML input.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode: TSESTree.Node) {
        const node = unwrapNode(rawNode) as TSESTree.CallExpression;
        if (node.type !== 'CallExpression') return;
        const f1 = checkLibXmlJsNoent(node, source, filePath);
        if (f1) { findings.push(f1); return; }
        const f2 = checkXml2jsUserInput(node, source, filePath, taintResult, parentMap);
        if (f2) { findings.push(f2); return; }
        const f3 = checkXmldomParseFromString(node, source, filePath, taintResult, parentMap);
        if (f3) { findings.push(f3); return; }
        const f4 = checkUnsafeXmlRequire(node, source, filePath);
        if (f4) findings.push(f4);
      },
    });

    return findings;
  },
};

export default rule;
