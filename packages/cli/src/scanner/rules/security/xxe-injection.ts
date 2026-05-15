import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

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

function isFromReq(node: TSESTree.Node): boolean {
  if (node.type === 'CallExpression') {
    const ce = node as TSESTree.CallExpression;
    if (isMemberExpression(ce.callee)) return isFromReq((ce.callee as TSESTree.MemberExpression).object);
    return false;
  }
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'req') {
    if (isIdentifier(me.property) && USER_INPUT_PROPS.has((me.property as TSESTree.Identifier).name)) {
      return true;
    }
  }
  return isFromReq(me.object);
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

function checkXml2jsUserInput(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || (me.property as TSESTree.Identifier).name !== 'parseString') return null;
  const firstArg = node.arguments[0];
  if (!firstArg || !isFromReq(firstArg)) return null;
  return {
    ruleId: 'security/xxe-injection',
    severity: 'warn',
    message: 'xml2js parsing user input — verify XXE protection is enabled',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Sanitize XML input before parsing and ensure external entities are disabled',
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

    walk(ast, {
      CallExpression(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.CallExpression;
        const f1 = checkLibXmlJsNoent(node, source, filePath);
        if (f1) { findings.push(f1); return; }
        const f2 = checkXml2jsUserInput(node, source, filePath);
        if (f2) { findings.push(f2); return; }
        const f3 = checkUnsafeXmlRequire(node, source, filePath);
        if (f3) findings.push(f3);
      },
    });

    return findings;
  },
};

export default rule;
