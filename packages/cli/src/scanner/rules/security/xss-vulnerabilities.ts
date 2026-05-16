import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isMemberExpression, isIdentifier, isCallExpression } from '../../../utils/ast-helpers.js';

const USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers']);

function isUserInput(node: TSESTree.Node): boolean {
  if (isMemberExpression(node)) {
    const me = node as TSESTree.MemberExpression;
    if (isMemberExpression(me.object)) {
      const parent = me.object as TSESTree.MemberExpression;
      if (isIdentifier(parent.object) && (parent.object as TSESTree.Identifier).name === 'req') {
        if (isIdentifier(parent.property) && USER_INPUT_PROPS.has((parent.property as TSESTree.Identifier).name)) {
          return true;
        }
      }
    }
  }
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInput(e));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInput(be.left) || isUserInput(be.right);
  }
  return false;
}

function isStaticString(node: TSESTree.Expression): boolean {
  if (isStringLiteral(node)) return true;
  if (node.type === 'TemplateLiteral') {
    return (node as TSESTree.TemplateLiteral).expressions.length === 0;
  }
  if (isCallExpression(node)) {
    const call = node as TSESTree.CallExpression;
    if (isMemberExpression(call.callee)) {
      const callee = call.callee as TSESTree.MemberExpression;
      if (isIdentifier(callee.property) && (callee.property as TSESTree.Identifier).name === 'replace') {
        const [search, replacement] = call.arguments as TSESTree.Expression[];
        if (search && replacement && isStringLiteral(search) && isStringLiteral(replacement)) return true;
      }
    }
  }
  return false;
}

function isInnerHTMLAssign(node: TSESTree.AssignmentExpression): boolean {
  if (!isMemberExpression(node.left)) return false;
  const me = node.left as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  const prop = (me.property as TSESTree.Identifier).name;
  return prop === 'innerHTML' || prop === 'outerHTML';
}

function checkInnerHTML(node: TSESTree.AssignmentExpression, source: string, filePath: string): Finding | null {
  if (!isInnerHTMLAssign(node)) return null;
  if (isStaticString(node.right)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'innerHTML assigned with a non-static value — potential XSS',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use textContent for text, or sanitize HTML with DOMPurify before inserting: element.innerHTML = DOMPurify.sanitize(value)',
  };
}

function checkDocumentWrite(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'document') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'write' && method !== 'writeln') return null;
  const arg = node.arguments[0];
  if (!arg || isStaticString(arg as TSESTree.Expression)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'document.write() with dynamic value — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Avoid document.write() entirely. Use DOM manipulation methods instead.',
  };
}

function checkInsertAdjacentHTML(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if ((me.property as TSESTree.Identifier).name !== 'insertAdjacentHTML') return null;
  const htmlArg = node.arguments[1];
  if (!htmlArg || isStaticString(htmlArg as TSESTree.Expression)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'insertAdjacentHTML() with dynamic value — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Sanitize with DOMPurify before calling insertAdjacentHTML, or use createElement/textContent instead.',
  };
}

function checkDangerouslySetInnerHTML(node: TSESTree.JSXAttribute, source: string, filePath: string): Finding | null {
  if (node.name.type !== 'JSXIdentifier') return null;
  if ((node.name as TSESTree.JSXIdentifier).name !== 'dangerouslySetInnerHTML') return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'dangerouslySetInnerHTML used without explicit sanitization check',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Wrap with DOMPurify.sanitize(): dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}',
  };
}

function isHtmlContentTypeHeader(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return false;
  if ((me.object as TSESTree.Identifier).name !== 'res') return false;
  if ((me.property as TSESTree.Identifier).name !== 'setHeader') return false;
  const nameArg = node.arguments[0] as TSESTree.Expression | undefined;
  const valueArg = node.arguments[1] as TSESTree.Expression | undefined;
  if (!nameArg || !valueArg) return false;
  if (!isStringLiteral(nameArg) || !isStringLiteral(valueArg)) return false;
  return (nameArg as TSESTree.StringLiteral).value.toLowerCase() === 'content-type' &&
    (valueArg as TSESTree.StringLiteral).value.toLowerCase().includes('text/html');
}

function isResSendDynamic(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return false;
  if ((me.object as TSESTree.Identifier).name !== 'res') return false;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'send' && method !== 'write') return false;
  const arg = node.arguments[0] as TSESTree.Expression | undefined;
  if (!arg) return false;
  return !isStaticString(arg);
}

function checkResSend(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'res') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'send' && method !== 'write') return null;
  const arg = node.arguments[0];
  if (!arg || !isUserInput(arg)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: `res.${method}() with user input — XSS risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Sanitize user input before sending as HTML, or use res.json() for data responses',
  };
}

function checkResRender(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'res') return null;
  if ((me.property as TSESTree.Identifier).name !== 'render') return null;

  const localsArg = node.arguments[1];
  if (!localsArg || localsArg.type !== 'ObjectExpression') return null;

  const obj = localsArg as TSESTree.ObjectExpression;
  const hasDirectUserInput = obj.properties.some((prop) => {
    if (prop.type !== 'Property') return false;
    const p = prop as TSESTree.Property;
    return isUserInput(p.value as TSESTree.Node);
  });

  if (!hasDirectUserInput) return null;

  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'warn',
    message: 'user input passed directly to template — verify escaping',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Ensure template engine escapes output. Use <%= %> not <%- %> in EJS for user-provided values.',
  };
}

const rule: Rule = {
  id: 'security/xss-vulnerabilities',
  name: 'XSS Vulnerabilities',
  category: 'security',
  severity: 'error',
  description: 'Detects Cross-Site Scripting (XSS) vulnerabilities via unsafe DOM manipulation',
  why: 'XSS allows attackers to inject and execute malicious scripts in users\' browsers, stealing session tokens, credentials, or performing actions as the victim.',
  fix: 'Sanitize all HTML content with DOMPurify before inserting into the DOM, or use safe DOM methods like textContent.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    let hasHtmlContentType = false;
    const dynamicSendNodes: TSESTree.CallExpression[] = [];
    const flaggedLines = new Set<number>();

    walk(ast, {
      AssignmentExpression(rawNode) {
        const finding = checkInnerHTML(rawNode as TSESTree.AssignmentExpression, source, filePath);
        if (finding) findings.push(finding);
      },
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;

        if (isHtmlContentTypeHeader(node)) {
          hasHtmlContentType = true;
          return;
        }

        const docWrite = checkDocumentWrite(node, source, filePath);
        if (docWrite) { findings.push(docWrite); return; }

        const adjHtml = checkInsertAdjacentHTML(node, source, filePath);
        if (adjHtml) { findings.push(adjHtml); return; }

        const resSend = checkResSend(node, source, filePath);
        if (resSend) {
          findings.push(resSend);
          flaggedLines.add(getLine(node));
        } else if (isResSendDynamic(node)) {
          dynamicSendNodes.push(node);
        }

        const resRender = checkResRender(node, source, filePath);
        if (resRender) findings.push(resRender);
      },
      JSXAttribute(rawNode) {
        if (!isCallExpression) return;
        const finding = checkDangerouslySetInnerHTML(rawNode as TSESTree.JSXAttribute, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    if (hasHtmlContentType) {
      for (const node of dynamicSendNodes) {
        if (!flaggedLines.has(getLine(node))) {
          findings.push({
            ruleId: 'security/xss-vulnerabilities',
            severity: 'error',
            message: 'HTML response with dynamic content — XSS risk',
            file: filePath,
            line: getLine(node),
            column: getColumn(node),
            snippet: extractSnippet(source, getLine(node)),
            fix: 'Sanitize dynamic content before sending as HTML, or use res.json() for data responses',
          });
        }
      }
    }

    return findings;
  },
};

export default rule;
