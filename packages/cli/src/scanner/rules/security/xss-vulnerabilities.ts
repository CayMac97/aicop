import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, isTestFile } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isMemberExpression, isIdentifier, isCallExpression } from '../../../utils/ast-helpers.js';
import { buildContextualTaintMap, isNodeContextuallyTainted, isArgContextuallyTainted, TaintResult, getCrossFileTaints } from '../../../utils/taint-tracker.js';
import { buildParentMap } from '../../ast-walker.js';

const USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers']);

const SANITIZER_NAMES = new Set([
  'sanitize', 'sanitizeHtml', 'xss', 'escape', 'encode', 'escapeHtml',
]);
const SANITIZER_OBJECTS = new Set(['DOMPurify', 'he', 'entities', 'validator']);

function getSanitizerCallName(node: TSESTree.CallExpression): string | null {
  if (!isMemberExpression(node.callee)) {
    if (isIdentifier(node.callee)) return (node.callee as TSESTree.Identifier).name;
    return null;
  }
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (isIdentifier(me.object)) {
    const obj = (me.object as TSESTree.Identifier).name;
    if (SANITIZER_OBJECTS.has(obj) && SANITIZER_NAMES.has(method)) return `${obj}.${method}`;
  }
  return SANITIZER_NAMES.has(method) ? method : null;
}

function buildSanitizedVarsMap(ast: ParsedAST): Set<string> {
  const sanitized = new Set<string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init || node.init.type !== 'CallExpression') return;
      if (node.id.type !== 'Identifier') return;
      const callName = getSanitizerCallName(node.init as TSESTree.CallExpression);
      if (callName) sanitized.add((node.id as TSESTree.Identifier).name);
    },
  });
  return sanitized;
}

function isSanitizedNode(node: TSESTree.Node, sanitizedVars: Set<string>): boolean {
  if (node.type === 'Identifier') return sanitizedVars.has((node as TSESTree.Identifier).name);
  if (node.type === 'CallExpression') {
    const name = getSanitizerCallName(node as TSESTree.CallExpression);
    return name !== null;
  }
  return false;
}

function isUserInput(node: TSESTree.Node, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
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
    return (node as TSESTree.TemplateLiteral).expressions.some((e) => isUserInput(e, taintResult, parentMap));
  }
  if (node.type === 'BinaryExpression') {
    const be = node as TSESTree.BinaryExpression;
    if (be.operator !== '+') return false;
    return isUserInput(be.left, taintResult, parentMap) || isUserInput(be.right, taintResult, parentMap);
  }
  if (node.type === 'CallExpression') {
    const ce = node as TSESTree.CallExpression;
    if (isMemberExpression(ce.callee) && isIdentifier(ce.callee.property) && ce.callee.property.name === 'join') {
      if (ce.callee.object.type === 'ArrayExpression') {
        return (ce.callee.object as TSESTree.ArrayExpression).elements.some(el => el && isUserInput(el, taintResult, parentMap));
      }
    }
  }
  return false;
}

function hasAllowlistValidation(node: TSESTree.Node, varName: string, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  let hasGuard = false;
  while (current) {
    if (
      current.type === 'IfStatement' ||
      current.type === 'ConditionalExpression' ||
      current.type === 'SwitchStatement' ||
      current.type === 'LogicalExpression'
    ) {
      let conditionNode: TSESTree.Node | undefined;
      if (current.type === 'IfStatement') conditionNode = current.test;
      else if (current.type === 'ConditionalExpression') conditionNode = current.test;
      else if (current.type === 'LogicalExpression') conditionNode = current.left;
      
      if (conditionNode) {
        walk(conditionNode, {
          CallExpression(rawNode) {
            const cNode = rawNode as TSESTree.CallExpression;
            if (isMemberExpression(cNode.callee)) {
              const prop = cNode.callee.property;
              if (isIdentifier(prop)) {
                if (prop.name === 'test' || prop.name === 'includes' || prop.name === 'has' || prop.name === 'indexOf') hasGuard = true;
              }
            }
          },
          BinaryExpression(rawNode) {
             const bNode = rawNode as TSESTree.BinaryExpression;
             if (bNode.operator === '===' || bNode.operator === '==' || bNode.operator === '!==' || bNode.operator === '!=') {
                if ((isIdentifier(bNode.left) && bNode.left.name === varName) || (isIdentifier(bNode.right) && bNode.right.name === varName)) {
                   hasGuard = true;
                }
             }
          }
        });
      }
      if (hasGuard) break;
    }
    current = parentMap.get(current);
  }
  return hasGuard;
}

function isSafelyValidated(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isIdentifier(node)) {
    return hasAllowlistValidation(node, node.name, parentMap);
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

function checkInnerHTML(node: TSESTree.AssignmentExpression, source: string, filePath: string, sanitizedVars: Set<string>, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isInnerHTMLAssign(node)) return null;
  if (isStaticString(node.right)) return null;
  if (isSanitizedNode(node.right, sanitizedVars)) return null;
  if (!isUserInput(node.right, taintResult, parentMap)) return null;
  if (isSafelyValidated(node.right, parentMap)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'innerHTML assigned with user-controlled value — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use textContent for text, or sanitize HTML with DOMPurify before inserting: element.innerHTML = DOMPurify.sanitize(value)',
  };
}

function checkDocumentWrite(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'document') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'write' && method !== 'writeln') return null;
  const arg = node.arguments[0];
  if (!arg || isStaticString(arg as TSESTree.Expression)) return null;
  if (!isUserInput(arg, taintResult, parentMap)) return null;
  if (isSafelyValidated(arg, parentMap)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'document.write() with user-controlled value — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Avoid document.write() entirely. Use DOM manipulation methods instead.',
  };
}

function checkInsertAdjacentHTML(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if ((me.property as TSESTree.Identifier).name !== 'insertAdjacentHTML') return null;
  const htmlArg = node.arguments[1];
  if (!htmlArg || isStaticString(htmlArg as TSESTree.Expression)) return null;
  if (!isUserInput(htmlArg, taintResult, parentMap)) return null;
  if (isSafelyValidated(htmlArg, parentMap)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'insertAdjacentHTML() with user-controlled value — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Sanitize with DOMPurify before calling insertAdjacentHTML, or use createElement/textContent instead.',
  };
}

function getHtmlPropValue(node: TSESTree.JSXAttribute): TSESTree.Node | null {
  if (!node.value || node.value.type !== 'JSXExpressionContainer') return null;
  const expr = (node.value as TSESTree.JSXExpressionContainer).expression;
  if (expr.type !== 'ObjectExpression') return null;
  for (const prop of (expr as TSESTree.ObjectExpression).properties) {
    if (prop.type !== 'Property') continue;
    const p = prop as TSESTree.Property;
    if (isIdentifier(p.key) && (p.key as TSESTree.Identifier).name === '__html') {
      return p.value as TSESTree.Node;
    }
  }
  return null;
}

function checkDangerouslySetInnerHTML(node: TSESTree.JSXAttribute, source: string, filePath: string, sanitizedVars: Set<string>, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (node.name.type !== 'JSXIdentifier') return null;
  if ((node.name as TSESTree.JSXIdentifier).name !== 'dangerouslySetInnerHTML') return null;
  const htmlVal = getHtmlPropValue(node);
  if (htmlVal && isSanitizedNode(htmlVal, sanitizedVars)) return null;
  if (htmlVal && isStaticString(htmlVal as TSESTree.Expression)) return null;
  if (!htmlVal || !isUserInput(htmlVal, taintResult, parentMap)) return null;
  if (isSafelyValidated(htmlVal, parentMap)) return null;
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'dangerouslySetInnerHTML used with user-controlled input — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Wrap with DOMPurify.sanitize(): dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}',
  };
}

function checkVueVHtml(node: TSESTree.JSXAttribute, source: string, filePath: string, sanitizedVars: Set<string>, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (node.name.type !== 'JSXIdentifier') return null;
  const name = (node.name as TSESTree.JSXIdentifier).name;
  if (name !== 'v-html' && name !== 'domPropsInnerHTML') return null;
  
  if (!node.value) return null;
  let valNode: TSESTree.Node = node.value;
  if (valNode.type === 'JSXExpressionContainer') {
    valNode = (valNode as TSESTree.JSXExpressionContainer).expression;
  }
  
  if (isSanitizedNode(valNode, sanitizedVars)) return null;
  if (isStaticString(valNode as TSESTree.Expression)) return null;
  if (!isUserInput(valNode, taintResult, parentMap)) return null;
  if (isSafelyValidated(valNode, parentMap)) return null;
  
  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: 'Vue v-html or domPropsInnerHTML used with user-controlled input — XSS risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use DOMPurify to sanitize the HTML before rendering: v-html="DOMPurify.sanitize(userInput)"',
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
  const contentTypeMatch = (nameArg as TSESTree.StringLiteral).value.toLowerCase() === 'content-type';
  const val = (valueArg as TSESTree.StringLiteral).value.toLowerCase();
  return contentTypeMatch && (val === 'text/html' || val.startsWith('text/html;'));
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

function checkResSend(node: TSESTree.CallExpression, source: string, filePath: string, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'res') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'send' && method !== 'write') return null;
  const arg = node.arguments[0];
  if (!arg || !isUserInput(arg, taintResult, parentMap)) return null;
  if (isSafelyValidated(arg, parentMap)) return null;
  
  // Exclude cases where the argument is definitively an object (req.query, req.body, req.params)
  // because res.send(obj) sends JSON, which is not an HTML XSS sink.
  if (arg.type === 'ObjectExpression') return null;
  if (isMemberExpression(arg)) {
    const argMe = arg as TSESTree.MemberExpression;
    if (isIdentifier(argMe.object) && argMe.object.name === 'req' && isIdentifier(argMe.property)) {
      const propName = argMe.property.name;
      if (propName === 'query' || propName === 'body' || propName === 'params') {
        return null;
      }
    }
  }

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

function checkJQueryHtmlAndAppend(node: TSESTree.CallExpression, source: string, filePath: string, sanitizedVars: Set<string>, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = me.property.name;
  if (method !== 'html' && method !== 'append' && method !== 'prepend' && method !== 'wrap' && method !== 'replaceWith') return null;
  
  const arg = node.arguments[0];
  if (!arg) return null;
  if (isSanitizedNode(arg, sanitizedVars)) return null;
  if (!isUserInput(arg, taintResult, parentMap)) return null;
  if (isSafelyValidated(arg, parentMap)) return null;

  return {
    ruleId: 'security/xss-vulnerabilities',
    severity: 'error',
    message: `jQuery/Cheerio .${method}() with user-controlled input — XSS risk`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: `Sanitize with DOMPurify.sanitize() before passing to .${method}() or use .text() instead`,
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
    if (isTestFile(filePath)) return findings;
    let hasHtmlContentType = false;
    const dynamicSendNodes: TSESTree.CallExpression[] = [];
    const flaggedLines = new Set<number>();
    const sanitizedVars = buildSanitizedVarsMap(ast);
    const taintResult = buildContextualTaintMap(ast, filePath);
    const parentMap = buildParentMap(ast);

    walk(ast, {
      AssignmentExpression(rawNode) {
        const finding = checkInnerHTML(rawNode as TSESTree.AssignmentExpression, source, filePath, sanitizedVars, taintResult, parentMap);
        if (finding) findings.push(finding);
      },
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;

        if (isHtmlContentTypeHeader(node)) {
          hasHtmlContentType = true;
          return;
        }

        const docWrite = checkDocumentWrite(node, source, filePath, taintResult, parentMap);
        if (docWrite) { findings.push(docWrite); return; }

        const adjHtml = checkInsertAdjacentHTML(node, source, filePath, taintResult, parentMap);
        if (adjHtml) { findings.push(adjHtml); return; }

        const jqueryXss = checkJQueryHtmlAndAppend(node, source, filePath, sanitizedVars, taintResult, parentMap);
        if (jqueryXss) { findings.push(jqueryXss); return; }

        const resSend = checkResSend(node, source, filePath, taintResult, parentMap);
        if (resSend) {
          findings.push(resSend);
          flaggedLines.add(getLine(node));
        } else if (isResSendDynamic(node)) {
          dynamicSendNodes.push(node);
        }

        // res.render() check
        if (isMemberExpression(node.callee) && isIdentifier(node.callee.object) && node.callee.object.name === 'res' && isIdentifier(node.callee.property) && node.callee.property.name === 'render') {
          const locals = node.arguments[1];
          if (locals && isUserInput(locals, taintResult, parentMap) && !isSafelyValidated(locals, parentMap)) {
            findings.push({
              ruleId: 'security/xss-vulnerabilities',
              severity: 'error',
              message: `res.render() called with unfiltered user input in local variables`,
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: 'Template engines like Handlebars/EJS auto-escape by default, but double-check that no triple-mustache or raw tags are used with these variables.',
            });
            flaggedLines.add(getLine(node));
          }
        }
      },
      JSXAttribute(rawNode) {
        const reactFinding = checkDangerouslySetInnerHTML(rawNode as TSESTree.JSXAttribute, source, filePath, sanitizedVars, taintResult, parentMap);
        if (reactFinding) findings.push(reactFinding);
        
        const vueFinding = checkVueVHtml(rawNode as TSESTree.JSXAttribute, source, filePath, sanitizedVars, taintResult, parentMap);
        if (vueFinding) findings.push(vueFinding);
      },
      Property(rawNode) {
        const node = rawNode as TSESTree.Property;
        if (node.key.type === 'Identifier' && node.key.name === 'dangerouslySetInnerHTML') {
          if (isArgContextuallyTainted(node.value, taintResult, parentMap) && !isSafelyValidated(node.value, parentMap)) {
            findings.push({
              ruleId: 'security/xss-vulnerabilities',
              severity: 'error',
              message: `dangerouslySetInnerHTML property assigned with user-controlled value — XSS risk`,
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: 'Sanitize HTML with DOMPurify before inserting it via dangerouslySetInnerHTML.',
            });
            flaggedLines.add(getLine(node));
          }
        }
      }
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

    const crossFileCalls = getCrossFileTaints(ast, filePath, taintResult);
    const reportedExternalLocations = new Set<string>();

    for (const crossCall of crossFileCalls) {
      const extParentMap = buildParentMap(crossCall.externalNode);
      walk(crossCall.externalNode, {
        AssignmentExpression(rawNode) {
          const node = rawNode as TSESTree.AssignmentExpression;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}:innerHTML`;
          if (reportedExternalLocations.has(dedupeKey)) return;
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map(), sanitizedExpressions: new Set<string>() };
          const finding = checkInnerHTML(node, source, crossCall.externalFilePath, sanitizedVars, crossTaintResult, extParentMap);
          if (finding) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/xss-vulnerabilities',
              severity: 'error',
              message: 'Cross-file XSS Risk: User input flows into innerHTML in imported function',
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix: 'Sanitize HTML with DOMPurify before inserting',
            });
          }
        },
        CallExpression(rawNode) {
          const node = rawNode as TSESTree.CallExpression;
          const dedupeKey = `${crossCall.externalFilePath}:${getLine(node)}`;
          if (reportedExternalLocations.has(dedupeKey)) return;

          let isVuln = false;
          let msg = '';
          let fix = '';
          
          const crossTaintResult: TaintResult = { globalTaints: crossCall.taintedParams, localTaints: new Map(), sanitizedExpressions: new Set<string>() };

          const docWrite = checkDocumentWrite(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
          if (docWrite) {
            isVuln = true; msg = 'document.write'; fix = docWrite.fix || '';
          } else {
            const adjHtml = checkInsertAdjacentHTML(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
            if (adjHtml) {
              isVuln = true; msg = 'insertAdjacentHTML'; fix = adjHtml.fix || '';
            } else {
              const resSend = checkResSend(node, source, crossCall.externalFilePath, crossTaintResult, extParentMap);
              if (resSend) {
                isVuln = true; msg = 'res.send'; fix = resSend.fix || '';
              }
            }
          }

          if (isVuln) {
            reportedExternalLocations.add(dedupeKey);
            const sourceNode = crossCall.awaitNode ?? crossCall.callNode;
            findings.push({
              ruleId: 'security/xss-vulnerabilities',
              severity: 'error',
              message: `Cross-file XSS Risk: User input flows into ${msg}() in imported function`,
              file: filePath,
              line: getLine(sourceNode),
              column: getColumn(sourceNode),
              snippet: extractSnippet(source, getLine(sourceNode)),
              fix,
            });
          }
        }
      });
    }

    return findings;
  },
};

export default rule;
