import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { HALLUCINATED_API_MAP } from './hallucinated-apis.data.js';

function checkHallucinatedCall(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const objectName = (me.object as TSESTree.Identifier).name;
  const methodName = (me.property as TSESTree.Identifier).name;
  const methodMap = HALLUCINATED_API_MAP.get(objectName);
  if (!methodMap) return null;
  const alternative = methodMap.get(methodName);
  if (!alternative) return null;
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

    walk(ast, {
      CallExpression(rawNode) {
        const finding = checkHallucinatedCall(rawNode as TSESTree.CallExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;
