import { TSESTree } from '@typescript-eslint/typescript-estree';

/** Type guard: node is an Identifier */
export function isIdentifier(node: TSESTree.Node): node is TSESTree.Identifier {
  return node.type === 'Identifier';
}

/** Type guard: node is a string Literal */
export function isStringLiteral(node: TSESTree.Node): node is TSESTree.StringLiteral {
  return node.type === 'Literal' && typeof (node as TSESTree.Literal).value === 'string';
}

/** Type guard: node is a Literal */
export function isLiteral(node: TSESTree.Node): node is TSESTree.Literal {
  return node.type === 'Literal';
}

/** Type guard: node is a CallExpression */
export function isCallExpression(node: TSESTree.Node): node is TSESTree.CallExpression {
  return node.type === 'CallExpression';
}

/** Type guard: node is a MemberExpression */
export function isMemberExpression(node: TSESTree.Node): node is TSESTree.MemberExpression {
  return node.type === 'MemberExpression';
}

/** Type guard: node is a TemplateLiteral */
export function isTemplateLiteral(node: TSESTree.Node): node is TSESTree.TemplateLiteral {
  return node.type === 'TemplateLiteral';
}

/** Type guard: node is a BinaryExpression */
export function isBinaryExpression(node: TSESTree.Node): node is TSESTree.BinaryExpression {
  return node.type === 'BinaryExpression';
}

/** Type guard: node is an ArrowFunctionExpression */
export function isArrowFunction(node: TSESTree.Node): node is TSESTree.ArrowFunctionExpression {
  return node.type === 'ArrowFunctionExpression';
}

/** Type guard: node is a FunctionDeclaration */
export function isFunctionDeclaration(node: TSESTree.Node): node is TSESTree.FunctionDeclaration {
  return node.type === 'FunctionDeclaration';
}

/** Type guard: node is a FunctionExpression */
export function isFunctionExpression(node: TSESTree.Node): node is TSESTree.FunctionExpression {
  return node.type === 'FunctionExpression';
}

/** Get the string name of an identifier, if available */
export function getIdentifierName(node: TSESTree.Node): string | null {
  if (isIdentifier(node)) return node.name;
  return null;
}

/** Get the string value of a member expression like `obj.prop` */
export function getMemberExpressionName(node: TSESTree.MemberExpression): string | null {
  if (!isIdentifier(node.object) || !isIdentifier(node.property)) return null;
  return `${node.object.name}.${node.property.name}`;
}

/** Get the start line of a node (1-based) */
export function getLine(node: TSESTree.Node): number {
  return node.loc.start.line;
}

/** Get the start column of a node (0-based) */
export function getColumn(node: TSESTree.Node): number {
  return node.loc.start.column;
}

/** Check if a callee matches `object.method` pattern */
export function matchesCall(
  node: TSESTree.CallExpression,
  objectName: string,
  methodName: string,
): boolean {
  const { callee } = node;
  if (!isMemberExpression(callee)) return false;
  const obj = getIdentifierName(callee.object);
  const prop = getIdentifierName(callee.property);
  return obj === objectName && prop === methodName;
}

/** Check if a callee is a direct function call (not a method) */
export function matchesDirectCall(node: TSESTree.CallExpression, name: string): boolean {
  return isIdentifier(node.callee) && node.callee.name === name;
}

/** Unwrap TSAsExpression, TSNonNullExpression, TSTypeAssertion, and ChainExpression */
export function unwrapNode(node: TSESTree.Node): TSESTree.Node {
  let current = node;
  while (
    current.type === 'TSAsExpression' ||
    current.type === 'TSNonNullExpression' ||
    current.type === 'TSTypeAssertion' ||
    current.type === 'ChainExpression'
  ) {
    current = (current as any).expression;
  }
  return current;
}
