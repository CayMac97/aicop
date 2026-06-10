import { TSESTree } from '@typescript-eslint/typescript-estree';

export type NodeHandler = (node: TSESTree.Node, parent: TSESTree.Node | null) => void;

export interface WalkVisitor {
  enter?: NodeHandler;
  exit?: NodeHandler;
  [nodeType: string]: NodeHandler | undefined;
}

const SKIP_KEYS = new Set(['parent', 'tokens', 'comments', 'range', 'loc']);

export function walk(root: TSESTree.Node | TSESTree.Program, visitor: WalkVisitor, parent: TSESTree.Node | null = null): void {
  visitor.enter?.(root as TSESTree.Node, parent);
  const typeHandler = visitor[root.type];
  typeHandler?.(root as TSESTree.Node, parent);

  const nodeRecord = root as unknown as Record<string, unknown>;
  for (const key of Object.keys(nodeRecord)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = nodeRecord[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child !== null && typeof child === 'object' && 'type' in child) {
          walk(child as TSESTree.Node, visitor, root as TSESTree.Node);
        }
      }
    } else if (value !== null && typeof value === 'object' && 'type' in value) {
      walk(value as TSESTree.Node, visitor, root as TSESTree.Node);
    }
  }

  visitor.exit?.(root as TSESTree.Node, parent);
}

export function collectNodes<T extends TSESTree.Node>(
  root: TSESTree.Node | TSESTree.Program,
  nodeType: string,
): T[] {
  const nodes: T[] = [];
  walk(root, {
    [nodeType](node) {
      nodes.push(node as T);
    },
  });
  return nodes;
}

export function buildParentMap(root: TSESTree.Node | TSESTree.Program): Map<TSESTree.Node, TSESTree.Node> {
  const parentMap = new Map<TSESTree.Node, TSESTree.Node>();
  walk(root, {
    enter(node, parent) {
      if (parent) {
        parentMap.set(node, parent);
      }
    }
  });
  return parentMap;
}
