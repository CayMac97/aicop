import { TSESTree } from '@typescript-eslint/typescript-estree';

export type NodeHandler = (node: TSESTree.Node, parent: TSESTree.Node | null) => void;

export interface WalkVisitor {
  enter?: NodeHandler;
  exit?: NodeHandler;
  [nodeType: string]: NodeHandler | undefined;
}

const SKIP_KEYS = new Set(['parent', 'tokens', 'comments', 'range', 'loc']);

let currentSkipRanges: [number, number][] = [];

export function setSkipRanges(ranges: [number, number][]) {
  currentSkipRanges = ranges;
}

export function walk(root: TSESTree.Node | TSESTree.Program, visitor: WalkVisitor, parent: TSESTree.Node | null = null): void {
  if (root.range) {
    for (const r of currentSkipRanges) {
      if (root.range[0] >= r[0] && root.range[1] <= r[1]) {
        return;
      }
    }
  }

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

export type AsyncNodeHandler = (node: TSESTree.Node, parent: TSESTree.Node | null) => Promise<void>;

export interface AsyncWalkVisitor {
  enter?: AsyncNodeHandler;
  exit?: AsyncNodeHandler;
  [nodeType: string]: AsyncNodeHandler | undefined;
}

export async function asyncWalk(root: TSESTree.Node | TSESTree.Program, visitor: AsyncWalkVisitor, parent: TSESTree.Node | null = null): Promise<void> {
  if (root.range) {
    for (const r of currentSkipRanges) {
      if (root.range[0] >= r[0] && root.range[1] <= r[1]) {
        return;
      }
    }
  }

  if (visitor.enter) {
    await visitor.enter(root as TSESTree.Node, parent);
  }
  const typeHandler = visitor[root.type];
  if (typeHandler) {
    await typeHandler(root as TSESTree.Node, parent);
  }

  const nodeRecord = root as unknown as Record<string, unknown>;
  for (const key of Object.keys(nodeRecord)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = nodeRecord[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child !== null && typeof child === 'object' && 'type' in child) {
          await asyncWalk(child as TSESTree.Node, visitor, root as TSESTree.Node);
        }
      }
    } else if (value !== null && typeof value === 'object' && 'type' in value) {
      await asyncWalk(value as TSESTree.Node, visitor, root as TSESTree.Node);
    }
  }

  if (visitor.exit) {
    await visitor.exit(root as TSESTree.Node, parent);
  }
}
