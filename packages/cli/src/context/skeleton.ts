import * as ts from 'typescript';
import { readFileContent } from '../utils/file-utils.js';

export async function generateSkeleton(filePath: string): Promise<string> {
  const code = await readFileContent(filePath);
  
  const sourceFile = ts.createSourceFile(
    filePath,
    code,
    ts.ScriptTarget.Latest,
    true
  );

  const transformer: ts.TransformerFactory<ts.SourceFile> = (context) => {
    return (rootNode) => {
      function visit(node: ts.Node): ts.Node {
        // Strip function body for standard functions
        if (ts.isFunctionDeclaration(node)) {
          return ts.factory.updateFunctionDeclaration(
            node,
            ts.getModifiers(node),
            node.asteriskToken,
            node.name,
            node.typeParameters,
            node.parameters,
            node.type,
            ts.factory.createBlock([ts.factory.createExpressionStatement(ts.factory.createStringLiteral("...skeleton..."))], false)
          );
        }

        // Strip method body for classes
        if (ts.isMethodDeclaration(node)) {
          return ts.factory.updateMethodDeclaration(
            node as ts.MethodDeclaration,
            ts.getModifiers(node),
            (node as ts.MethodDeclaration).asteriskToken,
            (node as ts.MethodDeclaration).name,
            (node as ts.MethodDeclaration).questionToken,
            (node as ts.MethodDeclaration).typeParameters,
            (node as ts.MethodDeclaration).parameters,
            (node as ts.MethodDeclaration).type,
            ts.factory.createBlock([ts.factory.createExpressionStatement(ts.factory.createStringLiteral("...skeleton..."))], false)
          );
        }

        // Arrow functions could be tricky if they are expression-bodied, but we can try to block them
        if (ts.isArrowFunction(node) && ts.isBlock(node.body)) {
           return ts.factory.updateArrowFunction(
             node,
             ts.getModifiers(node),
             node.typeParameters,
             node.parameters,
             node.type,
             node.equalsGreaterThanToken,
             ts.factory.createBlock([ts.factory.createExpressionStatement(ts.factory.createStringLiteral("...skeleton..."))], false)
           );
        }

        return ts.visitEachChild(node, visit, context);
      }
      return ts.visitNode(rootNode, visit) as ts.SourceFile;
    };
  };

  const result = ts.transform(sourceFile, [transformer]);
  const transformedSourceFile = result.transformed[0];
  const printer = ts.createPrinter({ newLine: ts.NewLineKind.LineFeed });
  
  const skeletonCode = printer.printNode(
    ts.EmitHint.Unspecified,
    transformedSourceFile,
    sourceFile
  );

  return skeletonCode;
}
