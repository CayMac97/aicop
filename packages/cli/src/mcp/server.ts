import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { scan } from '../scanner/index.js';
import { loadConfig } from '../config/loader.js';
import { generateSkeleton } from '../context/skeleton.js';
import { applyFixes } from '../fixer/index.js';
import path from 'path';

export async function startMcpServer(): Promise<void> {
  const server = new Server(
    {
      name: 'aicop-mcp',
      version: '1.2.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'aicop_scan',
          description: 'Scan a directory or file for security, AI-smell and tech-debt issues',
          inputSchema: {
            type: 'object',
            properties: {
              targetPath: {
                type: 'string',
                description: 'Path to the file or directory to scan',
              },
            },
            required: ['targetPath'],
          },
        },
        {
          name: 'aicop_skeleton',
          description: 'Generate an AST-skeleton for a JS/TS file to reduce token usage by stripping function bodies',
          inputSchema: {
            type: 'object',
            properties: {
              targetPath: {
                type: 'string',
                description: 'Path to the JS/TS file to skeletonize',
              },
            },
            required: ['targetPath'],
          },
        },
        {
          name: 'aicop_fix',
          description: 'Automatically fix deterministic issues identified by AICop in a given file or directory via AST transformation.',
          inputSchema: {
            type: 'object',
            properties: {
              targetPath: {
                type: 'string',
                description: 'Path to the file or directory to fix',
              },
            },
            required: ['targetPath'],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === 'aicop_scan') {
      const targetPath = String(request.params.arguments?.targetPath || '.');
      const resolvedTarget = path.resolve(process.cwd(), targetPath);
      const config = await loadConfig(process.cwd());

      const result = await scan({
        path: resolvedTarget,
        config,
        severity: 'info',
        format: 'json',
        ci: true,
        fix: false,
        noAiScore: false,
        watch: false,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }

    if (request.params.name === 'aicop_skeleton') {
      const targetPath = String(request.params.arguments?.targetPath);
      const resolvedTarget = path.resolve(process.cwd(), targetPath);
      const skeletonCode = await generateSkeleton(resolvedTarget);

      return {
        content: [
          {
            type: 'text',
            text: skeletonCode,
          },
        ],
      };
    }

    if (request.params.name === 'aicop_fix') {
      const targetPath = String(request.params.arguments?.targetPath || '.');
      const resolvedTarget = path.resolve(process.cwd(), targetPath);
      const config = await loadConfig(process.cwd());

      const result = await scan({
        path: resolvedTarget,
        config,
        severity: 'info',
        format: 'json',
        ci: true,
        fix: false,
        noAiScore: true,
        watch: false,
      });

      await applyFixes(result, { dryRun: false });

      // Calculate how many issues were resolved
      const originalIssues = result.files.reduce((sum, f) => sum + f.findings.length, 0);

      return {
        content: [
          {
            type: 'text',
            text: `Successfully executed deterministic fixes in ${resolvedTarget}.\\nIssues detected in scan before fix: ${originalIssues}.\\nCheck the workspace to verify changes. Backups of original files are stored in .aicop-backup.`,
          },
        ],
      };
    }

    throw new Error(`Tool not found: ${request.params.name}`);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
