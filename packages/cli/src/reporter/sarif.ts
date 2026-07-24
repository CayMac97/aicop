import { ScanResult, Finding } from '../scanner/rules/types.js';

export function formatSarif(result: ScanResult, version: string): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'AICop',
            version: version,
            informationUri: 'https://github.com/CayMac97/aicop',
            rules: [] as any[],
          },
        },
        results: [] as any[],
      },
    ],
  };

  const ruleMap = new Map<string, any>();

  for (const fileResult of result.files) {
    for (const finding of fileResult.findings) {
      if (!ruleMap.has(finding.ruleId)) {
        ruleMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.ruleId,
          shortDescription: { text: finding.message },
          fullDescription: { text: finding.message },
          defaultConfiguration: {
            level: getSarifLevel(finding.severity),
          },
        });
      }

      sarif.runs[0].results.push({
        ruleId: finding.ruleId,
        level: getSarifLevel(finding.severity),
        message: {
          text: finding.message + (finding.fix ? `\nFix: ${finding.fix}` : ''),
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: fileResult.filePath,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: finding.line,
                startColumn: finding.column || 1,
              },
            },
          },
        ],
      });
    }
  }

  sarif.runs[0].tool.driver.rules = Array.from(ruleMap.values());

  return JSON.stringify(sarif, null, 2);
}

function getSarifLevel(severity: string): string {
  switch (severity) {
    case 'error':
      return 'error';
    case 'warn':
      return 'warning';
    case 'info':
      return 'note';
    default:
      return 'none';
  }
}
