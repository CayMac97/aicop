import { cosmiconfig } from 'cosmiconfig';
import { VibescanConfig } from '../scanner/rules/types.js';
import { DEFAULT_CONFIG } from './defaults.js';
import { validateConfig } from './validator.js';
import { logger } from '../utils/logger.js';
import path from 'path';

const MODULE_NAME = 'vibescan';

export async function loadConfig(searchFrom?: string, configPath?: string): Promise<VibescanConfig> {
  const explorer = cosmiconfig(MODULE_NAME, {
    searchPlaces: [
      'package.json',
      `.${MODULE_NAME}rc.json`,
      `.${MODULE_NAME}rc.js`,
      `.${MODULE_NAME}rc.cjs`,
      `${MODULE_NAME}.config.js`,
      `${MODULE_NAME}.config.cjs`,
    ],
    searchStrategy: 'project',
  } as Parameters<typeof cosmiconfig>[1]);

  try {
    const result = configPath
      ? await explorer.load(configPath)
      : await explorer.search(searchFrom ?? process.cwd());

    if (!result || result.isEmpty) {
      logger.debug('No config file found, using defaults');
      return DEFAULT_CONFIG;
    }

    logger.debug(`Config loaded from ${path.relative(process.cwd(), result.filepath)}`);

    const validation = validateConfig(result.config);
    if (!validation.valid) {
      logger.warn(`Config validation errors in ${result.filepath}:`);
      for (const err of validation.errors) {
        logger.warn(`  - ${err}`);
      }
      logger.warn('Using default config');
      return DEFAULT_CONFIG;
    }

    return validation.config;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`Failed to load config: ${message}`);
    return DEFAULT_CONFIG;
  }
}
