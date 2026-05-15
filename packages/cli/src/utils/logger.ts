import chalk from 'chalk';

/** Available log levels */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

let currentLevel: LogLevel = LogLevel.INFO;
let ciMode = false;

/** Set the minimum log level for output */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

/** Enable or disable CI mode (disables colors) */
export function setCiMode(enabled: boolean): void {
  ciMode = enabled;
}

/** Format a message with level prefix */
function format(prefix: string, colorFn: (s: string) => string, message: string): string {
  return ciMode ? `${prefix} ${message}` : `${colorFn(prefix)} ${message}`;
}

/** Log a debug message to stderr */
export function debug(message: string): void {
  if (currentLevel <= LogLevel.DEBUG) {
    process.stderr.write(format('[DEBUG]', chalk.gray, message) + '\n');
  }
}

/** Log an info message to stderr */
export function info(message: string): void {
  if (currentLevel <= LogLevel.INFO) {
    process.stderr.write(format('[INFO]', chalk.blue, message) + '\n');
  }
}

/** Log a warning message to stderr */
export function warn(message: string): void {
  if (currentLevel <= LogLevel.WARN) {
    process.stderr.write(format('[WARN]', chalk.yellow, message) + '\n');
  }
}

/** Log an error message to stderr */
export function error(message: string): void {
  if (currentLevel <= LogLevel.ERROR) {
    process.stderr.write(format('[ERROR]', chalk.red, message) + '\n');
  }
}

/** Bundled logger object for convenience */
export const logger = { debug, info, warn, error, setLogLevel, setCiMode };
