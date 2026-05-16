/**
 * Clean Express utility module — zero findings expected at warn severity.
 * Used by the AICop smoke test suite to verify no false positives.
 */
import { Request, Response } from 'express';

/** Returns application health status. */
export function handleHealth(_req: Request, res: Response): void {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
}

/** Clamps a numeric page number to a valid range. */
export function parsePageNumber(value: string): number {
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 1) {
    return 1;
  }
  return parsed;
}

/** Normalises a display name to lowercase trimmed form. */
export function formatDisplayName(name: string): string {
  if (name.trim().length === 0) {
    return 'anonymous';
  }
  return name.toLowerCase().trim();
}

/** Validates that all required fields are present in a request body. */
export function validateRequired(
  body: Record<string, unknown>,
  fields: string[],
): string | null {
  for (const field of fields) {
    if (body[field] === undefined || body[field] === null) {
      return `Missing required field: ${field}`;
    }
  }
  return null;
}
