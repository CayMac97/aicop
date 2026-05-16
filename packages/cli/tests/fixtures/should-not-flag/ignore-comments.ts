// aicop-ignore
const JWT_SECRET = 'super-secret-jwt-signing-key-xyz';

// aicop-ignore security/hardcoded-secrets
const DB_PASSWORD = 'db-password-should-be-suppressed';

export const safeValue = process.env.REAL_SECRET;
