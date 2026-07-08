// aicop-ignore
console.log('This should be ignored by the blanket ignore');

// aicop-ignore security/hardcoded-secrets
const DB_PASSWORD = 'db-password-should-be-suppressed';

export const safeValue = process.env.REAL_SECRET;
