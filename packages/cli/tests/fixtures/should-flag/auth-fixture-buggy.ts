// @ts-nocheck
/**
 * @aicop-fixture
 * INTENTIONALLY BROKEN CODE — AICop Test Fixture
 *
 * Expected findings:
 *   [security/hardcoded-secrets]       line 18, 19
 *   [security/sql-injection]           line 52, 78
 *   [security/jwt-no-expiry]           line 60
 *   [security/missing-rate-limit]      line 45, 70, 90
 *   [security/weak-crypto]             line 100
 *   [ai-smell/mixed-async-patterns]    line 47, 73
 *   [ai-smell/inconsistent-error-handling] line 55, 83
 *   [ai-smell/todo-stub-functions]     line 105, 115
 *   [ai-smell/debug-leftovers]         line 62, 88
 *   [tech-debt/missing-types]          line 45, 70
 */

import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import mysql from "mysql2";

// ❌ [security/hardcoded-secrets] — JWT secret hardcoded in source
const JWT_SECRET = "super_secret_jwt_key_do_not_share";
// ❌ [security/hardcoded-secrets] — DB password hardcoded
const DB_PASSWORD = "admin1234";

const app = express();
app.use(express.json());

// ❌ [tech-debt/hardcoded-config] — port not from env
const PORT = 3000;

// DB connection
// ❌ [security/hardcoded-secrets] — full connection string with credentials
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "userdb",
});

db.connect((err) => {
  if (err) {
    console.error("DB connection failed:", err); // ❌ [ai-smell/debug-leftovers]
  }
});

// ─────────────────────────────────────────────
// LOGIN ROUTE
// ❌ [security/missing-rate-limit] — no rate limiting on auth endpoint
// ❌ [tech-debt/missing-types] — no types on req/res
// ─────────────────────────────────────────────
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // ❌ [security/sql-injection] — user input directly concatenated into query
  const query = "SELECT * FROM users WHERE username = '" + username + "'";

  // ❌ [ai-smell/mixed-async-patterns] — callback style mixed with async/await below
  db.query(query, async (err, results: any) => {
    if (err) {
      // ❌ [ai-smell/inconsistent-error-handling] — error swallowed, no response sent
      console.error(err);
    }

    const users = results as any[];

    if (users.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // ❌ [security/jwt-no-expiry] — no expiresIn option
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET);

    console.log("User logged in:", user.username); // ❌ [ai-smell/debug-leftovers]

    res.json({ token });
  });
});

// ─────────────────────────────────────────────
// REGISTER ROUTE
// ❌ [security/missing-rate-limit] — no rate limiting
// ❌ [tech-debt/missing-types] — no types on req/res
// ─────────────────────────────────────────────
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // ❌ [security/sql-injection] — template literal with user input in SQL
  const checkQuery = `SELECT * FROM users WHERE email = '${email}'`;

  // ❌ [ai-smell/mixed-async-patterns] — .then() inside an async function that already uses await
  db.promise()
    .query(checkQuery)
    .then(async ([rows]: any) => {
      if ((rows as any[]).length > 0) {
        return res.status(409).json({ message: "Email already registered" });
      }

      const hash = await bcrypt.hash(password, 10);

      // ❌ [security/sql-injection] — again, direct string concatenation
      const insertQuery =
        "INSERT INTO users (username, email, password_hash) VALUES ('" +
        username +
        "', '" +
        email +
        "', '" +
        hash +
        "')";

      await db.promise().query(insertQuery);

      res.status(201).json({ message: "User registered successfully" });
    })
    .catch((err) => {
      // ❌ [ai-smell/inconsistent-error-handling] — different error pattern than /login
      console.error("Registration error:", err); // ❌ [ai-smell/debug-leftovers]
      res.status(500).json({ message: "Internal server error" });
    });
});

// ─────────────────────────────────────────────
// PASSWORD RESET ROUTE
// ❌ [security/missing-rate-limit] — critical endpoint, no rate limiting
// ❌ [security/weak-crypto] — Math.random() used for security token
// ─────────────────────────────────────────────
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // ❌ [security/weak-crypto] — Math.random() is not cryptographically secure
  const resetToken = Math.random().toString(36).substring(2);

  // TODO: save token to DB                  // ❌ [ai-smell/todo-stub-functions]
  // TODO: send email with reset link        // ❌ [ai-smell/todo-stub-functions]

  console.log("Reset token for", email, ":", resetToken); // ❌ [ai-smell/debug-leftovers]

  res.json({ message: "Reset email sent" });
});

// ─────────────────────────────────────────────
// PROFILE ROUTE (protected)
// ─────────────────────────────────────────────
app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  // ❌ [ai-smell/inconsistent-error-handling] — jwt.verify result not typed, error not re-thrown
  jwt.verify(token, JWT_SECRET);

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    // ❌ [ai-smell/todo-stub-functions] — returns hardcoded placeholder instead of real data
    res.json({
      userId: (decoded as any).userId,
      username: (decoded as any).username,
      // TODO: fetch full profile from database
      role: "user",
      premium: false,
    });
  });
});

// ─────────────────────────────────────────────
// CHANGE PASSWORD
// ─────────────────────────────────────────────
// ❌ [ai-smell/todo-stub-functions] — function body is entirely a stub
app.post("/change-password", (req, res) => {
  // TODO: implement password change logic
  throw new Error("Not implemented");
});

// ─────────────────────────────────────────────
// DELETE ACCOUNT
// ─────────────────────────────────────────────
// ❌ [ai-smell/todo-stub-functions] — returns hardcoded success without doing anything
app.delete("/account", (req, res) => {
  // TODO: actually delete the account
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // ❌ [ai-smell/debug-leftovers]
});

export default app;
