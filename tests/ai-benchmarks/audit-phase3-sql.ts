// Vulnerable
function vuln1(req: any, res: any) {
  const query = `SELECT * FROM users WHERE id = ${req.body.id}`;
  db.query(query); // Should be detected
}

function vuln2(req: any, res: any) {
  const userId = req.query.userId;
  db.execute("SELECT * FROM users WHERE id = '" + userId + "'"); // Should be detected
}

function vuln3(req: any, res: any) {
  let q = "SELECT * ";
  q += "FROM users WHERE username = " + req.params.username;
  db.query(q); // Should be detected
}

// Safe
function safe1(req: any, res: any) {
  const query = `SELECT * FROM users WHERE id = ?`;
  db.query(query, [req.body.id]); // Should NOT be detected
}

function safe2(req: any, res: any) {
  const table = "users";
  db.execute(`SELECT * FROM ${table} WHERE id = ?`, [req.query.userId]); // Should NOT be detected
}

function safe3(req: any, res: any) {
  const q = "SELECT * FROM users WHERE id = $1";
  db.query(q, [req.params.id]); // Should NOT be detected
}

// Edge Cases (Modern JS)
function edge1(req: any, res: any) {
  const { id } = req.body;
  db.query(`SELECT * FROM users WHERE id = ${id}`); // Should be detected (destructuring taint)
}

function edge2(req: any, res: any) {
  const id = req.body?.id ?? 'default';
  db.query(`SELECT * FROM users WHERE id = ${id}`); // Should be detected (optional chaining taint)
}
